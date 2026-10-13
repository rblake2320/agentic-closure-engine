"""Real TLS sockets, real credential admission, and independent certificate trust."""

import hashlib
import http.client
import secrets
import ssl
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from closure_engine.protocol import ClosureError
from closure_engine.runtime import ROLES, Deployment, Runtime, enroll, init_identity
from closure_engine.runtime.api import ApiServer


def certificates(root):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ACE isolated TLS operator")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    pem, private = root / "tls.pem", root / "tls.key"
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return pem, private


def test_cli_registers_tls_certificate_options():
    result = subprocess.run(
        [sys.executable, "-I", "-m", "closure_engine", "api-serve", "--help"], capture_output=True, text=True
    )
    assert result.returncode == 0
    assert "--tls-cert-file" in result.stdout and "--tls-key-file" in result.stdout


@pytest.mark.parametrize("missing", ["certificate", "key"])
def test_half_configured_tls_never_downgrades_to_http(tmp_path, missing):
    from closure_engine.runtime.tls import server_context

    cert, key = certificates(tmp_path)
    with pytest.raises(ClosureError, match="TLS_CERTIFICATE_AND_KEY_REQUIRED"):
        server_context(None if missing == "certificate" else cert, None if missing == "key" else key)


def test_invalid_certificate_has_typed_startup_refusal(tmp_path):
    from closure_engine.runtime.tls import server_context

    cert, key = certificates(tmp_path)
    cert.write_text("not a certificate")
    with pytest.raises(ClosureError, match="TLS_CONFIGURATION_INVALID"):
        server_context(cert, key)


@pytest.fixture
def tls_api(tmp_path):
    from closure_engine.runtime.tls import secure_server

    cert, key = certificates(tmp_path)
    deployment = Deployment(tmp_path / "deployment")
    for role in ROLES:
        init_identity(deployment.role_root(role), role, "tls-" + role)
    pin = enroll(deployment, ["primary", "protected1", "protected2"])["trust_hash"]
    token = secrets.token_urlsafe(32)
    credentials = {
        hashlib.sha256(token.encode()).hexdigest(): {"principal": "readonly-auditor", "roles": ["viewer"]}
    }
    server = ApiServer(("127.0.0.1", 0), Runtime(deployment, pin), credentials, hosts=None, read_timeout=2)
    secure_server(server, cert, key)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1], cert, token
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def request(port, cert, token, *, hostname="localhost", origin=None):
    context = ssl.create_default_context(cafile=str(cert))
    connection = http.client.HTTPSConnection(hostname, port, context=context, timeout=3)
    headers = {"Authorization": "Bearer " + token}
    if origin:
        headers["Origin"] = origin
    try:
        connection.request("GET", "/api/v1/whoami", headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def test_trusted_tls_and_viewer_identity_control(tls_api):
    port, cert, token = tls_api
    status, body = request(port, cert, token)
    assert status == 200 and b"readonly-auditor" in body


def test_tls_does_not_replace_bearer_admission(tls_api):
    port, cert, _ = tls_api
    assert request(port, cert, "incorrect-credential")[0] == 401


def test_unknown_ca_is_refused(tls_api):
    port, _, token = tls_api
    connection = http.client.HTTPSConnection("localhost", port, timeout=3)
    with pytest.raises(ssl.SSLCertVerificationError):
        connection.request("GET", "/api/v1/whoami", headers={"Authorization": "Bearer " + token})
    connection.close()


def test_wrong_certificate_hostname_is_refused(tls_api):
    port, cert, token = tls_api
    with pytest.raises(ssl.SSLCertVerificationError):
        request(port, cert, token, hostname="127.0.0.1")


def test_cleartext_to_tls_port_is_not_authenticated(tls_api):
    port, _, token = tls_api
    connection = http.client.HTTPConnection("localhost", port, timeout=3)
    with pytest.raises((OSError, http.client.HTTPException)):
        connection.request("GET", "/api/v1/whoami", headers={"Authorization": "Bearer " + token})
        connection.getresponse()
    connection.close()


def test_tls_origin_must_use_https(tls_api):
    port, cert, token = tls_api
    assert request(port, cert, token, origin=f"http://localhost:{port}")[0] == 403
    assert request(port, cert, token, origin=f"https://localhost:{port}")[0] == 200
