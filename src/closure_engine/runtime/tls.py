"""Operator-configured TLS for API, custody and role service listeners.

Certificate trust is configured independently by clients. These helpers never enroll a
certificate into a client's trust store or silently fall back to cleartext.
"""

import ssl

from ..protocol import ClosureError


def server_context(cert_file=None, key_file=None):
    if cert_file is None and key_file is None:
        return None
    if not cert_file or not key_file:
        raise ClosureError("TLS_CERTIFICATE_AND_KEY_REQUIRED")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.load_cert_chain(str(cert_file), str(key_file))
    except (OSError, ssl.SSLError) as exc:
        raise ClosureError("TLS_CONFIGURATION_INVALID", type(exc).__name__) from exc
    return context


def secure_server(server, cert_file=None, key_file=None):
    try:
        context = server_context(cert_file, key_file)
        if context is not None:
            server.socket = context.wrap_socket(server.socket, server_side=True)
            server.transport_scheme = "https"
        return server
    except BaseException:
        server.server_close()
        raise
