"""Shipped operating CLI commands. Every command prints one JSON object; errors exit 2.

Runtime commands never accept a time argument: the service clock supplies every timestamp.
The trust pin comes from --expected-trust-hash or ACE_EXPECTED_TRUST_HASH, never from the
deployment folder.
"""

import json
import os
import sys
from pathlib import Path

from ..protocol import ClosureError, canonical, strict_loads
from .api import ROLES as API_ROLES
from .api import ApiServer, load_credentials, load_credentials_value
from .custody import LocalCustody
from .custody_service import CustodyServer, RemoteCustody
from .deployment import Deployment, enroll, enroll_target
from .files import create_exclusive, replace_json
from .identities import ROLES, init_identity
from .roles import ROLE_ACTIONS, DistributedRuntime, RoleServer
from .service import Runtime, artifact_bytes
from .target import ReferenceTarget, ReferenceTargetServer

TX_ACTIONS = (
    "propose",
    "approve",
    "freeze",
    "baseline",
    "bind",
    "deploy",
    "run",
    "observe",
    "close",
    "accept",
    "status",
    "recover",
    "recover-complete",
    "bundle",
)
COMMANDS = {
    "api-credential",
    "api-revoke",
    "api-serve",
    "custody-serve",
    "role-serve",
    "init",
    "enroll",
    "target-enroll",
    "target-init",
    "target-serve",
    "tx",
    "reconcile",
    "checkpoint",
    "status",
}


def _pin(parser):
    parser.add_argument("--deployment", required=True, help="Deployment root (role state roots beneath it)")
    parser.add_argument(
        "--expected-trust-hash",
        default=os.environ.get("ACE_EXPECTED_TRUST_HASH"),
        help="Operator-held enrollment pin (or ACE_EXPECTED_TRUST_HASH)",
    )


def register(sub):
    p = sub.add_parser("init", help="Create one persistent role identity (private key never printed)")
    p.add_argument("--deployment", required=True)
    p.add_argument("--role", required=True, choices=ROLES)
    p.add_argument("--issuer", required=True)
    p = sub.add_parser("enroll", help="Operator: enroll every role's public key; prints the trust pin")
    p.add_argument("--deployment", required=True)
    p.add_argument("--check", action="append", required=True, help="Check id the verifier may sign (repeat)")
    p = sub.add_parser("target-enroll", help="Operator: enroll an HTTP target and its probe profile")
    p.add_argument("--deployment", required=True)
    p.add_argument("--target-id", required=True)
    p.add_argument("--base-url", required=True)
    p.add_argument("--checks", required=True, help="JSON file: list of {id, kind, phase, mandatory, probe}")
    p.add_argument("--timeout-ms", type=int, default=5000)
    p = sub.add_parser("target-init", help="Initialise a persistent reference target with its first artifact")
    p.add_argument("--state-dir", required=True)
    p.add_argument("--artifact", required=True)
    p.add_argument("--token-sha256", required=True)
    p = sub.add_parser("target-serve", help="Serve a reference target (ACE HTTP target protocol v1)")
    p.add_argument("--state-dir", required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p = sub.add_parser("tx", help="Run one lifecycle step of a transaction")
    p.add_argument("action", choices=TX_ACTIONS)
    _pin(p)
    p.add_argument("--transaction", required=True)
    p.add_argument("--target", help="propose: enrolled target id")
    p.add_argument("--artifact", help="propose: artifact file to deploy")
    p.add_argument("--intent", help="propose: human-readable intent")
    p.add_argument(
        "--expect",
        action="append",
        default=[],
        help="propose: CHECK=JSON owner-approved desired value for a primary check (repeat)",
    )
    p.add_argument(
        "--allow-partial",
        action="store_true",
        help="propose: opt the primary checks into confirmed non-deployment (PARTIALLY_PROVEN)",
    )
    p.add_argument("--duration-ms", type=int, default=60_000)
    p.add_argument("--min-samples", type=int, default=3)
    p.add_argument("--skew-ms", type=int, default=2_000)
    p.add_argument("--settle-ms", type=int, default=3_000)
    p.add_argument("--deadline-ms", type=int, default=600_000)
    p.add_argument("--recovery-deadline-ms", type=int, default=600_000)
    p.add_argument("--phase", choices=("all", "instant", "window"), default="all")
    p.add_argument("--output", help="bundle: write the runtime bundle to this new file")
    for name, text in (
        ("reconcile", "Broker: resolve pending intents from target state"),
        ("checkpoint", "Custodian: sign and print the current ledger head for export"),
        ("status", "Verified ledger summary"),
    ):
        _pin(sub.add_parser(name, help=text))
    register_api(sub)


def _service_args(parser, default_port=None):
    parser.add_argument("--bind", default="127.0.0.1", help="Listen address (container: 0.0.0.0)")
    parser.add_argument("--port", type=int, required=default_port is None, default=default_port)
    parser.add_argument(
        "--allowed-host",
        action="append",
        help="Exact host:port clients use (repeat). Required when --bind is not loopback.",
    )
    parser.add_argument(
        "--credentials", required=True, help="Credentials directory (live reload, mount read-only) or file"
    )


def register_api(sub):
    p = sub.add_parser(
        "api-credential", help="Issue a bearer token into a new private file; stores only its hash"
    )
    p.add_argument("--credentials", required=True, help="Credentials directory or file (sha256 -> principal)")
    p.add_argument("--principal", required=True)
    p.add_argument("--role", action="append", required=True, choices=sorted(API_ROLES))
    p.add_argument("--token-out", required=True, help="New private file that receives the token")
    p = sub.add_parser(
        "api-revoke", help="Revoke a bearer token by its sha256 (effective on the next request)"
    )
    p.add_argument("--credentials", required=True)
    p.add_argument("--token-sha256", required=True)
    p = sub.add_parser("api-serve", help="Operator JSON API for the UI (single-host or keyless gateway)")
    p.add_argument("--deployment", help="Single-host mode: deployment root holding role keys")
    p.add_argument("--expected-trust-hash", default=os.environ.get("ACE_EXPECTED_TRUST_HASH"))
    p.add_argument("--services", help="Keyless gateway mode: JSON file naming role services and custody")
    p.add_argument("--static-dir", help="Same-origin UI files")
    _service_args(p)
    p = sub.add_parser("custody-serve", help="Protected custody service (holds only the custodian key)")
    _pin(p)
    _service_args(p)
    p = sub.add_parser("role-serve", help="One role service (holds only that role's key)")
    _pin(p)
    p.add_argument("--role", required=True, choices=sorted(ROLE_ACTIONS))
    p.add_argument("--custody-url", required=True)
    p.add_argument("--custody-token-file", required=True)
    _service_args(p)


def _credentials_file(path):
    path = Path(path)
    return path / "credentials.json" if path.is_dir() else path


def _issue_credential(args):
    import hashlib
    import secrets

    path = _credentials_file(args.credentials)
    existing = strict_loads(path.read_bytes()) if path.exists() else {}
    token = secrets.token_urlsafe(32)
    create_exclusive(args.token_out, token.encode(), private=True)
    digest_hex = hashlib.sha256(token.encode()).hexdigest()
    existing[digest_hex] = {"principal": args.principal, "roles": sorted(set(args.role))}
    load_credentials_value(existing)
    replace_json(path, existing)
    return {
        "principal": args.principal,
        "roles": sorted(set(args.role)),
        "token_sha256": digest_hex,
        "token_file": str(Path(args.token_out)),
    }


def _revoke_credential(args):
    path = _credentials_file(args.credentials)
    existing = strict_loads(path.read_bytes())
    if args.token_sha256 not in existing:
        raise ClosureError("CREDENTIAL_UNKNOWN")
    revoked = existing.pop(args.token_sha256)
    if not existing:
        raise ClosureError("LAST_CREDENTIAL_REVOCATION_REFUSED")
    replace_json(path, existing)  # atomic rename; directory mounts see it on the next request
    return {"revoked": args.token_sha256, "principal": revoked["principal"]}


def _read_token(path):
    try:
        token = Path(path).read_bytes().decode().strip()
    except FileNotFoundError as exc:
        raise ClosureError("TOKEN_FILE_MISSING", str(path)) from exc
    if len(token) < 32:
        raise ClosureError("TOKEN_INVALID", str(path))
    return token


def _serve(server, name):
    print(
        json.dumps({"service": name, "bind": server.server_address[0], "port": server.server_address[1]}),
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def _serve_api(args):
    if (args.services is None) == (args.deployment is None):
        raise ClosureError("API_MODE_REQUIRED", "use exactly one of --deployment or --services")
    if args.services is not None:
        config = _read_json_file(args.services)
        if not isinstance(config, dict) or set(config) != set(ROLE_ACTIONS) | {"custody"}:
            raise ClosureError("SERVICES_CONFIG_INVALID")
        services = {
            role: (config[role]["url"], _read_token(config[role]["token_file"])) for role in ROLE_ACTIONS
        }
        runtime = DistributedRuntime(
            services, config["custody"]["url"], _read_token(config["custody"]["token_file"])
        )
    else:
        runtime = _runtime(args)
    static = args.static_dir or packaged_ui()
    server = ApiServer(
        (args.bind, args.port), runtime, load_credentials(args.credentials), static, hosts=args.allowed_host
    )
    _serve(server, "ace-runtime-api")


def _serve_custody(args):
    deployment, trust = _deployment_trust(args)
    custody = LocalCustody(deployment, trust)
    deployment.identity("custodian", trust)  # refuse to start without the enrolled custodian key
    server = CustodyServer(
        (args.bind, args.port),
        custody,
        hosts=args.allowed_host,
        credentials=load_credentials(args.credentials),
    )
    _serve(server, "ace-custody")


def _serve_role(args):
    deployment, _ = _deployment_trust(args)
    custody = RemoteCustody(args.custody_url, _read_token(args.custody_token_file))
    runtime = Runtime(deployment, args.expected_trust_hash, custody=custody)
    server = RoleServer(
        (args.bind, args.port),
        args.role,
        runtime,
        hosts=args.allowed_host,
        credentials=load_credentials(args.credentials),
    )
    _serve(server, "ace-role-" + args.role)


def packaged_ui():
    """The operator UI shipped inside the wheel (closure_engine/web), if this build includes it."""
    from importlib.resources import files

    web = files("closure_engine").joinpath("web")
    return str(web) if web.is_dir() and web.joinpath("index.html").is_file() else None


def _deployment_trust(args):
    if not args.expected_trust_hash:
        raise ClosureError("TRUST_ANCHOR_REQUIRED")
    root = Path(args.deployment)
    if not root.is_dir():
        raise ClosureError("DEPLOYMENT_MISSING", str(root))
    deployment = Deployment(root)
    return deployment, deployment.load_trust(args.expected_trust_hash)


def _read_json_file(path):
    try:
        return strict_loads(Path(path).read_bytes())
    except FileNotFoundError as exc:
        raise ClosureError("INPUT_MISSING", str(path)) from exc


def _expectations(values):
    expect = {}
    for item in values:
        check_id, sep, raw = item.partition("=")
        if not sep or not check_id or check_id in expect:
            raise ClosureError("INVALID_EXPECTATION", item)
        try:
            expect[check_id] = strict_loads(raw.encode())
        except ClosureError as exc:
            raise ClosureError("INVALID_EXPECTATION", item) from exc
    return expect


def _runtime(args):
    if not args.expected_trust_hash:
        raise ClosureError("TRUST_ANCHOR_REQUIRED")
    root = Path(args.deployment)
    if not root.is_dir():
        raise ClosureError("DEPLOYMENT_MISSING", str(root))
    return Runtime(Deployment(root), args.expected_trust_hash)


def _tx(args):
    runtime = _runtime(args)
    tx = args.transaction
    action = args.action
    if action == "propose":
        if not (args.target and args.artifact and args.intent):
            raise ClosureError("PROPOSE_REQUIRES_TARGET_ARTIFACT_INTENT")
        return runtime.propose(
            args.target,
            tx,
            artifact_bytes(args.artifact),
            intent=args.intent,
            expect=_expectations(args.expect),
            allow_partial=args.allow_partial,
            duration_ms=args.duration_ms,
            min_samples=args.min_samples,
            max_clock_skew_ms=args.skew_ms,
            settle_ms=args.settle_ms,
            deadline_ms=args.deadline_ms,
            recovery_deadline_ms=args.recovery_deadline_ms,
        )
    if action == "observe":
        return runtime.observe(tx, phase=args.phase)
    if action == "recover":
        return runtime.begin_recovery(tx)
    if action == "recover-complete":
        return runtime.complete_recovery(tx)
    if action == "bundle":
        if not args.output:
            raise ClosureError("OUTPUT_REQUIRED")
        out = Path(args.output)
        if out.exists():
            raise ClosureError("STATE_ALREADY_EXISTS", str(out))
        out.write_bytes(canonical(runtime.export_bundle(tx)) + b"\n")
        return {"transaction_id": tx, "bundle": str(out)}
    return getattr(runtime, action)(tx)


def dispatch(args):
    if args.command == "api-credential":
        return _issue_credential(args)
    if args.command == "api-serve":
        return _serve_api(args)
    if args.command == "api-revoke":
        return _revoke_credential(args)
    if args.command == "custody-serve":
        return _serve_custody(args)
    if args.command == "role-serve":
        return _serve_role(args)
    if args.command == "init":
        deployment = Deployment(args.deployment)
        return init_identity(deployment.role_root(args.role), args.role, args.issuer)
    if args.command == "enroll":
        return enroll(Deployment(args.deployment), args.check)
    if args.command == "target-enroll":
        checks = _read_json_file(args.checks)
        if not isinstance(checks, list):
            raise ClosureError("INVALID_TARGET_CHECK")
        return enroll_target(
            Deployment(args.deployment), args.target_id, args.base_url, checks, timeout_ms=args.timeout_ms
        )
    if args.command == "target-init":
        return ReferenceTarget.initialize(args.state_dir, artifact_bytes(args.artifact), args.token_sha256)
    if args.command == "target-serve":
        if args.host not in {"127.0.0.1", "::1", "localhost"} and not os.environ.get(
            "ACE_TARGET_ALLOW_NETWORK"
        ):
            raise ClosureError("NON_LOOPBACK_BIND_REQUIRES_ACE_TARGET_ALLOW_NETWORK")
        server = ReferenceTargetServer((args.host, args.port), args.state_dir)
        print(json.dumps({"service": "ace-reference-target", "port": server.server_address[1]}), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return None
    if args.command == "tx":
        return _tx(args)
    runtime = _runtime(args)
    if args.command == "reconcile":
        return runtime.reconcile()
    if args.command == "checkpoint":
        return runtime.checkpoint()
    return runtime.status()


def run(args):
    """Execute a runtime command; returns the process exit code."""
    try:
        result = dispatch(args)
        if result is not None:
            print(json.dumps(result, sort_keys=True))
        return 0
    except ClosureError as exc:
        print(json.dumps({"error": exc.code, "detail": str(exc)}), file=sys.stderr)
        return 2
    except (OSError, KeyError, TypeError) as exc:
        print(json.dumps({"error": "INPUT_OR_STORAGE_ERROR", "type": type(exc).__name__}), file=sys.stderr)
        return 2
