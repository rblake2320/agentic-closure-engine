"""Provision an isolated ACE deployment inside operator-mounted Docker volumes.

This command runs only during installation. Every live service sees its own role volume,
public enrollment, and its own authenticated channels. Private keys never leave the volumes.
An operator supplies an actual target profile; no target or outcome is fabricated here.
"""

import hashlib
import os
import secrets
import shutil
from pathlib import Path

from ..protocol import ClosureError, digest
from .deployment import Deployment, enroll, enroll_target
from .files import create_exclusive, create_json, read_json
from .identities import ROLES, init_identity
from .rpc import validate_credentials

ROLE_UIDS = {
    "actor": 11001,
    "owner": 11002,
    "authority": 11003,
    "verifier": 11004,
    "broker": 11005,
    "custodian": 11006,
}
SERVICE_ROLES = ("actor", "owner", "authority", "verifier", "broker")


def _credentials(folder, entries):
    folder.mkdir(parents=True, exist_ok=True)
    create_json(
        folder / "credentials.json",
        {
            hashlib.sha256(token.encode()).hexdigest(): {"principal": principal, "roles": roles}
            for token, principal, roles in entries
        },
        private=True,
    )


def _ownership(folder, uid):
    if os.name == "nt" or os.geteuid() != 0:
        raise ClosureError("CONTAINER_BOOTSTRAP_REQUIRES_ROOT")
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    os.chown(folder, uid, uid)
    folder.chmod(0o700)
    for path in folder.rglob("*"):
        if path.is_symlink():
            raise ClosureError("BOOTSTRAP_SYMLINK_DENIED")
        os.chown(path, uid, uid)
        path.chmod(0o700 if path.is_dir() else 0o600)


def _installed(root, operator, profile):
    restore_state = root / "operator" / "RESTORE_STATE.json"
    if restore_state.exists() and read_json(restore_state, "RESTORE_INCOMPLETE").get("status") != "COMPLETE":
        raise ClosureError("RESTORE_INCOMPLETE")
    seal = read_json(root / "operator" / "installation.json", "INSTALLATION_INCOMPLETE")
    if seal.get("profile_hash") != digest(profile):
        raise ClosureError("INSTALLATION_PROFILE_MISMATCH")
    trust = operator.load_trust(seal["trust_hash"])
    for role in ROLES:
        operator.identity(role, trust)
    target = operator.target(profile["target_id"])
    if digest(target) != seal["target_profile_hash"]:
        raise ClosureError("INSTALLATION_PROFILE_MISMATCH")
    for relative, expected in seal["configuration_hashes"].items():
        # Operator-owned bearer enrollment is mutable for live issue/revoke operations.
        # Its schema is checked, while role keys, trust, target and channel tokens stay pinned.
        credential_paths = {
            "gateway-auth/credentials.json",
            "custody-auth/credentials.json",
            *("auth/" + role + "/credentials.json" for role in SERVICE_ROLES),
        }
        if relative in credential_paths:
            validate_credentials(read_json(root / relative, "INSTALLATION_INCOMPLETE"))
            continue
        try:
            actual = digest((root / relative).read_bytes())
        except FileNotFoundError as exc:
            raise ClosureError("INSTALLATION_INCOMPLETE", relative) from exc
        if actual != expected:
            raise ClosureError("INSTALLATION_CONFIG_MISMATCH", relative)
    # Docker must find the nested writable mountpoint before mounting the broker key volume read-only.
    _ownership(operator.role_root("broker") / "intents", ROLE_UIDS["broker"])
    return {**seal["summary"], "installation": "existing"}


def provision(volume_root, target_profile):
    root = Path(volume_root).resolve()
    profile = read_json(target_profile, "TARGET_PROFILE_MISSING")
    if not isinstance(profile, dict) or set(profile) != {"target_id", "base_url", "checks"}:
        raise ClosureError("INVALID_TARGET_PROFILE")
    public = root / "operator"
    role_roots = {role: root / "keys" / role for role in ROLES}
    role_roots["custodian"] = root / "custody-data"
    operator = Deployment(root, {**role_roots, "operator": public})
    if (public / "trust.json").exists():
        return _installed(root, operator, profile)
    (operator.role_root("broker") / "intents").mkdir(parents=True, exist_ok=True)
    for role in ROLES:
        init_identity(role_roots[role], role, role + "-selfhosted")
    pin = enroll(operator, [check["id"] for check in profile["checks"]])["trust_hash"]
    target = enroll_target(operator, profile["target_id"], profile["base_url"], profile["checks"])
    gateway_token = secrets.token_urlsafe(32)
    custody_tokens = {role: secrets.token_urlsafe(32) for role in SERVICE_ROLES}
    _credentials(
        root / "custody-auth",
        [(t, r + "-service", [r]) for r, t in custody_tokens.items()]
        + [(gateway_token, "gateway", ["operator", "viewer"])],
    )
    for role in SERVICE_ROLES:
        _credentials(root / "auth" / role, [(gateway_token, "gateway", ["operator"])])
        create_exclusive(role_roots[role] / "custody.token", custody_tokens[role].encode(), private=True)
    gateway = root / "gateway"
    gateway.mkdir(parents=True, exist_ok=True)
    create_exclusive(gateway / "channel.token", gateway_token.encode(), private=True)
    operator_token = secrets.token_urlsafe(32)
    viewer_token = secrets.token_urlsafe(32)
    _credentials(
        root / "gateway-auth",
        [
            (operator_token, "installation-operator", [*SERVICE_ROLES, "operator", "custodian"]),
            (viewer_token, "auditor", ["viewer"]),
        ],
    )
    exports = root / "exports"
    create_exclusive(exports / "operator.token", operator_token.encode(), private=True)
    create_exclusive(exports / "viewer.token", viewer_token.encode(), private=True)
    create_exclusive(exports / "trust.pin", pin.encode())
    shutil.copyfile(public / "trust.json", exports / "trust.json")
    create_json(
        gateway / "services.json",
        {
            **{
                role: {"url": "http://" + role + ":9001", "token_file": "/gateway/channel.token"}
                for role in SERVICE_ROLES
            },
            "custody": {"url": "http://custody:9000", "token_file": "/gateway/channel.token"},
        },
    )
    # Public configuration has no keys or bearer tokens and is read-only in live services.
    for path in public.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    public.chmod(0o755)
    for role, uid in ROLE_UIDS.items():
        _ownership(role_roots[role], uid)
        if role in SERVICE_ROLES:
            _ownership(root / "auth" / role, uid)
    _ownership(root / "custody-auth", ROLE_UIDS["custodian"])
    _ownership(root / "custody-data", ROLE_UIDS["custodian"])
    _ownership(root / "broker-intents", ROLE_UIDS["broker"])
    _ownership(gateway, 11007)
    _ownership(root / "gateway-auth", 11007)
    summary = {
        "trust_hash": pin,
        "target_id": target["target_id"],
        "target_deploy_token_sha256": target["deploy_token_sha256"],
        "operator_token_file": str(exports / "operator.token"),
        "roles": list(ROLE_UIDS),
        "keys_exported": False,
    }
    config_files = [
        public / "trust.json",
        public / "trust.pin",
        operator.target_path(profile["target_id"]),
        operator.target_token_path(profile["target_id"]),
        gateway / "services.json",
        gateway / "channel.token",
        root / "gateway-auth" / "credentials.json",
        root / "custody-auth" / "credentials.json",
        *(root / "auth" / role / "credentials.json" for role in SERVICE_ROLES),
        *(role_roots[role] / "custody.token" for role in SERVICE_ROLES),
        *(exports / name for name in ("operator.token", "viewer.token", "trust.json", "trust.pin")),
    ]
    create_json(
        public / "installation.json",
        {
            "version": "ace.installation.v1",
            "trust_hash": pin,
            "profile_hash": digest(profile),
            "target_profile_hash": digest(operator.target(profile["target_id"])),
            "configuration_hashes": {
                str(path.relative_to(root)): digest(path.read_bytes()) for path in config_files
            },
            "summary": summary,
        },
    )
    return {**summary, "installation": "new"}
