"""container_backup: real deployments in the container volume layout, real ledgers advanced by
real transactions against a real reference target, real encrypted archives."""

import io
import json
import os
import secrets
import tarfile
import threading

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from test_runtime_e2e import CHECKS, artifact, expect_of, free_port

from closure_engine.protocol import ClosureError, canonical
from closure_engine.runtime import (
    Deployment,
    ReferenceTarget,
    ReferenceTargetServer,
    Runtime,
    enroll,
    enroll_target,
    init_identity,
)
from closure_engine.runtime import container_backup as cb
from closure_engine.runtime.identities import ROLES

ROOT_UID = hasattr(os, "geteuid") and os.geteuid() == 0


def layout(root):
    return Deployment(
        root,
        {
            **{r: root / "keys" / r for r in ROLES},
            "custodian": root / "custody-data",
            "operator": root / "operator",
        },
    )


@pytest.fixture
def installation(tmp_path):
    root = tmp_path / "volumes"
    deployment = layout(root)
    for role in ROLES:
        init_identity(deployment.role_root(role), role, role + "-bk")
    pin = enroll(deployment, [c["id"] for c in CHECKS])["trust_hash"]
    port = free_port()
    target = enroll_target(deployment, "shop/api", f"http://127.0.0.1:{port}", CHECKS)
    for relative in cb.VOLUME_PATHS:
        (root / relative).mkdir(parents=True, exist_ok=True)
    ReferenceTarget.initialize(tmp_path / "target", artifact(1), target["deploy_token_sha256"])
    server = ReferenceTargetServer(("127.0.0.1", port), tmp_path / "target")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    runtime = Runtime(deployment, pin)
    runtime.status()  # genesis ledger + checkpoint
    yield {"root": root, "pin": pin, "runtime": runtime, "tmp": tmp_path, "deployment": deployment}
    server.shutdown()
    server.server_close()


def advance(runtime, tx, answer):
    runtime.propose("shop/api", tx, artifact(answer), intent="backup", expect=expect_of(artifact(answer)))
    runtime.approve(tx)
    return runtime.checkpoint()


def take(inst, name):
    out, key = inst["tmp"] / name, inst["tmp"] / (name + "-keys") / "snapshot.key"
    key.parent.mkdir()
    receipt = cb.backup(inst["root"], out, inst["pin"], key)
    return out / "snapshot.ace", key, receipt


def restore(inst, target, archive, key, anchor, **kwargs):
    return cb.restore(inst["tmp"] / target, archive, key, inst["pin"], anchor, **kwargs)


# ----- BK-07: Worked only after the archived bytes verify -------------------------------------
def test_backup_verifies_archived_bytes_before_reporting_worked(installation):
    archive, key, receipt = take(installation, "b1")
    assert receipt["result"] == "Worked" and receipt["archive_verified"] is True
    assert cb.verify_archive(archive, key, installation["pin"])["verification"] == receipt["verification"]


def test_key_file_beside_archive_is_refused(installation):
    out = installation["tmp"] / "same"
    with pytest.raises(ClosureError, match="BACKUP_KEY_BESIDE_ARCHIVE"):
        cb.backup(installation["root"], out, installation["pin"], out / "snapshot.key")


# ----- BK-01: independent checkpoint, refused before install -----------------------------------
def test_older_snapshot_is_refused_before_anything_is_installed(installation):
    old_archive, old_key, _ = take(installation, "old")
    newest = advance(installation["runtime"], "tx-1", 2)
    with pytest.raises(ClosureError, match="SNAPSHOT_OLDER_THAN_EXPECTED_CHECKPOINT"):
        restore(installation, "r-old", old_archive, old_key, newest, set_ownership=False)
    assert cb._occupied(installation["tmp"] / "r-old") == []
    assert cb.restore_state(installation["tmp"] / "r-old") is None


def test_current_snapshot_with_its_checkpoint_restores_completely(installation):
    newest = advance(installation["runtime"], "tx-2", 3)
    archive, key, receipt = take(installation, "cur")
    result = restore(installation, "r-cur", archive, key, newest, set_ownership=False)
    assert result["result"] == "Worked" and result["restored_files"] == receipt["files"]
    assert cb.restore_state(installation["tmp"] / "r-cur")["status"] == "COMPLETE"
    assert cb.verify_snapshot(installation["tmp"] / "r-cur", installation["pin"]) == receipt["verification"]


def test_forked_history_is_refused(installation, tmp_path):
    base_archive, base_key, _ = take(installation, "base")
    newest = advance(installation["runtime"], "tx-main", 4)
    main_archive, main_key, _ = take(installation, "main")
    # A different history from the same keys: restore the base, advance it differently.
    genesis = cb.verify_snapshot(installation["root"], installation["pin"])  # sanity: source verifies
    assert genesis["ledger"]["sequence"] >= 2
    base_anchor = json.loads((installation["root"] / "custody-data" / "checkpoint.json").read_bytes())
    assert base_anchor == newest
    fork_root = tmp_path / "fork"
    cb.restore(
        fork_root,
        base_archive,
        base_key,
        installation["pin"],
        _genesis_of(base_archive, base_key, tmp_path),
        set_ownership=False,
    )
    fork = Runtime(layout(fork_root), installation["pin"])
    forked = advance(fork, "tx-fork", 5)
    with pytest.raises(ClosureError, match="SNAPSHOT_OLDER_THAN_EXPECTED_CHECKPOINT"):
        restore(installation, "r-main", main_archive, main_key, forked, set_ownership=False)


def _genesis_of(archive, key, tmp_path):
    stage = tmp_path / ("stage-" + secrets.token_hex(4))
    stage.mkdir()
    cb._decrypt_and_stage(archive, cb._read_key(key), stage)
    return json.loads((stage / "custody-data" / "checkpoint.json").read_bytes())


def test_expected_checkpoint_is_required(installation):
    archive, key, _ = take(installation, "need")
    with pytest.raises(ClosureError, match="EXPECTED_CHECKPOINT_REQUIRED"):
        restore(installation, "r-need", archive, key, None, set_ownership=False)


# ----- BK-03: durable restore state and byte-checked resume ------------------------------------
@pytest.mark.skipif(ROOT_UID, reason="needs a host where container ownership fails (non-root)")
def test_interrupted_restore_resumes_with_same_archive(installation):
    newest = advance(installation["runtime"], "tx-3", 6)
    archive, key, receipt = take(installation, "res")
    target = installation["tmp"] / "r-res"
    # Real mid-sequence failure: container ownership cannot be applied on this host.
    with pytest.raises(ClosureError, match="CONTAINER_BOOTSTRAP_REQUIRES_ROOT"):
        restore(installation, "r-res", archive, key, newest, set_ownership=True)
    state = cb.restore_state(target)
    assert state["status"] == "INSTALLING" and state["files"] == receipt["files"]
    installed = cb._occupied(target)
    assert len(installed) == receipt["files"]
    (target / installed[0]).unlink()  # also lose one file
    result = restore(installation, "r-res", archive, key, newest, set_ownership=False)
    assert result["result"] == "Worked" and cb.restore_state(target)["status"] == "COMPLETE"
    assert cb.verify_snapshot(target, installation["pin"]) == receipt["verification"]
    again = restore(installation, "r-res", archive, key, newest, set_ownership=False)
    assert again["result"] == "AlreadyRestored"


@pytest.mark.skipif(ROOT_UID, reason="needs a host where container ownership fails (non-root)")
def test_resume_refuses_altered_files_and_other_archives(installation):
    newest = advance(installation["runtime"], "tx-4", 7)
    archive, key, _ = take(installation, "alt")
    other_archive, other_key, _ = take(installation, "alt2")
    target = installation["tmp"] / "r-alt"
    with pytest.raises(ClosureError, match="CONTAINER_BOOTSTRAP_REQUIRES_ROOT"):
        restore(installation, "r-alt", archive, key, newest, set_ownership=True)
    with pytest.raises(ClosureError, match="RESTORE_STATE_OTHER_ARCHIVE"):
        restore(installation, "r-alt", other_archive, other_key, newest, set_ownership=False)
    victim = target / [p for p in cb._occupied(target) if p.endswith("identity.json")][0]
    victim.write_bytes(victim.read_bytes() + b" ")
    with pytest.raises(ClosureError, match="RESTORE_RESUME_CONFLICT"):
        restore(installation, "r-alt", archive, key, newest, set_ownership=False)
    assert cb.restore_state(target)["status"] == "INSTALLING"


def test_nonempty_destination_without_restore_state_is_refused(installation):
    archive, key, _ = take(installation, "ne")
    target = installation["tmp"] / "r-ne" / "custody-data"
    target.mkdir(parents=True)
    (target / "ledger.sqlite").write_bytes(b"existing")
    with pytest.raises(ClosureError, match="RESTORE_TARGET_NOT_EMPTY"):
        restore(
            installation,
            "r-ne",
            archive,
            key,
            _genesis_of(archive, key, installation["tmp"]),
            set_ownership=False,
        )


# ----- BK-06 / BK-08: typed failures and strict JSON ------------------------------------------
@pytest.mark.parametrize("damage", ["flip", "truncate", "wrong-key"])
def test_authentication_failures_are_typed(installation, damage):
    archive, key, _ = take(installation, "auth-" + damage)
    if damage == "flip":
        raw = bytearray(archive.read_bytes())
        raw[len(raw) // 2] ^= 1
        archive.write_bytes(bytes(raw))
    elif damage == "truncate":
        archive.write_bytes(archive.read_bytes()[:-40])
    else:
        key.write_bytes(b"\x02" * 32)
    with pytest.raises(ClosureError, match="BACKUP_AUTHENTICATION_FAILED"):
        cb.verify_archive(archive, key, installation["pin"])


def sealed(tmp_path, payload, name):
    """An authentic archive (correct key) whose plaintext is ``payload``."""
    key, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    header = cb.MAGIC + nonce
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    enc.authenticate_additional_data(header)
    body = enc.update(payload) + enc.finalize()
    (tmp_path / name).write_bytes(header + body + enc.tag)
    (tmp_path / (name + ".key")).write_bytes(key)
    return tmp_path / name, tmp_path / (name + ".key")


def test_authentic_but_malformed_archive_is_typed_format_error(installation):
    archive, key = sealed(installation["tmp"], b"not a gzip tar stream" * 4, "garbage.ace")
    with pytest.raises(ClosureError, match="BACKUP_FORMAT_INVALID"):
        cb.verify_archive(archive, key, installation["pin"])


def test_manifest_with_duplicate_keys_is_refused(installation):
    buffer = io.BytesIO()
    manifest = b'{"version":"ace.backup.v1","files":[],"files":[],"verification":{}}'
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        entry = tarfile.TarInfo("manifest.json")
        entry.size = len(manifest)
        tar.addfile(entry, io.BytesIO(manifest))
    archive, key = sealed(installation["tmp"], buffer.getvalue(), "dup.ace")
    with pytest.raises(ClosureError, match="DUPLICATE_KEY"):
        cb.verify_archive(archive, key, installation["pin"])


def test_restore_state_record_is_not_backed_up(installation):
    newest = installation["runtime"].checkpoint()
    archive, key, _ = take(installation, "st")
    restore(installation, "r-st", archive, key, newest, set_ownership=False)
    restored = installation["tmp"] / "r-st"
    out, second_key = installation["tmp"] / "st2", installation["tmp"] / "st2-keys" / "k"
    second_key.parent.mkdir()
    receipt = cb.backup(restored, out, installation["pin"], second_key)
    assert receipt["result"] == "Worked"
    staged = installation["tmp"] / "st2-stage"
    staged.mkdir()
    manifest = cb._decrypt_and_stage(out / "snapshot.ace", cb._read_key(second_key), staged)
    assert all(not item["path"].endswith(cb.STATE_FILE) for item in manifest["files"])
    assert canonical(manifest["verification"])
