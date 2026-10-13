"""Real disk/HTTP release admission, activation and recovery; no mocks."""

import hashlib
import io
import json
import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest

from closure_engine.adapters.static_release import StaticReleaseTarget, validate_archive
from closure_engine.protocol import ClosureError, digest


def archive(version=1, page=b"<h1>Original</h1>", extra=None):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("release.json", json.dumps({"version": version, "entrypoint": "index.html"}))
        z.writestr("index.html", page)
        z.writestr("assets/site.css", b"h1 { color: navy }")
        for name, content in extra or []:
            if isinstance(name, str):
                # zipfile's Windows writer normalizes backslashes; construct the hostile
                # on-wire name explicitly so this is not a vacuous client-normalization test.
                item = zipfile.ZipInfo()
                item.filename = item.orig_filename = name
                z.writestr(item, content)
            else:
                z.writestr(name, content)
    return stream.getvalue()


@pytest.fixture
def target(tmp_path):
    protected = tmp_path / "operator-policy"
    protected.mkdir()
    (protected / "access.json").write_bytes(b'{"deploy":"broker-only"}\n')
    (protected / "retention.json").write_bytes(b'{"history":"immutable"}\n')
    root = tmp_path / "releases"
    StaticReleaseTarget.initialize(root, archive(), hashlib.sha256(b"test-broker").hexdigest(), protected)
    return StaticReleaseTarget(root), protected


@pytest.mark.parametrize(
    "name",
    [
        "../escape.html",
        "/absolute.html",
        "a/../../escape.html",
        "C:/escape.html",
        "a\\evil.html",
        "a//evil.html",
        "a/./evil.html",
        "a/evil.html.",
        "CON.html",
        "assets/NUL.css",
        "%2e%2e/x.html",
        "assets/name:stream.css",
        "ace/v1/state",
        "release.json/child.html",
        "INDEX.html",
    ],
)
def test_archive_rejects_hostile_or_aliasing_names(target, name):
    site, _ = target
    before = site.state()
    with pytest.raises(ClosureError):
        site.replace(before["artifact_hash"], archive(extra=[(name, b"attack")]), "hostile")
    assert site.state() == before
    assert not (site.root.parent / "escape.html").exists()


def test_archive_rejects_symlink_duplicate_and_bomb():
    symlink = zipfile.ZipInfo("link.html")
    symlink.create_system = 3
    symlink.external_attr = 0o120777 << 16
    for extras in [
        [(symlink, b"../elsewhere")],
        [("index.html", b"duplicate")],
        [("huge.css", b"x" * 2_000_000)],
    ]:
        with pytest.raises(ClosureError):
            validate_archive(archive(extra=extras))


def test_invalid_zip_and_manifest_are_typed():
    for raw in [b"not ZIP", archive(extra=[("attack.exe", b"binary")]), archive(version=False)]:
        with pytest.raises(ClosureError):
            validate_archive(raw)


def test_exact_restore_reopen_precondition_and_protected_readback(target):
    site, protected = target
    original, before = site.artifact(), site.state()
    changed = archive(2, b"<h1>Released</h1>")
    assert site.replace(before["artifact_hash"], changed, "release-one") == 200
    assert site.application("/index.html")[0] == b"<h1>Released</h1>"
    assert site.status()["index_sha256"] == digest(b"<h1>Released</h1>")
    reopened = StaticReleaseTarget(site.root)
    assert reopened.artifact() == changed
    assert reopened.replace(before["artifact_hash"], original, "stale-restore") == 412
    assert reopened.artifact() == changed
    assert reopened.replace(digest(changed), original, "restore") == 200
    assert reopened.artifact() == original
    assert reopened.state()["generation"] == 3
    (protected / "access.json").write_bytes(b'{"deploy":"UNSAFE"}')
    assert reopened.protected("access") == b'{"deploy":"UNSAFE"}'


def test_intent_replay_is_idempotent_but_conflicting_reuse_is_refused(target):
    site, _ = target
    original = site.state()["artifact_hash"]
    changed = archive(2)
    assert site.replace(original, changed, "same-intent") == 200
    assert site.replace(original, changed, "same-intent") == 200
    assert site.state()["generation"] == 2
    with pytest.raises(ClosureError, match="INTENT_CONFLICT"):
        site.replace(digest(changed), archive(3), "same-intent")


def test_tampered_active_file_and_archive_fail_closed(target):
    site, _ = target
    folder = site.root / "releases" / site.state()["artifact_hash"][7:]
    (folder / "site" / "index.html").write_bytes(b"tampered")
    with pytest.raises(ClosureError, match="RELEASE_CORRUPT"):
        site.application("/index.html")
    (folder / "artifact.zip").write_bytes(b"tampered")
    with pytest.raises(ClosureError, match="RELEASE_CORRUPT"):
        StaticReleaseTarget(site.root).artifact()


def test_persisted_pending_intent_reconciles_old_or_new_but_not_third_state(target):
    site, _ = target
    before = site.state()
    changed = archive(2)
    site.replace(before["artifact_hash"], changed, "observed-intent")
    intent_path = site.root / "intents" / (hashlib.sha256(b"observed-intent").hexdigest() + ".json")
    record = json.loads(intent_path.read_bytes())
    record["status"] = "PENDING"
    intent_path.write_text(json.dumps(record))
    reopened = StaticReleaseTarget(site.root)
    assert json.loads(intent_path.read_bytes())["status"] == "APPLIED"
    assert reopened.reconcile() == []
    record["after_hash"] = digest(archive(9))
    record["status"] = "PENDING"
    intent_path.write_text(json.dumps(record))
    with pytest.raises(ClosureError, match="ACTIVATION_QUARANTINED"):
        StaticReleaseTarget(site.root)


def test_pack_cli_real_directory_exact_output_and_overwrite_refused(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "index.html").write_bytes(b"<h1>Customer release</h1>")
    (source / "release.json").write_text('{"version":7,"entrypoint":"index.html"}')
    out = tmp_path / "release.zip"
    command = [
        sys.executable,
        "-I",
        "-m",
        "closure_engine.adapters.static_release",
        "pack",
        "--source",
        str(source),
        "--out",
        str(out),
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["artifact_hash"] == digest(out.read_bytes())
    assert validate_archive(out.read_bytes())["manifest"]["version"] == 7
    assert subprocess.run(command, capture_output=True, timeout=15).returncode != 0


def test_separate_process_writers_fence_one_real_activation(target, tmp_path):
    site, _ = target
    before = site.state()["artifact_hash"]
    code = (
        "from closure_engine.adapters.static_release import StaticReleaseTarget; "
        "import sys,json; from pathlib import Path; t=StaticReleaseTarget(sys.argv[1]); "
        "print(json.dumps({'status':t.replace(sys.argv[2],Path(sys.argv[3]).read_bytes(),sys.argv[4])}))"
    )
    children = []
    for number in (2, 3):
        raw_path = tmp_path / f"concurrent-{number}.zip"
        raw_path.write_bytes(archive(number))
        children.append(
            subprocess.Popen(
                [sys.executable, "-I", "-c", code, str(site.root), before, str(raw_path), f"writer-{number}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        )
    observed = []
    for child in children:
        stdout, stderr = child.communicate(timeout=20)
        assert child.returncode == 0, stderr
        observed.append(json.loads(stdout)["status"])
    assert sorted(observed) == [200, 412]
    assert StaticReleaseTarget(site.root).state()["generation"] == 2
    receipt = os.environ.get("ACE_STATIC_ADAPTER_RACE_RECEIPT")
    if receipt:
        Path(receipt).write_text(
            json.dumps({"processes": [p.pid for p in children], "statuses": observed, "generation": 2})
        )


def test_actual_process_kill_during_pending_activation_reopens_consistently(target, tmp_path):
    site, _ = target
    original = site.artifact()
    changed = archive(2, extra=[(f"assets/file-{i}.txt", os.urandom(8192)) for i in range(40)])
    raw_path = tmp_path / "interrupt.zip"
    raw_path.write_bytes(changed)
    code = (
        "from closure_engine.adapters.static_release import StaticReleaseTarget; "
        "import sys; from pathlib import Path; t=StaticReleaseTarget(sys.argv[1]); "
        "t.replace(sys.argv[2],Path(sys.argv[3]).read_bytes(),'kill-during-activation')"
    )
    child = subprocess.Popen(
        [sys.executable, "-I", "-c", code, str(site.root), digest(original), str(raw_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    intent = site.root / "intents" / (hashlib.sha256(b"kill-during-activation").hexdigest() + ".json")
    observed_pending = False
    limit = time.monotonic() + 10
    try:
        while time.monotonic() < limit and child.poll() is None:
            if intent.exists():
                try:
                    record = json.loads(intent.read_bytes())
                except (ValueError, OSError):
                    continue
                if record["status"] == "PENDING":
                    observed_pending = True
                    child.kill()
                    break
            time.sleep(0.0005)
        child.communicate(timeout=10)
        assert observed_pending, "Never observed live WAL intent before killing actual child"
        assert child.returncode != 0
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
    recovered = StaticReleaseTarget(site.root)
    assert recovered.artifact() in (original, changed)
    classification = json.loads(intent.read_bytes())["status"]
    assert classification in {"APPLIED", "NOT_APPLIED"}
    # Safe reissue uses the original intent and precondition; no second visible activation.
    assert recovered.replace(digest(original), changed, "kill-during-activation") == 200
    assert recovered.artifact() == changed
    assert recovered.state()["generation"] == 2
    receipt = os.environ.get("ACE_STATIC_ADAPTER_FAULT_RECEIPT")
    if receipt:
        Path(receipt).write_text(
            json.dumps(
                {
                    "killed_pid": child.pid,
                    "exit_code": child.returncode,
                    "pending_intent_observed": observed_pending,
                    "classification_after_reopen": classification,
                    "safe_reissue_generation": 2,
                    "original_hash": digest(original),
                    "current_hash": digest(changed),
                }
            )
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows junction test has Linux symlink twin")
def test_windows_junction_release_custody_refused(target, tmp_path):
    site, _ = target
    release = site.root / "releases" / site.state()["artifact_hash"][7:] / "site"
    outside = tmp_path / "outside"
    outside.mkdir()
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(release / "linked"), str(outside)], capture_output=True, timeout=10
    )
    assert result.returncode == 0
    with pytest.raises(ClosureError, match="UNSAFE_STORAGE_PATH"):
        site.application("/linked/index.html")


@pytest.mark.skipif(os.name == "nt", reason="Linux symlink test has Windows junction twin")
def test_linux_symlink_release_custody_refused(target, tmp_path):
    site, _ = target
    release = site.root / "releases" / site.state()["artifact_hash"][7:] / "site"
    (release / "linked").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ClosureError, match="UNSAFE_STORAGE_PATH"):
        site.application("/linked/index.html")
