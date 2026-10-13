"""Real standalone companion-script subprocess tests, with actual files/git/Ed25519."""

import ast
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

TOOL = Path(
    os.environ.get("RELEASE_MANIFEST_SCRIPT", Path(__file__).parents[1] / "tools/release_manifest.py")
)
DOMAIN = b"ACE-RELEASE-PUBLISHER-V1\x00"


def canonical(x):
    return json.dumps(x, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()


def save(path, value):
    path.write_bytes(canonical(value))


def command(args, expected=0):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    assert result.returncode == expected, (result.returncode, result.stdout, result.stderr)
    return json.loads(result.stdout if expected == 0 else result.stderr)


@pytest.fixture
def release(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "recipe.txt").write_text("python -m build --wheel --no-isolation\n")
    (source / "requirements.lock").write_text("example-dependency==1.2.3\n")
    git = ["git", "-C", str(source)]
    subprocess.run(git + ["init", "-q"], check=True)
    subprocess.run(git + ["config", "core.autocrlf", "false"], check=True)
    subprocess.run(git + ["add", "."], check=True)
    subprocess.run(
        git
        + [
            "-c",
            "user.name=Release Test",
            "-c",
            "user.email=release@example.invalid",
            "commit",
            "-qm",
            "Actual test build inputs",
        ],
        check=True,
    )
    commit = subprocess.check_output(git + ["rev-parse", "HEAD"], text=True).strip()
    tree = subprocess.check_output(git + ["rev-parse", "HEAD^{tree}"], text=True).strip()
    bundle = tmp_path / "assets"
    bundle.mkdir()
    shutil.copy2(source / "recipe.txt", bundle / "recipe.txt")
    shutil.copy2(source / "requirements.lock", bundle / "requirements.lock")
    shutil.copy2(TOOL, bundle / "release_manifest.py")
    installed = tmp_path / "installed-verifier.py"
    shutil.copy2(TOOL, installed)
    with zipfile.ZipFile(bundle / "example-1.0.0-py3-none-any.whl", "w") as wheel:
        wheel.writestr("example/__init__.py", "VALUE = 42\n")
        wheel.writestr(
            "example-1.0.0.dist-info/METADATA",
            "Metadata-Version: 2.4\nName: example\nVersion: 1.0.0\n"
            "Requires-Dist: example-dependency==1.2.3\n",
        )
    artifact = bundle / "example-1.0.0-py3-none-any.whl"
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "library",
                "name": "example",
                "version": "1.0.0",
                "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(artifact.read_bytes()).hexdigest()}],
            }
        },
        "components": [{"type": "library", "name": "example-dependency", "version": "1.2.3"}],
    }
    save(bundle / "sbom.json", sbom)
    key = Ed25519PrivateKey.generate()
    private = tmp_path / "publisher.private.pem"
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    private.chmod(0o600)
    public = base64.b64encode(key.public_key().public_bytes_raw()).decode()
    profile = {
        "schema": "ace.publisher-profile.v1",
        "purpose": "ace.release.publisher.v1",
        "publisher": "test-publisher",
        "public_key": public,
        "runtime_key_exclusions": [],
    }
    enrollment = tmp_path / "publisher-profile.json"
    save(enrollment, profile)
    pin = "sha256:" + hashlib.sha256(canonical(profile)).hexdigest()
    state = tmp_path / "consumer.json"
    save(
        state,
        {
            "schema": "ace.release-consumer.v1",
            "publisher": "test-publisher",
            "last_version": None,
            "last_manifest_sha256": None,
        },
    )
    base = [sys.executable, "-I", str(installed)]
    common = ["--bundle", str(bundle), "--publisher-profile", str(enrollment), "--publisher-pin", pin]
    issue = base + [
        "issue",
        *common,
        "--private-key-file",
        str(private),
        "--source",
        str(source),
        "--source-commit",
        commit,
        "--source-tree",
        tree,
        "--version",
        "1.0.0",
        "--artifact",
        artifact.name,
        "--recipe",
        "recipe.txt",
        "--recipe-source",
        "recipe.txt",
        "--lock",
        "requirements.lock",
        "--lock-source",
        "requirements.lock",
        "--sbom",
        "sbom.json",
        "--verifier",
        "release_manifest.py",
    ]
    verify = base + ["verify", *common, "--expected-version", "1.0.0", "--state", str(state)]
    return {
        "bundle": bundle,
        "key": key,
        "private": private,
        "enrollment": enrollment,
        "profile": profile,
        "state": state,
        "source": source,
        "issue": issue,
        "verify": verify,
        "artifact": artifact,
    }


def changed_arg(args, name, value):
    args = list(args)
    args[args.index(name) + 1] = value
    return args


def resign(release, edit, domain=DOMAIN):
    path = release["bundle"] / "release-manifest.json"
    envelope = json.loads(path.read_text())
    edit(envelope["payload"])
    envelope["signature"] = base64.b64encode(
        release["key"].sign(domain + canonical(envelope["payload"]))
    ).decode()
    save(path, envelope)


def test_real_issue_verify_and_replay(release):
    assert command(release["issue"])["status"] == "ISSUED"
    assert command(release["verify"])["status"] == "VERIFIED"
    assert command(release["verify"], 3)["code"] == "VERSION_REPLAY"
    assert json.loads(release["state"].read_text())["last_version"] == "1.0.0"


@pytest.mark.parametrize(
    "case",
    [
        "wrong-pin",
        "tamper",
        "missing",
        "extra",
        "empty-extra-dir",
        "wrong-version",
        "signature",
        "wrong-domain",
        "purpose",
        "path-escape",
        "missing-state",
        "state-inside",
        "profile-inside",
        "hardlink",
        "old-version",
    ],
)
def test_actual_bundle_refusals(release, case):
    command(release["issue"])
    verify = release["verify"]
    if case == "wrong-pin":
        verify = changed_arg(verify, "--publisher-pin", "sha256:" + "0" * 64)
    elif case == "tamper":
        release["artifact"].write_bytes(release["artifact"].read_bytes() + b"tamper")
    elif case == "missing":
        release["artifact"].unlink()
    elif case == "extra":
        (release["bundle"] / "undeclared.txt").write_text("extra")
    elif case == "empty-extra-dir":
        (release["bundle"] / "undeclared").mkdir()
    elif case == "wrong-version":
        verify = changed_arg(verify, "--expected-version", "2.0.0")
    elif case == "signature":
        path = release["bundle"] / "release-manifest.json"
        x = json.loads(path.read_text())
        x["signature"] = base64.b64encode(bytes(64)).decode()
        save(path, x)
    elif case == "wrong-domain":
        resign(release, lambda p: None, domain=b"ACE-RUNTIME-VERDICT\x00")
    elif case == "purpose":
        resign(release, lambda p: p.update(purpose="ace.runtime.verdict"))
    elif case == "path-escape":
        resign(release, lambda p: p.update(artifact="../outside.whl"))
    elif case == "missing-state":
        release["state"].unlink()
    elif case == "state-inside":
        verify = changed_arg(verify, "--state", str(release["bundle"] / "consumer.json"))
    elif case == "profile-inside":
        target = release["bundle"] / "publisher-profile.json"
        shutil.copy2(release["enrollment"], target)
        verify = changed_arg(verify, "--publisher-profile", str(target))
    elif case == "hardlink":
        outside = release["artifact"].parent.parent / "outside.whl"
        release["artifact"].rename(outside)
        os.link(outside, release["artifact"])
    elif case == "old-version":
        x = json.loads(release["state"].read_text())
        x["last_version"] = "2.0.0"
        save(release["state"], x)
    result = command(verify, 3)
    assert result["status"] == "REFUSED"


def test_runtime_key_collision_is_denied_by_both_operations(release):
    command(release["issue"])
    profile = release["profile"]
    profile["runtime_key_exclusions"] = [profile["public_key"]]
    save(release["enrollment"], profile)
    pin = "sha256:" + hashlib.sha256(canonical(profile)).hexdigest()
    for args in (release["issue"], release["verify"]):
        assert command(changed_arg(args, "--publisher-pin", pin), 3)["code"] == "RUNTIME_KEY_REUSE"


@pytest.mark.parametrize(
    "case", ["dirty", "commit", "tree", "recipe", "lock", "sbom-hash", "sbom-dependency", "wrong-key"]
)
def test_issuer_refuses_bad_provenance_or_inventory(release, case):
    issue = release["issue"]
    if case == "dirty":
        (release["source"] / "untracked.txt").write_text("dirty")
    elif case in ("commit", "tree"):
        issue = changed_arg(issue, "--source-" + case, "0" * 40)
    elif case in ("recipe", "lock"):
        name = "recipe.txt" if case == "recipe" else "requirements.lock"
        (release["bundle"] / name).write_text("changed")
    elif case.startswith("sbom"):
        path = release["bundle"] / "sbom.json"
        bom = json.loads(path.read_text())
        if case == "sbom-hash":
            bom["metadata"]["component"]["hashes"][0]["content"] = "0" * 64
        else:
            bom["components"] = []
        save(path, bom)
    else:
        key = Ed25519PrivateKey.generate()
        release["private"].write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
    assert command(issue, 3)["status"] == "REFUSED"
    assert not (release["bundle"] / "release-manifest.json").exists()


def test_actual_symlink_or_windows_junction_refused(release):
    command(release["issue"])
    external = release["bundle"].parent / "external"
    external.mkdir()
    (external / "file.txt").write_text("outside")
    link = release["bundle"] / "escape"
    if os.name == "nt":
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(external)], capture_output=True, check=True
        )
    else:
        link.symlink_to(external, target_is_directory=True)
    assert command(release["verify"], 3)["code"] == "UNSAFE_DIRECTORY"


def test_concurrent_replay_only_one_acceptance(release):
    command(release["issue"])

    def verify():
        return subprocess.run(release["verify"], capture_output=True, text=True, timeout=30)

    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda _: verify(), range(2)))
    assert sorted(result.returncode for result in results) == [0, 3]
    rejected = next(result for result in results if result.returncode == 3)
    assert json.loads(rejected.stderr)["code"] in ("VERSION_REPLAY", "CONSUMER_STATE_BUSY")


def test_companion_has_no_runtime_or_model_imports():
    tree = ast.parse(TOOL.read_text())
    imports = {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not imports & {"closure_engine", "work_ledger", "openai", "anthropic"}


def test_tampered_companion_refused(release):
    command(release["issue"])
    with (release["bundle"] / "release_manifest.py").open("ab") as stream:
        stream.write(b"# altered\n")
    assert command(release["verify"], 3)["code"] == "ARTIFACT_MISMATCH"


def test_duplicate_json_refused(release):
    command(release["issue"])
    p = release["bundle"] / "release-manifest.json"
    raw = p.read_bytes()
    p.write_bytes(b'{"signature":"duplicate",' + raw[1:])
    assert command(release["verify"], 3)["code"] == "DUPLICATE_JSON_KEY"


def test_pre_release_order_preserves_high_water(release):
    artifact = release["artifact"]
    with zipfile.ZipFile(artifact) as wheel:
        members = {name: wheel.read(name) for name in wheel.namelist()}
    metadata_path = next(name for name in members if name.endswith(".dist-info/METADATA"))
    members[metadata_path] = members[metadata_path].replace(b"Version: 1.0.0\n", b"Version: 1.0.0.dev1\n")
    with zipfile.ZipFile(artifact, "w") as wheel:
        for name, value in members.items():
            wheel.writestr(name, value)
    sbom_path = release["bundle"] / "sbom.json"
    sbom = json.loads(sbom_path.read_text())
    sbom["metadata"]["component"]["version"] = "1.0.0.dev1"
    sbom["metadata"]["component"]["hashes"][0]["content"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
    save(sbom_path, sbom)
    command(changed_arg(release["issue"], "--version", "1.0.0.dev1"))
    verify = changed_arg(release["verify"], "--expected-version", "1.0.0.dev1")
    assert command(verify)["status"] == "VERIFIED"
    state = json.loads(release["state"].read_text())
    state["last_version"] = "1.0.0rc1"
    save(release["state"], state)
    assert command(verify, 3)["code"] == "VERSION_REPLAY"


def test_release_version_must_match_wheel_metadata_at_issue(release):
    issue = changed_arg(release["issue"], "--version", "2.0.0")
    assert command(issue, 3)["code"] == "RELEASE_VERSION_MISMATCH"
    assert not (release["bundle"] / "release-manifest.json").exists()


def test_release_version_must_match_wheel_metadata_at_verify(release):
    command(release["issue"])
    resign(release, lambda p: p.update(version="2.0.0"))
    verify = changed_arg(release["verify"], "--expected-version", "2.0.0")
    assert command(verify, 3)["code"] == "RELEASE_VERSION_MISMATCH"
    assert json.loads(release["state"].read_text())["last_version"] is None
