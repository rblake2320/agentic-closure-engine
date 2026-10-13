"""Offline publisher attestation of a closed release directory; no ACE runtime imports."""

import argparse
import base64
import contextlib
import email.parser
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PURPOSE = "ace.release.publisher.v1"
DOMAIN = b"ACE-RELEASE-PUBLISHER-V1\x00"
SCHEMA = "ace.release-manifest.v1"
MANIFEST = "release-manifest.json"
MAX_FILE = 512 * 1024 * 1024


class Refused(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise Refused(code)


def canonical(value):
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def load(path, limit=128 * 1024):
    path = Path(path)
    require(not unsafe(path), "UNSAFE_FILE")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, "INPUT_TOO_LARGE")
    return json.loads(
        raw,
        object_pairs_hook=no_duplicates,
        parse_constant=lambda value: (_ for _ in ()).throw(Refused("NONFINITE_JSON")),
    )


def exact(value, fields, code="STRUCTURE_INVALID"):
    require(isinstance(value, dict) and set(value) == set(fields), code)


def unsafe(path):
    """No symlink, Windows junction/reparse point, including all parent components."""
    path = Path(path).absolute()
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            return True
    return False


def relative(name):
    require(isinstance(name, str) and len(name) <= 240, "PATH_INVALID")
    require(bool(re.fullmatch(r"[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*", name)), "PATH_INVALID")
    require(
        all(
            part not in (".", "..")
            and not part.endswith((".", " "))
            and part.split(".")[0].upper()
            not in {
                "CON",
                "PRN",
                "AUX",
                "NUL",
                *[f"COM{i}" for i in range(1, 10)],
                *[f"LPT{i}" for i in range(1, 10)],
            }
            for part in name.split("/")
        ),
        "PATH_INVALID",
    )
    return name


def member(root, name):
    name = relative(name)
    path = root / name
    require(not unsafe(path), "UNSAFE_FILE")
    require(path.resolve().is_relative_to(root.resolve()), "PATH_ESCAPE")
    require(path.is_file(), "FILE_MISSING")
    require(path.stat().st_nlink == 1, "HARDLINK_REFUSED")
    return path


def digest_file(path):
    require(not unsafe(path), "UNSAFE_FILE")
    digest = hashlib.sha256()
    length = 0
    with Path(path).open("rb") as stream:
        while chunk := stream.read(65536):
            length += len(chunk)
            require(length <= MAX_FILE, "FILE_TOO_LARGE")
            digest.update(chunk)
    return {"sha256": digest.hexdigest(), "bytes": length}


def inventory(root):
    require(root.is_dir() and not unsafe(root), "BUNDLE_UNSAFE")
    files = []
    directories = []
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in dirs:
            child = Path(directory) / name
            require(not unsafe(child), "UNSAFE_DIRECTORY")
            directories.append(child.relative_to(root).as_posix())
        for name in names:
            child = Path(directory) / name
            rel = child.relative_to(root).as_posix()
            member(root, rel)
            files.append(rel)
        require(len(files) <= 64 and len(directories) <= 64, "BUNDLE_TOO_MANY_FILES")
    require(len({name.casefold() for name in files}) == len(files), "CASE_COLLISION")
    return set(files), set(directories)


def outside(path, root):
    p = Path(path).absolute()
    require(not unsafe(p) and not p.resolve().is_relative_to(root.resolve()), "TRUST_MUST_BE_EXTERNAL")
    return p


def profile(path, pin, root):
    p = load(outside(path, root), 64 * 1024)
    exact(p, ("schema", "purpose", "publisher", "public_key", "runtime_key_exclusions"))
    require(p["schema"] == "ace.publisher-profile.v1" and p["purpose"] == PURPOSE, "WRONG_PURPOSE")
    require(
        isinstance(p["publisher"], str) and bool(re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", p["publisher"])),
        "PUBLISHER_INVALID",
    )
    require("sha256:" + hashlib.sha256(canonical(p)).hexdigest() == pin, "PUBLISHER_PIN_MISMATCH")
    raw = base64.b64decode(p["public_key"], validate=True)
    require(len(raw) == 32, "PUBLIC_KEY_INVALID")
    require(
        isinstance(p["runtime_key_exclusions"], list) and len(p["runtime_key_exclusions"]) <= 256,
        "EXCLUSION_INVENTORY_INVALID",
    )
    excluded = [base64.b64decode(value, validate=True) for value in p["runtime_key_exclusions"]]
    require(all(len(value) == 32 for value in excluded), "EXCLUSION_INVENTORY_INVALID")
    require(raw not in excluded, "RUNTIME_KEY_REUSE")
    return p, raw


def version(value):
    require(isinstance(value, str), "VERSION_INVALID")
    match = re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:(\.dev|a|b|rc)(0|[1-9][0-9]*))?", value
    )
    require(match is not None, "VERSION_INVALID")
    major, minor, patch, phase, count = match.groups()
    return (
        int(major),
        int(minor),
        int(patch),
        {".dev": 0, "a": 1, "b": 2, "rc": 3, None: 4}[phase],
        int(count or 0),
    )


def normalize(name):
    require(
        isinstance(name, str) and bool(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?", name)),
        "PRODUCT_NAME_INVALID",
    )
    return re.sub(r"[-_.]+", "-", name).lower()


def wheel_metadata(root, artifact):
    require(artifact.endswith(".whl"), "PRODUCT_WHEEL_REQUIRED")
    with zipfile.ZipFile(member(root, artifact)) as wheel:
        metadata_paths = [name for name in wheel.namelist() if name.endswith(".dist-info/METADATA")]
        require(len(metadata_paths) == 1, "WHEEL_METADATA_INVALID")
        info = wheel.getinfo(metadata_paths[0])
        require(info.file_size <= 1024 * 1024, "WHEEL_METADATA_INVALID")
        metadata = email.parser.BytesParser().parsebytes(wheel.read(metadata_paths[0]))

    require(
        len(metadata.get_all("Name", [])) == 1 and len(metadata.get_all("Version", [])) == 1,
        "WHEEL_METADATA_INVALID",
    )
    normalize(metadata["Name"])
    version(metadata["Version"])
    return metadata


def sbom_check(root, payload):
    bom = load(member(root, payload["sbom"]), 16 * 1024 * 1024)
    require(
        isinstance(bom, dict)
        and bom.get("bomFormat") == "CycloneDX"
        and bom.get("specVersion") in ("1.5", "1.6"),
        "SBOM_FORMAT_INVALID",
    )
    require(isinstance(bom.get("metadata"), dict), "SBOM_SUBJECT_INVALID")
    component = bom["metadata"].get("component", {})
    require(isinstance(component, dict), "SBOM_SUBJECT_INVALID")
    require(
        component.get("type") in ("application", "library") and bool(component.get("name")),
        "SBOM_SUBJECT_INVALID",
    )
    hashes = component.get("hashes", [])
    require(
        any(
            h.get("alg") == "SHA-256" and h.get("content") == payload["files"][payload["artifact"]]["sha256"]
            for h in hashes
        ),
        "SBOM_ARTIFACT_MISMATCH",
    )
    require(isinstance(bom.get("components"), list), "SBOM_COMPONENTS_MISSING")
    metadata = wheel_metadata(root, payload["artifact"])
    require(payload["version"] == metadata["Version"], "RELEASE_VERSION_MISMATCH")

    require(payload["product"] == normalize(metadata["Name"]), "PRODUCT_WHEEL_MISMATCH")

    require(
        normalize(component["name"]) == normalize(metadata["Name"])
        and component.get("version") == metadata["Version"],
        "SBOM_SUBJECT_INVALID",
    )
    names = set()
    for dependency in metadata.get_all("Requires-Dist", []):
        match = re.match(r"([A-Za-z0-9][A-Za-z0-9_.-]*)", dependency)
        require(match is not None, "WHEEL_METADATA_INVALID")
        names.add(normalize(match.group(1)))
    components = bom["components"]
    require(
        all(
            isinstance(c, dict) and c.get("type") == "library" and isinstance(c.get("name"), str)
            for c in components
        ),
        "SBOM_COMPONENT_INVALID",
    )
    require(
        {normalize(c["name"]) for c in components} == names and len(components) == len(names),
        "SBOM_DEPENDENCIES_MISMATCH",
    )
    require(
        payload["sbom_scope"]
        == "product-wheel-and-direct-declared-dependencies; excludes-host-and-transitive-runtime",
        "SBOM_SCOPE_INVALID",
    )


def payload_check(root, payload):
    exact(
        payload,
        (
            "schema",
            "purpose",
            "publisher",
            "publisher_pin",
            "product",
            "version",
            "source",
            "artifact",
            "recipe",
            "lock",
            "sbom",
            "verifier",
            "sbom_scope",
            "files",
        ),
    )
    require(payload["schema"] == SCHEMA and payload["purpose"] == PURPOSE, "WRONG_PURPOSE")
    version(payload["version"])
    exact(payload["source"], ("commit", "tree", "recipe_path", "lock_path"))
    for field in ("commit", "tree"):
        require(bool(re.fullmatch(r"[0-9a-f]{40}", payload["source"][field])), "SOURCE_INVALID")
    for field in ("recipe_path", "lock_path"):
        relative(payload["source"][field])
    names = [relative(payload[key]) for key in ("artifact", "recipe", "lock", "sbom", "verifier")]
    require(len(set(names)) == 5 and MANIFEST not in names, "ROLE_PATH_COLLISION")
    require(isinstance(payload["files"], dict) and set(payload["files"]) == set(names), "INVENTORY_INVALID")
    for name, expected in payload["files"].items():
        exact(expected, ("sha256", "bytes"))
        require(
            isinstance(expected["bytes"], int)
            and not isinstance(expected["bytes"], bool)
            and 0 <= expected["bytes"] <= MAX_FILE,
            "SIZE_INVALID",
        )
        require(bool(re.fullmatch(r"[0-9a-f]{64}", expected["sha256"])), "DIGEST_INVALID")
        require(digest_file(member(root, name)) == expected, "ARTIFACT_MISMATCH")
    files, directories = inventory(root)
    require(files == set(names) | {MANIFEST}, "EXTRA_OR_MISSING_FILE")
    expected_dirs = set()
    for name in names:
        expected_dirs.update(str(p).replace("\\", "/") for p in Path(name).parents if str(p) != ".")
    require(directories == expected_dirs, "EXTRA_DIRECTORY")
    sbom_check(root, payload)


def git(source, *arguments):
    return subprocess.check_output(["git", "-C", str(source), *arguments], stderr=subprocess.PIPE)


def atomic(path, raw, replace):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=".release-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)
            os.unlink(temporary)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def issue(args):
    root = Path(args.bundle).absolute()
    p, public = profile(args.publisher_profile, args.publisher_pin, root)
    source = Path(args.source).absolute()
    require(git(source, "status", "--porcelain", "--untracked-files=all").strip() == b"", "SOURCE_NOT_CLEAN")
    require(git(source, "rev-parse", "HEAD").decode().strip() == args.source_commit, "SOURCE_PIN_MISMATCH")
    source_tree = git(source, "rev-parse", "HEAD^{tree}").decode().strip()
    require(source_tree == args.source_tree, "SOURCE_TREE_MISMATCH")
    version(args.version)
    key_path = outside(args.private_key_file, root)
    require(key_path.stat().st_size <= 8192 and key_path.stat().st_nlink == 1, "PRIVATE_KEY_INVALID")
    require(os.name == "nt" or stat.S_IMODE(key_path.stat().st_mode) & 0o077 == 0, "PRIVATE_KEY_PERMISSIONS")
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    require(isinstance(key, Ed25519PrivateKey), "PRIVATE_KEY_INVALID")
    require(key.public_key().public_bytes_raw() == public, "PUBLISHER_KEY_MISMATCH")
    payload = {
        "schema": SCHEMA,
        "purpose": PURPOSE,
        "publisher": p["publisher"],
        "publisher_pin": args.publisher_pin,
        "product": normalize(wheel_metadata(root, args.artifact)["Name"]),
        "version": args.version,
        "source": {
            "commit": args.source_commit,
            "tree": source_tree,
            "recipe_path": relative(args.recipe_source),
            "lock_path": relative(args.lock_source),
        },
        "artifact": relative(args.artifact),
        "recipe": relative(args.recipe),
        "lock": relative(args.lock),
        "sbom": relative(args.sbom),
        "verifier": relative(args.verifier),
        "sbom_scope": "product-wheel-and-direct-declared-dependencies; excludes-host-and-transitive-runtime",
        "files": {},
    }
    for name in (args.artifact, args.recipe, args.lock, args.sbom, args.verifier):
        payload["files"][relative(name)] = digest_file(member(root, name))
    for name, source_path in ((args.recipe, args.recipe_source), (args.lock, args.lock_source)):
        require(
            member(root, name).read_bytes() == git(source, "show", "HEAD:" + relative(source_path)),
            "BUILD_INPUT_NOT_COMMITTED",
        )
    require(
        member(root, args.verifier).read_bytes() == Path(__file__).read_bytes(), "VERIFIER_BYTES_MISMATCH"
    )
    envelope = {
        "payload": payload,
        "signature": base64.b64encode(key.sign(DOMAIN + canonical(payload))).decode(),
    }
    # Validate closed inventory with temporary manifest present; remove it on any failure.
    manifest = root / MANIFEST
    atomic(manifest, canonical(envelope), replace=False)
    try:
        payload_check(root, payload)
    except BaseException:
        manifest.unlink()
        raise
    return {"status": "ISSUED", "version": args.version, "manifest_sha256": digest_file(manifest)["sha256"]}


@contextlib.contextmanager
def consumer_lock(path):
    lock = Path(str(path) + ".lock")
    require(not unsafe(lock), "UNSAFE_FILE")
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        require(os.fstat(fd).st_nlink == 1, "HARDLINK_REFUSED")
        if os.name == "nt":
            import msvcrt

            if os.fstat(fd).st_size == 0:
                os.write(fd, b"0")
            os.lseek(fd, 0, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise Refused("CONSUMER_STATE_BUSY") from exc
        else:
            import fcntl

            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise Refused("CONSUMER_STATE_BUSY") from exc
        yield
    finally:
        os.close(fd)


def verify(args):
    root = Path(args.bundle).absolute()
    p, public = profile(args.publisher_profile, args.publisher_pin, root)
    envelope = load(member(root, MANIFEST))
    exact(envelope, ("payload", "signature"))
    payload = envelope["payload"]
    require(isinstance(payload, dict) and payload.get("purpose") == PURPOSE, "WRONG_PURPOSE")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            base64.b64decode(envelope["signature"], validate=True), DOMAIN + canonical(payload)
        )
    except InvalidSignature as exc:
        raise Refused("SIGNATURE_INVALID") from exc
    require(
        payload.get("publisher") == p["publisher"] and payload.get("publisher_pin") == args.publisher_pin,
        "PUBLISHER_BINDING_MISMATCH",
    )
    require(payload.get("version") == args.expected_version, "EXPECTED_VERSION_MISMATCH")
    payload_check(root, payload)
    require(payload["product"] == normalize(args.expected_product), "EXPECTED_PRODUCT_MISMATCH")
    state_path = outside(args.state, root)
    with consumer_lock(state_path):
        state = load(state_path)
        exact(
            state,
            ("schema", "publisher", "product", "last_version", "last_manifest_sha256"),
            "CONSUMER_STATE_INVALID",
        )
        require(state["product"] == payload["product"], "CONSUMER_PRODUCT_MISMATCH")
        require(
            state["schema"] == "ace.release-consumer.v1" and state["publisher"] == p["publisher"],
            "CONSUMER_STATE_INVALID",
        )
        require(
            state["last_version"] is None or version(payload["version"]) > version(state["last_version"]),
            "VERSION_REPLAY",
        )
        digest = digest_file(root / MANIFEST)["sha256"]
        state.update(last_version=payload["version"], last_manifest_sha256=digest)
        atomic(state_path, canonical(state), replace=True)
    return {
        "status": "VERIFIED",
        "version": payload["version"],
        "manifest_sha256": digest,
        "publisher": p["publisher"],
        "product": payload["product"],
        "scope": "publisher-attestation-not-reproducible-build-proof",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("issue", "verify"):
        child = sub.add_parser(command)
        for flag in ("bundle", "publisher-profile", "publisher-pin"):
            child.add_argument("--" + flag, required=True)
        if command == "issue":
            for flag in (
                "private-key-file",
                "source",
                "source-commit",
                "source-tree",
                "version",
                "artifact",
                "recipe",
                "recipe-source",
                "lock",
                "lock-source",
                "sbom",
                "verifier",
            ):
                child.add_argument("--" + flag, required=True)
        else:
            child.add_argument("--expected-product", required=True)
            child.add_argument("--expected-version", required=True)
            child.add_argument("--state", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(issue(args) if args.command == "issue" else verify(args), sort_keys=True))
        return 0
    except (
        Refused,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        OSError,
        zipfile.BadZipFile,
        subprocess.CalledProcessError,
    ) as exc:
        # Do not reflect file paths, keys, git stderr, or untrusted document text.
        print(
            json.dumps(
                {"status": "REFUSED", "code": str(exc) if isinstance(exc, Refused) else type(exc).__name__}
            ),
            file=sys.stderr,
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
