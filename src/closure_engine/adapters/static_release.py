"""Real static-file release target implementing ACE HTTP target protocol v1.

An approved ZIP becomes an immutable release directory. Activation changes one atomic
descriptor, never a live directory tree. Recovery deploys the exact retained ZIP bytes.
The state root is operator-owned custody: actors must not have filesystem write access.
"""

import argparse
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import stat
import threading
import time
import zipfile
import zlib
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

from ..protocol import ClosureError, canonical, digest, strict_loads
from ..runtime.files import create_exclusive, create_json, read_json, replace_json
from ..runtime.target import ARTIFACT_PATH, STATE_PATH

MAX_ARCHIVE = 524_288
MAX_EXPANDED = 8 * 1024 * 1024
MAX_FILE = 1024 * 1024
MAX_ENTRIES = 128
MAX_RATIO = 100
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
HASH = re.compile(r"sha256:[0-9a-f]{64}")
INTENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}")
RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10))}
MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".txt": "text/plain; charset=utf-8",
    ".webp": "image/webp",
}


def _safe_name(name):
    if not isinstance(name, str) or len(name) > 240 or ".." in name:
        raise ClosureError("ARCHIVE_PATH_INVALID")
    parts = name.split("/")
    if any(not NAME.fullmatch(p) or p.endswith(".") or p.split(".")[0].upper() in RESERVED for p in parts):
        raise ClosureError("ARCHIVE_PATH_INVALID")
    if parts[0].lower() in {"ace", "protected", "release-status"}:
        raise ClosureError("ARCHIVE_PATH_RESERVED")
    return parts


def validate_archive(raw):
    """Fully admit a bounded ZIP before any file creation, never ZIP extract/extractall."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_ARCHIVE:
        raise ClosureError("ARTIFACT_TOO_LARGE")
    if not raw.startswith(b"PK\x03\x04"):
        raise ClosureError("ARCHIVE_INVALID")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            if not 1 <= len(entries) <= MAX_ENTRIES:
                raise ClosureError("ARCHIVE_ENTRY_LIMIT")
            seen, file_keys, files, declared = set(), set(), {}, 0
            for info in entries:
                name = info.filename.rstrip("/") if info.is_dir() else info.filename
                _safe_name(name)
                key = name.casefold()
                if info.orig_filename != info.filename or key in seen:
                    raise ClosureError("ARCHIVE_DUPLICATE_OR_ALIAS")
                seen.add(key)
                mode = info.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if kind not in {0, stat.S_IFDIR if info.is_dir() else stat.S_IFREG}:
                    raise ClosureError("ARCHIVE_SPECIAL_FILE")
                if info.flag_bits & 1 or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    raise ClosureError("ARCHIVE_ENCODING_UNSUPPORTED")
                if info.is_dir():
                    if info.file_size:
                        raise ClosureError("ARCHIVE_INVALID")
                    continue
                if Path(name).suffix.lower() not in MIME:
                    raise ClosureError("ARCHIVE_CONTENT_TYPE_UNSUPPORTED")
                if info.file_size > MAX_FILE or info.file_size > max(1, info.compress_size) * MAX_RATIO:
                    raise ClosureError("ARCHIVE_EXPANSION_LIMIT")
                declared += info.file_size
                if declared > MAX_EXPANDED:
                    raise ClosureError("ARCHIVE_EXPANSION_LIMIT")
                with archive.open(info) as stream:
                    content = stream.read(min(MAX_FILE, info.file_size) + 1)
                if len(content) != info.file_size:
                    raise ClosureError("ARCHIVE_LENGTH_MISMATCH")
                files[name] = content
                file_keys.add(key)
            # A file cannot also be a directory, including case-folded Windows aliases.
            for name in seen:
                if any(
                    parent in file_keys
                    for parent in ("/".join(name.split("/")[:i]) for i in range(1, len(name.split("/"))))
                ):
                    raise ClosureError("ARCHIVE_PATH_CONFLICT")
            if "release.json" not in files or "index.html" not in files:
                raise ClosureError("RELEASE_MANIFEST_MISSING")
            manifest = strict_loads(files["release.json"])
            if (
                not isinstance(manifest, dict)
                or set(manifest) != {"version", "entrypoint"}
                or type(manifest["version"]) is not int
                or not 1 <= manifest["version"] <= 2**31 - 1
                or manifest["entrypoint"] != "index.html"
            ):
                raise ClosureError("RELEASE_MANIFEST_INVALID")
            return {"manifest": manifest, "files": files}
    except (
        zipfile.BadZipFile,
        RuntimeError,
        OSError,
        EOFError,
        NotImplementedError,
        zlib.error,
        UnicodeError,
    ) as exc:
        raise ClosureError("ARCHIVE_INVALID") from exc


def _guard(path):
    """Refuse symlinks and Windows reparse points in every existing path component."""
    path = Path(path).absolute()
    if str(path).startswith("\\\\"):
        raise ClosureError("UNSAFE_STORAGE_PATH")
    for component in reversed((path, *path.parents)):
        try:
            meta = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(meta.st_mode) or getattr(meta, "st_file_attributes", 0) & 0x400:
            raise ClosureError("UNSAFE_STORAGE_PATH")
    return path


def _read(path, limit):
    path = _guard(path)
    try:
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except OSError as exc:
        raise ClosureError("RELEASE_STORAGE_UNAVAILABLE") from exc
    if len(raw) > limit:
        raise ClosureError("RELEASE_CORRUPT")
    return raw


def _sync_directory(path):
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


@contextmanager
def _process_lock(path):
    """OS lock released by process death; no stale PID lock files or lock stealing."""
    with _guard(path).open("r+b") as stream:
        deadline = time.monotonic() + 5
        while True:
            try:
                if os.name == "nt":
                    import msvcrt

                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise ClosureError("TARGET_BUSY") from exc
                time.sleep(0.025)
        try:
            yield
        finally:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


class StaticReleaseTarget:
    """Persistent real release deployment, active-file readback and operator resource probes."""

    def __init__(self, root):
        self.root = _guard(root)
        self._lock = threading.Lock()
        self.config = read_json(_guard(self.root / "config.json"), "TARGET_STATE_MISSING")
        if (
            not isinstance(self.config, dict)
            or set(self.config) != {"version", "token_sha256", "protected_dir"}
            or self.config["version"] != "v1"
            or not isinstance(self.config["token_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", self.config["token_sha256"])
            or not isinstance(self.config["protected_dir"], str)
        ):
            raise ClosureError("TARGET_STATE_CORRUPT")
        self._snapshot()
        self.reconcile()

    @staticmethod
    def initialize(root, artifact, token_sha256, protected_dir):
        admitted = validate_archive(artifact)
        root, protected = _guard(root), _guard(protected_dir)
        if not re.fullmatch(r"[0-9a-f]{64}", token_sha256):
            raise ClosureError("INVALID_TOKEN_HASH")
        if root == protected or root in protected.parents or protected in root.parents:
            raise ClosureError("PROTECTED_RESOURCE_OVERLAP")
        for name in ("access.json", "retention.json"):
            strict_loads(_read(protected / name, 65536))
        if root.exists():
            raise ClosureError("STATE_ALREADY_EXISTS")
        root.mkdir(parents=True)
        (root / "releases").mkdir()
        (root / "intents").mkdir()
        create_exclusive(root / "activation.lock", b"0", private=True)
        create_json(
            root / "config.json",
            {"version": "v1", "token_sha256": token_sha256, "protected_dir": str(protected)},
            private=True,
        )
        StaticReleaseTarget._store_release(root, artifact, admitted)
        create_json(
            root / "active.json",
            {"artifact_hash": digest(artifact), "generation": 1, "intent_id": "initialize"},
        )
        _sync_directory(root)
        return {"artifact_hash": digest(artifact), "generation": 1}

    @staticmethod
    def _store_release(root, artifact, admitted):
        release = _guard(root / "releases" / digest(artifact)[7:])
        if release.exists():
            if _read(release / "artifact.zip", MAX_ARCHIVE) != artifact:
                raise ClosureError("RELEASE_CORRUPT")
            for name, raw in admitted["files"].items():
                if _read(release / "site" / name, MAX_FILE) != raw:
                    raise ClosureError("RELEASE_CORRUPT")
            return
        staging = _guard(root / "releases" / (".staging-" + secrets.token_hex(12)))
        staging.mkdir()
        create_exclusive(staging / "artifact.zip", artifact)
        for name, raw in admitted["files"].items():
            create_exclusive(_guard(staging / "site" / name), raw)
        # Data is durable before the only visible pointer can name it. Interrupted staging
        # stays unreferenced; no startup path activates it or deletes forensic material.
        for folder in sorted(
            (p for p in staging.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True
        ):
            _sync_directory(folder)
        _sync_directory(staging)
        staging.rename(release)
        _sync_directory(root / "releases")

    def _snapshot(self):
        descriptor = read_json(_guard(self.root / "active.json"), "TARGET_STATE_MISSING")
        if (
            not isinstance(descriptor, dict)
            or set(descriptor) != {"artifact_hash", "generation", "intent_id"}
            or not isinstance(descriptor["artifact_hash"], str)
            or not HASH.fullmatch(descriptor["artifact_hash"])
            or type(descriptor["generation"]) is not int
            or descriptor["generation"] < 1
            or not isinstance(descriptor["intent_id"], str)
            or not INTENT.fullmatch(descriptor["intent_id"])
        ):
            raise ClosureError("TARGET_STATE_CORRUPT")
        folder = _guard(self.root / "releases" / descriptor["artifact_hash"][7:])
        raw = _read(folder / "artifact.zip", MAX_ARCHIVE)
        if digest(raw) != descriptor["artifact_hash"]:
            raise ClosureError("RELEASE_CORRUPT")
        return descriptor, raw, validate_archive(raw), folder

    def state(self):
        descriptor = self._snapshot()[0]
        return {key: descriptor[key] for key in ("artifact_hash", "generation")}

    def artifact(self):
        return self._snapshot()[1]

    def authorized(self, token):
        return hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), self.config["token_sha256"])

    def status(self):
        descriptor, _, admitted, folder = self._snapshot()
        page = _read(folder / "site" / "index.html", MAX_FILE)
        if page != admitted["files"]["index.html"]:
            raise ClosureError("RELEASE_CORRUPT")
        return {
            "version": admitted["manifest"]["version"],
            "index_sha256": digest(page),
            "artifact_hash": descriptor["artifact_hash"],
        }

    def protected(self, name):
        if name not in {"access", "retention"}:
            raise ClosureError("RESOURCE_UNKNOWN")
        raw = _read(Path(self.config["protected_dir"]) / (name + ".json"), 65536)
        strict_loads(raw)
        return raw

    def application(self, path):
        name = "index.html" if path == "/" else path.removeprefix("/")
        _safe_name(name)
        _, _, admitted, folder = self._snapshot()
        # Guard even unknown paths, so a hostile local junction is never followed.
        file_path = _guard(folder / "site" / name)
        if name not in admitted["files"]:
            raise ClosureError("RESOURCE_UNKNOWN")
        raw = _read(file_path, MAX_FILE)
        if raw != admitted["files"][name]:
            raise ClosureError("RELEASE_CORRUPT")
        return raw, MIME[Path(name).suffix.lower()]

    def _reconcile_unlocked(self):
        descriptor = self._snapshot()[0]
        result = []
        for path in sorted(_guard(self.root / "intents").glob("*.json")):
            record = read_json(_guard(path), "INTENT_MISSING")
            if (
                not isinstance(record, dict)
                or set(record) != {"intent_id", "before_hash", "before_generation", "after_hash", "status"}
                or not isinstance(record["intent_id"], str)
                or not INTENT.fullmatch(record["intent_id"])
                or path.stem != hashlib.sha256(record["intent_id"].encode()).hexdigest()
                or any(
                    not isinstance(record[key], str) or not HASH.fullmatch(record[key])
                    for key in ("before_hash", "after_hash")
                )
                or type(record["before_generation"]) is not int
                or record["before_generation"] < 1
                or record["status"] not in {"PENDING", "APPLIED", "NOT_APPLIED"}
            ):
                raise ClosureError("ACTIVATION_QUARANTINED")
            if record["status"] != "PENDING":
                continue
            if (
                descriptor["artifact_hash"] == record["after_hash"]
                and descriptor["intent_id"] == record["intent_id"]
            ):
                record["status"] = "APPLIED"
            elif (
                descriptor["artifact_hash"] == record["before_hash"]
                and descriptor["generation"] == record["before_generation"]
            ):
                record["status"] = "NOT_APPLIED"
            else:
                raise ClosureError("ACTIVATION_QUARANTINED")
            replace_json(path, record)
            result.append({"intent_id": record["intent_id"], "status": record["status"]})
        return result

    def reconcile(self):
        with self._lock, _process_lock(self.root / "activation.lock"):
            return self._reconcile_unlocked()

    def replace(self, expected, artifact, intent_id):
        if not isinstance(expected, str) or not HASH.fullmatch(expected):
            raise ClosureError("PRECONDITION_REQUIRED")
        if not isinstance(intent_id, str) or not INTENT.fullmatch(intent_id):
            raise ClosureError("INTENT_REQUIRED")
        admitted = validate_archive(artifact)
        after = digest(artifact)
        path = _guard(self.root / "intents" / (hashlib.sha256(intent_id.encode()).hexdigest() + ".json"))
        with self._lock, _process_lock(self.root / "activation.lock"):
            self._reconcile_unlocked()
            current = self._snapshot()[0]
            if path.exists():
                prior = read_json(path, "INTENT_MISSING")
                if prior["before_hash"] != expected or prior["after_hash"] != after:
                    raise ClosureError("INTENT_CONFLICT")
                if prior["status"] == "APPLIED":
                    return (
                        200
                        if current["artifact_hash"] == after and current["intent_id"] == intent_id
                        else 412
                    )
                if prior["status"] != "NOT_APPLIED":
                    raise ClosureError("ACTIVATION_QUARANTINED")
            if current["artifact_hash"] != expected:
                return 412
            record = {
                "intent_id": intent_id,
                "before_hash": expected,
                "before_generation": current["generation"],
                "after_hash": after,
                "status": "PENDING",
            }
            if path.exists():
                replace_json(path, record)
            else:
                create_json(path, record)
            _sync_directory(path.parent)
            self._store_release(self.root, artifact, admitted)
            replace_json(
                self.root / "active.json",
                {"artifact_hash": after, "generation": current["generation"] + 1, "intent_id": intent_id},
            )
            _sync_directory(self.root)
            replace_json(path, dict(record, status="APPLIED"))
            _sync_directory(path.parent)
            return 200


def default_checks():
    """Usable enrolled profile: expected version + content hash, two live protected resources."""
    return [
        {
            "id": "site-version",
            "kind": "primary",
            "phase": "window",
            "mandatory": True,
            "probe": {"type": "http-json", "path": "/release-status", "pointer": "/version"},
        },
        {
            "id": "site-content",
            "kind": "primary",
            "phase": "window",
            "mandatory": True,
            "probe": {"type": "http-json", "path": "/release-status", "pointer": "/index_sha256"},
        },
        *(
            {
                "id": "protected-" + name,
                "kind": "invariant",
                "phase": "window",
                "mandatory": True,
                "probe": {"type": "http-unchanged", "path": "/protected/" + name},
            }
            for name in ("access", "retention")
        ),
        *(
            {"id": name, "kind": name, "phase": "instant", "mandatory": True, "probe": {"type": probe}}
            for name, probe in (
                ("deployment", "active-artifact"),
                ("stage", "staged-artifact"),
                ("baseline", "baseline-custody"),
            )
        ),
    ]


class _Handler(BaseHTTPRequestHandler):
    server_version = "ACE-Static-Release/1"

    def setup(self):
        super().setup()
        self.connection.settimeout(5)
        # Total header+body+operation ceiling; a trickle cannot reset a per-read timeout.
        self._deadline = threading.Timer(10, self._expire)
        self._deadline.daemon = True
        self._deadline.start()

    def _expire(self):
        try:
            self.connection.shutdown(2)
        except OSError:
            return

    def finish(self):
        self._deadline.cancel()
        super().finish()

    def log_message(self, *_):
        return

    def _send(self, status, raw, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'"
        )
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            return

    def _error(self, exc):
        code = exc.code if isinstance(exc, ClosureError) else "TARGET_STORAGE_ERROR"
        status = (
            404
            if code == "RESOURCE_UNKNOWN"
            else 503
            if code
            in {
                "RELEASE_CORRUPT",
                "RELEASE_STORAGE_UNAVAILABLE",
                "UNSAFE_STORAGE_PATH",
                "TARGET_STATE_CORRUPT",
                "ACTIVATION_QUARANTINED",
                "TARGET_BUSY",
            }
            or isinstance(exc, OSError)
            else 409
            if code == "INTENT_CONFLICT"
            else 400
        )
        return self._send(status, canonical({"error": code}))

    def do_GET(self):
        target = self.server.target
        try:
            if self.path == STATE_PATH:
                return self._send(200, canonical(target.state()))
            if self.path == ARTIFACT_PATH:
                return self._send(200, target.artifact(), "application/zip")
            if self.path == "/release-status":
                return self._send(200, canonical(target.status()))
            if self.path in {"/protected/access", "/protected/retention"}:
                return self._send(200, target.protected(self.path.rsplit("/", 1)[1]))
            parsed = urlsplit(self.path)
            if parsed.scheme or parsed.netloc or "%" in parsed.path:
                raise ClosureError("RESOURCE_UNKNOWN")
            raw, kind = target.application(unquote(parsed.path))
            return self._send(200, raw, kind)
        except (ClosureError, OSError) as exc:
            return self._error(exc)

    def do_PUT(self):
        target = self.server.target
        if self.path != ARTIFACT_PATH:
            return self._send(404, b'{"error":"RESOURCE_UNKNOWN"}')
        host = self.headers.get_all("Host") or []
        allowed = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
        if len(host) != 1 or host[0] not in allowed:
            return self._send(400, b'{"error":"HOST_INVALID"}')
        origin = self.headers.get_all("Origin") or []
        if origin and (len(origin) != 1 or origin[0] != "http://" + host[0]):
            return self._send(403, b'{"error":"ORIGIN_FORBIDDEN"}')
        auth = self.headers.get_all("Authorization") or []
        if len(auth) != 1 or not auth[0].startswith("Bearer ") or not target.authorized(auth[0][7:]):
            return self._send(401, b'{"error":"UNAUTHORIZED"}')
        length = self.headers.get_all("Content-Length") or []
        if (
            len(length) != 1
            or len(length[0]) > 9
            or not length[0].isascii()
            or not length[0].isdecimal()
            or self.headers.get_all("Transfer-Encoding")
        ):
            return self._send(400, b'{"error":"INVALID_LENGTH"}')
        measured = int(length[0])
        if not 0 < measured <= MAX_ARCHIVE:
            # Consume only a bounded already-sent oversized upload, so Windows does not
            # reset a normal <=2 MiB client before it receives the structured 413.
            self.connection.settimeout(0.25)
            remaining = min(measured, 2 * 1024 * 1024)
            try:
                while remaining:
                    chunk = self.rfile.read(min(remaining, 65536))
                    if not chunk:
                        break
                    remaining -= len(chunk)
            except OSError:
                pass  # Deliberately discard-only path; refusal still follows.
            return self._send(413, canonical({"error": "INPUT_TOO_LARGE", "limit_bytes": MAX_ARCHIVE}))
        expected, intent = self.headers.get_all("If-Match") or [], self.headers.get_all("X-ACE-Intent") or []
        if len(expected) != 1 or len(intent) != 1:
            return self._send(400, b'{"error":"PRECONDITION_AND_INTENT_REQUIRED"}')
        try:
            body = self.rfile.read(measured)
            if len(body) != measured:
                return self._send(400, b'{"error":"BODY_TRUNCATED"}')
            status = target.replace(expected[0], body, intent[0])
            return self._send(
                status,
                canonical({**target.state(), **({"error": "PRECONDITION_FAILED"} if status == 412 else {})}),
            )
        except (ClosureError, OSError, TimeoutError) as exc:
            return self._error(exc)

    def _unsupported(self):
        return self._send(405, b'{"error":"METHOD_NOT_ALLOWED"}')

    do_POST = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = _unsupported

    def send_error(self, code, message=None, explain=None):
        # BaseHTTPRequestHandler invokes this for malformed requests and unknown methods.
        # Never reflect attacker-controlled method, URL, headers or server paths in HTML.
        return self._send(
            405 if code == 501 else code,
            canonical({"error": "METHOD_NOT_ALLOWED" if code == 501 else "REQUEST_INVALID"}),
        )


class StaticReleaseServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, root):
        if address[0] != "127.0.0.1":
            raise ClosureError("LOOPBACK_ONLY")
        self.target = StaticReleaseTarget(root)
        self._slots = threading.BoundedSemaphore(32)
        super().__init__(address, _Handler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def pack_directory(source, output):
    source = _guard(source)
    if not source.is_dir():
        raise ClosureError("SOURCE_DIRECTORY_MISSING")
    buffer = io.BytesIO()
    count, total = 0, 0
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob("*")):
            _guard(path)
            if path.is_file():
                count += 1
                if count > MAX_ENTRIES:
                    raise ClosureError("ARCHIVE_ENTRY_LIMIT")
                name = path.relative_to(source).as_posix()
                _safe_name(name)
                raw = _read(path, MAX_FILE)
                total += len(raw)
                if total > MAX_EXPANDED:
                    raise ClosureError("ARCHIVE_EXPANSION_LIMIT")
                # Fixed archive metadata makes repeated builds of identical files identical.
                item = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
                item.compress_type = zipfile.ZIP_DEFLATED
                item.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(item, raw)
    raw = buffer.getvalue()
    validate_archive(raw)
    create_exclusive(_guard(output), raw)
    return {"artifact_hash": digest(raw), "archive_bytes": len(raw), "output": str(Path(output).absolute())}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    pack = commands.add_parser("pack", help="Build a bounded deterministic ZIP from actual site files")
    pack.add_argument("--source", required=True)
    pack.add_argument("--out", required=True)
    init = commands.add_parser("init", help="Enroll one empty operator-owned custody directory")
    init.add_argument("--root", required=True)
    init.add_argument("--archive", required=True)
    init.add_argument(
        "--token-hash-file", required=True, help="Public broker credential SHA256 file; never the credential"
    )
    init.add_argument("--protected-dir", required=True)
    serve = commands.add_parser("serve", help="Serve real site files and authenticated deployment protocol")
    serve.add_argument("--root", required=True)
    serve.add_argument("--port", type=int, default=8790)
    commands.add_parser("checks", help="Emit the real Runtime enrollment probe profile")
    args = parser.parse_args(argv)
    try:
        if args.command == "pack":
            result = pack_directory(args.source, args.out)
        elif args.command == "init":
            result = StaticReleaseTarget.initialize(
                args.root,
                _read(args.archive, MAX_ARCHIVE),
                _read(args.token_hash_file, 128).decode().strip(),
                args.protected_dir,
            )
        elif args.command == "checks":
            result = default_checks()
        else:
            server = StaticReleaseServer(("127.0.0.1", args.port), args.root)
            print(
                json.dumps({"listening": f"http://127.0.0.1:{server.server_port}", **server.target.state()}),
                flush=True,
            )
            try:
                server.serve_forever()
            finally:
                server.server_close()
            return 0
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ClosureError, OSError, UnicodeError) as exc:
        print(json.dumps({"error": exc.code if isinstance(exc, ClosureError) else "TARGET_STORAGE_ERROR"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
