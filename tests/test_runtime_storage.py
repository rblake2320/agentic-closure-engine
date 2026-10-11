"""RT-01 storage under real concurrency and RT-02 role denial vs filesystem errors.

No mocks: real threads hammer real files; a real read-only file produces a real OS
PermissionError inside a real API/custody request."""

import base64
import hashlib
import json
import os
import stat
import sys
import threading

import pytest
from test_runtime_api import RELEASE, TOKENS, VIEWER, api, call  # noqa: F401 - fixture
from test_runtime_e2e import artifact

from closure_engine.runtime.files import read_json, replace_json


def _hammer(path, read, gap):
    stop, errors = threading.Event(), []

    def reader():
        while not stop.is_set():
            try:
                value = read()
                if "n" not in value:
                    errors.append("torn")
            except FileNotFoundError:
                errors.append("reader saw a missing record")
            except PermissionError:
                pass  # a foreign reader may be refused briefly; the writer must still succeed
            if gap:
                stop.wait(gap)

    threads = [threading.Thread(target=reader) for _ in range(4)]
    for thread in threads:
        thread.start()
    try:
        for n in range(1, 301):
            replace_json(path, {"n": n})
    finally:
        stop.set()
        for thread in threads:
            thread.join()
    return errors


def test_replace_json_never_blocked_by_runtime_readers_in_a_tight_loop(tmp_path):
    path = tmp_path / "record.json"
    replace_json(path, {"n": 0})
    assert _hammer(path, lambda: read_json(path, "MISSING"), gap=0) == []
    assert read_json(path, "MISSING") == {"n": 300}


def test_replace_json_retries_past_intermittent_foreign_readers(tmp_path):
    path = tmp_path / "record.json"
    replace_json(path, {"n": 0})

    def foreign():
        with open(path, "rb") as stream:  # a plain open, e.g. an operator tool or backup reader
            return json.loads(stream.read())

    assert _hammer(path, foreign, gap=0.002) == []
    assert read_json(path, "MISSING") == {"n": 300}


def test_concurrent_writers_never_collide_on_a_shared_temp_file(tmp_path):
    path = tmp_path / "record.json"
    replace_json(path, {"w": None})
    failures = []

    def writer(name):
        for i in range(100):
            try:
                replace_json(path, {"w": name, "i": i})
            except OSError as exc:
                failures.append(type(exc).__name__)

    threads = [threading.Thread(target=writer, args=(f"w{k}",)) for k in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert failures == []
    assert set(read_json(path, "MISSING")) == {"w", "i"}
    assert not list(tmp_path.glob("*.tmp"))  # no stranded temporaries


def test_read_json_retries_through_concurrent_replacement(tmp_path):
    path = tmp_path / "record.json"
    replace_json(path, {"n": 0})
    stop, errors = threading.Event(), []

    def writer():
        n = 0
        while not stop.is_set():
            n += 1
            replace_json(path, {"n": n})

    thread = threading.Thread(target=writer)
    thread.start()
    try:
        for _ in range(500):
            try:
                assert "n" in read_json(path, "MISSING")
            except OSError as exc:
                errors.append(type(exc).__name__)
    finally:
        stop.set()
        thread.join()
    assert errors == []


@pytest.mark.skipif(sys.platform != "win32", reason="read-only target makes os.replace fail only on Windows")
def test_filesystem_permission_error_is_not_reported_as_role_denial(api, tmp_path):  # noqa: F811
    body = {
        "target_id": "shop/api",
        "transaction_id": "fs-1",
        "artifact_base64": base64.b64encode(artifact(13)).decode(),
        "expect": {"primary": 13},
        "intent": "storage",
    }
    assert call(api, "POST", "/api/v1/transactions", body, RELEASE)[0] == 201
    records = [p for p in tmp_path.rglob("transactions/*.json")]
    assert len(records) == 1
    os.chmod(records[0], stat.S_IREAD)  # a real OS PermissionError on the next atomic replace
    try:
        status, value = call(api, "POST", "/api/v1/transactions/fs-1/approve", None, RELEASE)
    finally:
        os.chmod(records[0], stat.S_IREAD | stat.S_IWRITE)
    assert status == 500 and value["error"] == "RUNTIME_ERROR"
    text = json.dumps(value)
    assert "ROLE_REQUIRED" not in text and str(tmp_path) not in text and "\\" not in text


def test_real_role_denial_still_reports_role_required(api):  # noqa: F811
    status, value = call(api, "POST", "/api/v1/transactions/x/approve", None, VIEWER)
    assert status == 403 and value == {"error": "ROLE_REQUIRED", "role": "owner"}


def test_role_denied_is_not_an_os_error():
    from closure_engine.runtime.rpc import RoleDenied

    assert not issubclass(RoleDenied, OSError)
    assert hashlib.sha256(b"x")  # module import sanity
    assert TOKENS
