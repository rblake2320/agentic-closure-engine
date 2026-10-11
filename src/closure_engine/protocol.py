"""Bounded protocol parsing, canonical bytes and time primitives."""

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from importlib.resources import files

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker

MAX_BYTES = 1_048_576
MAX_DEPTH = 24
POLICY_HASH = "sha256:" + hashlib.sha256(b"ACE/v1/20261011/mandatory-fail-first+packet-replay-v2").hexdigest()
GENESIS = "sha256:" + hashlib.sha256(b"ACE/v1/genesis").hexdigest()
DATE_CHECKER = FormatChecker()


@DATE_CHECKER.checks("date-time", raises=ValueError)
def _utc_timestamp_format(value):
    milliseconds(value)
    return True


class ClosureError(ValueError):
    def __init__(self, code, detail=""):
        self.code = code
        super().__init__(code + (": " + detail if detail else ""))


def _bounded(value, depth=0):
    if depth > MAX_DEPTH:
        raise ClosureError("INPUT_TOO_DEEP")
    if isinstance(value, dict):
        if len(value) > 512 or any(not isinstance(k, str) for k in value):
            raise ClosureError("INVALID_OBJECT")
        for k, v in value.items():
            _bounded(k, depth + 1)
            _bounded(v, depth + 1)
    elif isinstance(value, list):
        if len(value) > 4096:
            raise ClosureError("TOO_MANY_ITEMS")
        for v in value:
            _bounded(v, depth + 1)
    elif isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeError as exc:
            raise ClosureError("INVALID_UNICODE") from exc
    elif isinstance(value, bool) or value is None:
        return
    elif isinstance(value, int):
        if abs(value) > 2**53 - 1:
            raise ClosureError("INTEGER_RANGE")
    else:
        raise ClosureError("INVALID_PROTOCOL_TYPE")


def canonical(value):
    _bounded(value)
    try:
        raw = rfc8785.dumps(value)
    except (ValueError, UnicodeError) as exc:
        raise ClosureError("CANONICALIZATION_FAILED") from exc
    if len(raw) > MAX_BYTES:
        raise ClosureError("INPUT_TOO_LARGE")
    return raw


def digest(value):
    raw = value if isinstance(value, bytes) else canonical(value)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _unique(pairs):
    value = {}
    for k, v in pairs:
        if k in value:
            raise ClosureError("DUPLICATE_KEY")
        value[k] = v
    return value


def strict_loads(raw):
    if isinstance(raw, bytes):
        if len(raw) > MAX_BYTES:
            raise ClosureError("INPUT_TOO_LARGE")
        try:
            raw = raw.decode("utf-8")
        except UnicodeError as exc:
            raise ClosureError("INVALID_UNICODE") from exc
    if not isinstance(raw, str) or len(raw.encode("utf-8", errors="surrogatepass")) > MAX_BYTES:
        raise ClosureError("INPUT_TOO_LARGE")
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
        canonical(value)
        return value
    except ClosureError:
        raise
    except (ValueError, RecursionError) as exc:
        raise ClosureError("INVALID_JSON") from exc


def validate(name, value):
    canonical(value)
    try:
        schema = strict_loads(files("closure_engine").joinpath("schemas", "v1", name + ".json").read_bytes())
    except FileNotFoundError as exc:
        raise ClosureError("UNKNOWN_SCHEMA") from exc
    errors = list(Draft202012Validator(schema, format_checker=DATE_CHECKER).iter_errors(value))
    if errors:
        raise ClosureError("SCHEMA_INVALID", str(errors[0].message)[:240])
    return value


def milliseconds(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z", value
    ):
        raise ClosureError("INVALID_TIMESTAMP")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        delta = dt - datetime(1970, 1, 1, tzinfo=UTC)
        return (delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds // 1000
    except (ValueError, OverflowError) as exc:
        raise ClosureError("INVALID_TIMESTAMP") from exc


def timestamp(ms):
    dt = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(milliseconds=ms)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")
