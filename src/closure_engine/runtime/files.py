"""Exclusive, durable file creation for runtime state. Nothing here overwrites existing state."""

import os
from pathlib import Path

from ..protocol import ClosureError, canonical, strict_loads

PRIVATE_MODE = 0o600
_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)


def create_exclusive(path, raw, *, private=False):
    """Create ``path`` with ``raw`` bytes; fail if it exists. fsync before returning."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, _FLAGS, PRIVATE_MODE if private else 0o644)
    except FileExistsError as exc:
        raise ClosureError("STATE_ALREADY_EXISTS", str(path)) from exc
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path


def create_json(path, value, *, private=False):
    return create_exclusive(path, canonical(value) + b"\n", private=private)


def replace_json(path, value):
    """Atomic replace for mutable runtime records (tmp -> fsync -> rename)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    with open(temp, "wb") as stream:
        stream.write(canonical(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)
    return path


def read_json(path, missing_code):
    path = Path(path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise ClosureError(missing_code, str(path)) from exc
    return strict_loads(raw.rstrip(b"\n"))
