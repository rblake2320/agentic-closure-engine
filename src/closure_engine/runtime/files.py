"""Exclusive, durable file creation for runtime state. Nothing here overwrites existing state."""

import os
import secrets
import time
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


# Windows refuses to rename over a file another handle has open (WinError 5/32) and briefly
# denies opens of a file being replaced. Readers hold records only momentarily, so a short,
# bounded retry resolves the race; a persistent denial (e.g. a read-only file) still fails.
RETRY_ATTEMPTS = 40
RETRY_DELAY_S = 0.025


def _retry(operation):
    for attempt in range(RETRY_ATTEMPTS):
        try:
            return operation()
        except PermissionError:
            if attempt == RETRY_ATTEMPTS - 1:
                raise
            time.sleep(RETRY_DELAY_S)


def _replace(source, target):
    """Atomic rename over ``target``. On Windows use POSIX-semantics rename (Windows 10 1709+),
    which replaces a target that readers hold open with delete sharing (see _read_shared);
    fall back to os.replace where the filesystem does not support it."""
    if os.name != "nt":
        os.replace(source, target)
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel32.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    set_info = kernel32.SetFileInformationByHandle
    set_info.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    set_info.restype = wintypes.BOOL
    close = kernel32.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    delete_access, share_all, open_existing, normal = 0x00010000, 0x7, 3, 0x80
    handle = create(str(source), delete_access, share_all, None, open_existing, normal, None)
    if handle in (None, wintypes.HANDLE(-1).value):
        os.replace(source, target)
        return
    try:
        name = str(Path(target).resolve())
        encoded = name.encode("utf-16-le")

        class RenameInfo(ctypes.Structure):
            _fields_ = [
                ("Flags", wintypes.DWORD),
                ("RootDirectory", wintypes.HANDLE),
                ("FileNameLength", wintypes.DWORD),
                ("FileName", ctypes.c_byte * (len(encoded) + 2)),
            ]

        info = RenameInfo()
        info.Flags = 0x1 | 0x2  # FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS
        info.RootDirectory = None
        info.FileNameLength = len(encoded)
        ctypes.memmove(info.FileName, encoded, len(encoded))
        file_rename_info_ex = 22
        if set_info(handle, file_rename_info_ex, ctypes.byref(info), ctypes.sizeof(info)):
            return
        error = ctypes.get_last_error()
    finally:
        close(handle)
    if error in (5, 32):
        raise PermissionError(13, "Access denied", str(target))
    os.replace(source, target)  # filesystem without POSIX rename support


def replace_json(path, value):
    """Atomic replace for mutable runtime records (unique tmp -> fsync -> rename)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f"{path.name}.{secrets.token_hex(8)}.tmp")  # writers never share a temp
    try:
        with open(temp, "wb") as stream:
            stream.write(canonical(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        _retry(lambda: _replace(temp, path))
    finally:
        if temp.exists():
            temp.unlink(missing_ok=True)
    return path


def _read_shared(path):
    """Read a record. On Windows the handle allows concurrent delete/rename, so a writer's
    atomic replace never waits on (or fails because of) a reader holding the file open."""
    if os.name != "nt":
        return Path(path).read_bytes()
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel32.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    generic_read, share_all, open_existing, normal = 0x80000000, 0x7, 3, 0x80
    handle = create(str(path), generic_read, share_all, None, open_existing, normal, None)
    if handle in (None, wintypes.HANDLE(-1).value):
        error = ctypes.get_last_error()
        if error in (2, 3):  # file / path not found
            raise FileNotFoundError(2, "No such file", str(path))
        raise PermissionError(13, "Access denied", str(path))
    fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    with os.fdopen(fd, "rb") as stream:
        return stream.read()


def read_json(path, missing_code):
    path = Path(path)
    try:
        raw = _retry(lambda: _read_shared(path))
    except FileNotFoundError as exc:
        raise ClosureError(missing_code, str(path)) from exc
    return strict_loads(raw.rstrip(b"\n"))
