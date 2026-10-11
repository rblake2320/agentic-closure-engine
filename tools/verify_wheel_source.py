"""Bind an exact wheel to the current package sources and repository commit."""

import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--wheel", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    root, wheel = Path(args.repository).resolve(), Path(args.wheel).resolve()
    source = root / "src" / args.package
    entries = []
    with zipfile.ZipFile(wheel) as archive:
        members = {
            name
            for name in archive.namelist()
            if name.startswith(args.package + "/") and not name.endswith("/")
        }
        expected = {
            path.relative_to(root / "src").as_posix()
            for path in source.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
        }
        assert members == expected, {
            "missing": sorted(expected - members),
            "unexpected": sorted(members - expected),
        }
        for name in sorted(members):
            packaged = archive.read(name)
            actual = (root / "src" / name).read_bytes()
            assert actual == packaged, "Wheel differs from source: " + name
            entries.append({"path": name, "sha256": hashlib.sha256(packaged).hexdigest()})
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    dirty = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=no"], cwd=root, text=True
    )
    assert not dirty, "Commit tracked source changes before binding the wheel"
    result = {
        "result": "Worked",
        "commit": commit,
        "wheel": str(wheel),
        "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "package_files": entries,
    }
    with Path(args.output).open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(result, indent=2))
    print(json.dumps({"result": "Worked", "commit": commit, "files": len(entries), "receipt": args.output}))


if __name__ == "__main__":
    main()
