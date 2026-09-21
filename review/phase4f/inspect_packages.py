"""Inspect candidate archives without extracting untrusted paths."""
import email
import hashlib
import json
import re
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

directory = Path(sys.argv[1])
wheel = directory / "myt_machine_settlement-0.6.0rc1-py3-none-any.whl"
sdist = directory / "myt_machine_settlement-0.6.0rc1.tar.gz"
companions = list(directory.glob("myt-core-bbs-companion-*.tgz"))
assert len(companions) == 1
report = {}


def inspect(name, contents, kind):
    path = PurePosixPath(name)
    assert not path.is_absolute() and ".." not in path.parts and "\\" not in name
    assert not any(p in path.parts for p in ("node_modules", ".npm", ".git", "__pycache__", "review", "research", "tests", "test"))
    assert not name.endswith((".pem", ".db", ".sqlite", ".pyc", ".exe", ".dll"))
    assert re.search(rb"(?:/home/|[A-Za-z]:\\\\Users\\\\)", contents) is None
    assert b"wsl.localhost" not in contents
    assert re.search(rb"-----BEGIN (?:ENCRYPTED |RSA |EC )?PRIVATE KEY-----[\r\n]+[A-Za-z0-9+/=\r\n]+-----END", contents) is None
    if kind != "companion":
        assert "companions" not in path.parts
    else:
        assert len(path.parts) >= 2 and path.parts[0] == "package"
        assert path.parts[1] in ("src", "README.md", "LICENSE", "npm-shrinkwrap.json", "package.json")


with zipfile.ZipFile(wheel) as archive:
    files = archive.namelist()
    for name in files:
        inspect(name, archive.read(name), "wheel")
    names = [name for name in files if name.endswith("/METADATA")]
    assert len(names) == 1
    metadata = email.message_from_bytes(archive.read(names[0]))
    assert metadata["Name"] == "myt-machine-settlement"
    assert metadata["Version"] == "0.6.0rc1"
    assert metadata.get_all("Requires-Dist") == ["cryptography>=50.0.0"]
    assert "myt_machine/disclosure.py" in files
    report["wheel"] = {"files": len(files), "runtime": metadata.get_all("Requires-Dist")}

for path, kind in ((sdist, "sdist"), (companions[0], "companion")):
    with tarfile.open(path, "r:gz") as archive:
        files = []
        for member in archive.getmembers():
            assert member.isfile() or member.isdir(), "Links or special archive members forbidden"
            if member.isfile():
                raw = archive.extractfile(member).read()
                inspect(member.name, raw, kind)
                files.append(member.name)
        if kind == "companion":
            lock = json.loads(archive.extractfile("package/npm-shrinkwrap.json").read())
            assert len(lock["packages"]) == 4
            assert lock["packages"]["node_modules/@digitalbazaar/bbs-signatures"]["version"] == "3.1.0"
        else:
            assert any(name.endswith("/docs/phase4f-protocol-v1.md") for name in files)
            assert any(name.endswith("/docs/phase4f-header-vector.json") for name in files)
        report[kind] = {"files": len(files)}
report["sha256"] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (wheel, sdist, companions[0])}
print(json.dumps(report, indent=2, sort_keys=True))
