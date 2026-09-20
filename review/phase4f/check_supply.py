"""Inspect pinned registry archives without executing or extracting dependency code."""
import base64
import hashlib
import io
import json
import tarfile
import urllib.request
from pathlib import Path

root = Path(__file__).resolve().parents[2]
lock = json.loads((root / "companions/bbs/npm-shrinkwrap.json").read_text())
expected = {
    "@digitalbazaar/bbs-signatures": ("3.1.0", "1b03d2528922ea6ee6f290a198136421f282fed8"),
    "@noble/curves": ("2.4.0", "656c4364dffa44c64aa0c49914b8000b278b67a9"),
    "@noble/hashes": ("2.4.0", "663c2aeeffc308ac0cded59bd32f7c212adacfc2"),
}
result = []
for name, (version, commit) in expected.items():
    value = lock["packages"]["node_modules/" + name]
    assert value["version"] == version
    assert value["resolved"].startswith("https://registry.npmjs.org/" + name + "/-/")
    with urllib.request.urlopen(value["resolved"], timeout=30) as response:
        raw = response.read(20 * 1024 * 1024 + 1)
    assert len(raw) <= 20 * 1024 * 1024
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(raw).digest()).decode()
    assert integrity == value["integrity"]
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        members = archive.getmembers()
        assert len(members) < 5000
        assert not any(m.name.lower().endswith((".node", ".exe", ".dll", ".so", ".dylib", ".wasm")) for m in members)
        package = json.load(archive.extractfile("package/package.json"))
        assert not any(h in package.get("scripts", {}) for h in ("preinstall", "install", "postinstall"))
    result.append({"package": name, "version": version, "registry_integrity": integrity,
                   "source_commit": commit, "license": package["license"],
                   "install_hooks": False, "native_binaries": False,
                   "exact_composition_independently_audited": False})
assert len(lock["packages"]) == 4
print(json.dumps({"dependencies": result, "crypto_backend_externally_qualified": False,
                  "external_crypto_review_required": True}, indent=2))
