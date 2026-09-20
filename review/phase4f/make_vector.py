"""Generate a public interoperability fixture; never writes any private key."""
import base64
import json
import sys
from pathlib import Path

from attack_candidate import IndependentAttacks

# Reuse only valid setup; protocol transport is calculated independently here.
out = Path(sys.argv[1])
IndependentAttacks.setUpClass()
case = IndependentAttacks()
try:
    case.setUp()
    credential = json.loads(case.cred.raw)
    request = json.loads(case.request.raw)
    proof = json.loads(case.proof.raw)
    canonical = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    header = b"MYT-REPUTATION-DISCLOSURE-PRESENTATION-V1\n" + canonical
    value = {
        "purpose": "PUBLIC TEST ONLY; CSPRNG-generated ephemeral keys discarded",
        "credential": credential, "request": request, "presentation": proof,
        "presentation_header_hex": header.hex(),
        "presentation_header_base64url": base64.urlsafe_b64encode(header).decode().rstrip("="),
        "proof_bytes": len(base64.urlsafe_b64decode(proof["proof"] + "==")),
        "transport_encoding_only": True,
    }
    assert case.verify(case.proof.raw)
    out.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
finally:
    case.doCleanups()
    IndependentAttacks.tearDownClass()
