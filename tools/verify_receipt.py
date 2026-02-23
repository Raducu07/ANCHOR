import json
import sys
import hmac
import hashlib
import base64


def canonical_json_bytes(obj) -> bytes:
    # Must match server canonicalization: sort_keys + compact separators + ensure_ascii
    s = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return s.encode("utf-8")


def b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def verify(envelope: dict, secret: str) -> bool:
    receipt = envelope["receipt"]
    sig = envelope["signature"]

    payload = canonical_json_bytes(receipt)
    mac = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
    expected = b64url_nopad(mac)

    return hmac.compare_digest(expected, sig)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python tools/verify_receipt.py <signed_receipt.json> <SECRET>")
        sys.exit(2)

    path = sys.argv[1]
    secret = sys.argv[2]

    with open(path, "r", encoding="utf-8") as f:
        envelope = json.load(f)

    ok = verify(envelope, secret)
    print("VALID" if ok else "INVALID")