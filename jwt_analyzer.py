"""
JWT Analyzer (AppSec helper)
Author: wh0isje

What it does:
- Decodes JWT header/payload (Base64URL) safely (no network calls)
- Validates structure and common anti-patterns
- Extracts useful fields (alg, kid, typ, iss, aud, exp, nbf, iat, sub)
- Optional HS* signature verification (only if you provide the secret)

Notes:
- This tool is for analysis and validation in authorized contexts.
- It does NOT attempt to bypass authentication.
"""

import argparse
import base64
import datetime as dt
import hmac
import hashlib
import json
import re
import sys
from typing import Any, Dict, Optional, Tuple


B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def b64url_decode(data: str) -> bytes:
    if not data or not B64URL_RE.match(data):
        raise ValueError("Invalid Base64URL segment.")
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def parse_jwt(token: str) -> Tuple[str, str, str]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have 3 parts: header.payload.signature")
    return parts[0], parts[1], parts[2]


def decode_json_segment(seg: str) -> Dict[str, Any]:
    raw = b64url_decode(seg)
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Invalid JSON: {e}")
    if not isinstance(obj, dict):
        raise ValueError("JWT segment JSON must be an object.")
    return obj


def pretty(obj: Any) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True)


def ts_to_human(ts: Any) -> Optional[str]:
    if ts is None:
        return None
    try:
        ts_int = int(ts)
        return dt.datetime.fromtimestamp(ts_int, tz=dt.timezone.utc).isoformat()
    except Exception:
        return None


def verify_hs(token: str, secret: str, alg: str) -> bool:
    header_b64, payload_b64, sig_b64 = parse_jwt(token)

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    sig = b64url_decode(sig_b64)

    if alg == "HS256":
        digestmod = hashlib.sha256
    elif alg == "HS384":
        digestmod = hashlib.sha384
    elif alg == "HS512":
        digestmod = hashlib.sha512
    else:
        raise ValueError("Unsupported HS algorithm for verification.")

    expected = hmac.new(secret.encode("utf-8"), signing_input, digestmod).digest()
    return hmac.compare_digest(expected, sig)


def security_notes(header: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    notes: Dict[str, Any] = {}

    alg = str(header.get("alg", "")).upper()
    typ = header.get("typ")
    kid = header.get("kid")

    # Header checks
    if not alg:
        notes["alg_missing"] = "Header missing 'alg'. Token may be malformed."
    if alg == "NONE":
        notes["alg_none_risk"] = "alg=none is dangerous if accepted by server."
    if typ and str(typ).lower() != "jwt":
        notes["typ_unusual"] = f"typ is unusual: {typ}"
    if kid:
        notes["kid_present"] = "kid present. Ensure server-side key selection is safe (avoid path/URL injection)."

    # Claim checks (basic)
    exp = payload.get("exp")
    nbf = payload.get("nbf")
    iat = payload.get("iat")
    iss = payload.get("iss")
    aud = payload.get("aud")
    sub = payload.get("sub")

    if exp is None:
        notes["exp_missing"] = "No exp claim. Tokens without expiration increase replay risk."
    else:
        exp_h = ts_to_human(exp)
        if not exp_h:
            notes["exp_invalid"] = f"exp is not a valid UNIX timestamp: {exp}"
        else:
            try:
                exp_dt = dt.datetime.fromtimestamp(int(exp), tz=dt.timezone.utc)
                if exp_dt < dt.datetime.now(tz=dt.timezone.utc):
                    notes["exp_expired"] = f"Token appears expired (exp={exp_h})."
            except Exception:
                pass

    for k in ["nbf", "iat"]:
        v = payload.get(k)
        if v is not None and not ts_to_human(v):
            notes[f"{k}_invalid"] = f"{k} is not a valid UNIX timestamp: {v}"

    if iss is None:
        notes["iss_missing"] = "No iss claim. Ensure issuer validation is enforced if required."
    if aud is None:
        notes["aud_missing"] = "No aud claim. Ensure audience validation is enforced if required."
    if sub is None:
        notes["sub_missing"] = "No sub claim. Subject should identify the principal when relevant."

    # Scope/role heuristics
    if "role" in payload or "roles" in payload:
        notes["roles_present"] = "Role/roles claim present. Ensure authorization is server-side, not token-trusting only."
    if "scope" in payload or "scopes" in payload:
        notes["scopes_present"] = "Scope claim present. Verify scope enforcement is correct."

    return notes


def main():
    ap = argparse.ArgumentParser(description="JWT Analyzer (AppSec helper)")
    ap.add_argument("token", help="JWT string (header.payload.signature)")
    ap.add_argument("--verify-hs-secret", help="Verify HS* signature using the provided secret")
    ap.add_argument("--raw", action="store_true", help="Print raw Base64URL segments too")
    args = ap.parse_args()

    try:
        header_b64, payload_b64, sig_b64 = parse_jwt(args.token)
        header = decode_json_segment(header_b64)
        payload = decode_json_segment(payload_b64)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(2)

    alg = str(header.get("alg", "")).upper()

    print("=== JWT Analyzer ===\n")

    if args.raw:
        print("[Raw segments]")
        print(f"header_b64 : {header_b64}")
        print(f"payload_b64: {payload_b64}")
        print(f"sig_b64    : {sig_b64}\n")

    print("[Header]")
    print(pretty(header), "\n")

    print("[Payload]")
    print(pretty(payload), "\n")

    # Helpful claim rendering
    for claim in ["iat", "nbf", "exp"]:
        if claim in payload:
            human = ts_to_human(payload.get(claim))
            if human:
                print(f"[Time] {claim}: {payload.get(claim)} -> {human}")
    print()

    notes = security_notes(header, payload)
    print("[Security notes]")
    if notes:
        for k, v in notes.items():
            print(f"- {k}: {v}")
    else:
        print("- No obvious notes.")
    print()

    # Optional verification for HS*
    if args.verify_hs_secret:
        if alg not in ("HS256", "HS384", "HS512"):
            print(f"[!] Verification requested, but alg={alg} is not HS256/384/512.")
            sys.exit(3)
        try:
            ok = verify_hs(args.token, args.verify_hs_secret, alg)
            print(f"[Verify] HMAC signature ({alg}): {'VALID' if ok else 'INVALID'}")
        except Exception as e:
            print(f"[!] Verification error: {e}")
            sys.exit(4)


if __name__ == "__main__":
    main()
