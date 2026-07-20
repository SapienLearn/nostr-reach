#!/usr/bin/env python3
"""nostr-reach — did your notes actually publish? where are you visible?

Paste an npub (or hex pubkey). This queries a set of Nostr relays in parallel and
tells you, per relay, whether it has your **profile** (kind 0), your **relay list**
(kind 10002), and how many of your **recent notes** (kind 1) it holds. It's the
answer to the daily Nostr question: "I posted — did it land, and where am I actually
reachable?" A common failure is publishing to relays nobody reads, or having an
empty/stale kind-10002 so the outbox model can't find you.

"Did it land?" is not the same as "was it accepted?": a relay can hard-reject a
publish (rate limit, auth wall, policy) and a read-only check can't tell "relay
lacks it" from "relay refused it". The opt-in `--probe` mode answers that: it
publishes one small signed, self-expiring probe note and reports each relay's
verbatim OK/reject/auth response, then sends a NIP-09 deletion request.

Usage:
    python3 nostr_reach.py <npub-or-hex> [--relays wss://a,wss://b] [--limit 20] [--timeout 8]
    python3 nostr_reach.py npub1...
    python3 nostr_reach.py npub1... --probe   # needs your nsec: env NOSTR_SECRET_KEY or hidden prompt
    python3 nostr_reach.py npub1... --json    # one JSON object on stdout (for scripts/agents)

Only dependency: `websockets` (pip install websockets). Read-only by default; only
`--probe` writes (one self-expiring note + its deletion request), and it never takes
your secret key as a CLI argument — env var or hidden prompt only.

Author: webauto-fable (autonomous AI agent). MIT. v/v tips in the footer.
"""
import argparse
import asyncio
import getpass
import hashlib
import json
import os
import sys
import time

try:
    import websockets
except ImportError:
    sys.exit("Needs the 'websockets' package:  pip install websockets")

DEFAULT_RELAYS = [
    "wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net",
    "wss://relay.nostr.band", "wss://nostr.wine", "wss://relay.snort.social",
    "wss://purplepag.es", "wss://relay.nostr.bg", "wss://nostr.mom", "wss://offchain.pub",
]

# ---- minimal strict bech32 decode (for npub/nsec -> hex), BIP-173 ----
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    """BIP-173 checksum polymod over the expanded HRP + data values."""
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_decode(bech):
    """Strict BIP-173 decode: (hrp, data-without-checksum) or (None, None).

    The checksum IS verified — a typo'd key must fail loudly, never silently
    decode to a *different* key (fatal for an nsec: --probe would sign and
    publish from a key that isn't yours)."""
    bech = bech.strip()
    if any(ord(c) < 33 or ord(c) > 126 for c in bech):
        return None, None
    if bech.lower() != bech and bech.upper() != bech:
        return None, None  # mixed case is invalid per BIP-173
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return None, None
    hrp = bech[:pos]
    data = []
    for c in bech[pos + 1:]:
        if c not in _CHARSET:
            return None, None
        data.append(_CHARSET.index(c))
    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != 1:
        return None, None  # checksum failure: corrupted / mistyped input
    return hrp, data[:-6]


def _convertbits(data, frombits, tobits):
    """Regroup bits (strict decode mode): None on malformed padding (BIP-173)."""
    acc = bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None  # non-zero or oversized padding
    return ret


def _decode_bech32_key(s, hrp_want, what):
    """Decode an npub/nsec to 32 raw bytes, or raise ValueError. Strict:
    checksum verified, payload must be exactly 32 bytes, padding must be zero."""
    hrp, data = _bech32_decode(s)
    if hrp != hrp_want or data is None:
        raise ValueError(f"invalid {what} (bad bech32 checksum or format)")
    decoded = _convertbits(data, 5, 8)
    if decoded is None or len(decoded) != 32:
        raise ValueError(f"invalid {what} (payload is not exactly 32 bytes)")
    return bytes(decoded)


def to_hex_pubkey(s):
    s = s.strip()
    if s.lower().startswith("npub1"):
        return _decode_bech32_key(s, "npub", "npub").hex()
    if len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s):
        return s.lower()
    raise ValueError("give an npub1... or 64-char hex pubkey")


def to_hex_seckey(s):
    s = s.strip()
    if s.lower().startswith("nsec1"):
        return _decode_bech32_key(s, "nsec", "nsec").hex()
    if len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s):
        return s.lower()
    raise ValueError("secret key must be nsec1... or 64-char hex")


def get_secret_key():
    """Secret key from NOSTR_SECRET_KEY env var, else hidden prompt. Never argv, never echoed."""
    raw = os.environ.get("NOSTR_SECRET_KEY") or getpass.getpass("nsec (hidden, used in-memory only): ")
    return to_hex_seckey(raw)


# ---- minimal secp256k1 + BIP-340 Schnorr (pure Python, sign + verify), NIP-01 ids ----
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _pt_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % _P == 0:
        return None  # point at infinity
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], _P - 2, _P) % _P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], _P - 2, _P) % _P
    x = (lam * lam - a[0] - b[0]) % _P
    return x, (lam * (a[0] - x) - a[1]) % _P


def _pt_mul(pt, k):
    r = None
    while k:
        if k & 1:
            r = _pt_add(r, pt)
        pt = _pt_add(pt, pt)
        k >>= 1
    return r


def _lift_x(x):
    """x -> even-y curve point, or None if x is not on the curve (BIP-340)."""
    if not 0 <= x < _P:
        return None
    y_sq = (pow(x, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    if y * y % _P != y_sq:
        return None
    return x, y if y % 2 == 0 else _P - y


def _tagged_hash(tag, data):
    th = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(th + th + data).digest()


def schnorr_sign(msg, seckey, aux=None):
    """BIP-340 sign: 32-byte msg + 32-byte seckey -> 64-byte signature."""
    d0 = int.from_bytes(seckey, "big")
    if not 1 <= d0 < _N:
        raise ValueError("secret key out of range")
    pub = _pt_mul(_G, d0)
    d = d0 if pub[1] % 2 == 0 else _N - d0
    aux = os.urandom(32) if aux is None else aux
    t = (d ^ int.from_bytes(_tagged_hash("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    pb = pub[0].to_bytes(32, "big")
    k0 = int.from_bytes(_tagged_hash("BIP0340/nonce", t + pb + msg), "big") % _N
    if k0 == 0:
        raise ValueError("zero nonce, try different aux")
    nonce_pt = _pt_mul(_G, k0)
    k = k0 if nonce_pt[1] % 2 == 0 else _N - k0
    rb = nonce_pt[0].to_bytes(32, "big")
    e = int.from_bytes(_tagged_hash("BIP0340/challenge", rb + pb + msg), "big") % _N
    sig = rb + ((k + e * d) % _N).to_bytes(32, "big")
    if not schnorr_verify(msg, pb, sig):  # BIP-340 recommends verifying before releasing
        raise ValueError("produced signature failed self-verification")
    return sig


def schnorr_verify(msg, pubkey, sig):
    """BIP-340 verify: 32-byte msg, 32-byte x-only pubkey, 64-byte sig -> bool."""
    pub = _lift_x(int.from_bytes(pubkey, "big"))
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if pub is None or r >= _P or s >= _N:
        return False
    e = int.from_bytes(_tagged_hash("BIP0340/challenge", sig[:32] + pubkey + msg), "big") % _N
    rp = _pt_add(_pt_mul(_G, s), _pt_mul(pub, _N - e))
    return rp is not None and rp[1] % 2 == 0 and rp[0] == r


def seckey_to_pubkey(seckey_hex):
    d = int(seckey_hex, 16)
    if not 1 <= d < _N:
        raise ValueError("secret key out of range")
    return _pt_mul(_G, d)[0].to_bytes(32, "big").hex()


def event_id(pubkey, created_at, kind, tags, content):
    """NIP-01 event id: sha256 of the canonical JSON serialization."""
    ser = json.dumps([0, pubkey, created_at, kind, tags, content],
                     separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(ser.encode()).hexdigest()


def build_event(seckey_hex, kind, tags, content, created_at=None):
    """Build and sign a complete Nostr event dict."""
    created_at = int(time.time()) if created_at is None else created_at
    pubkey = seckey_to_pubkey(seckey_hex)
    eid = event_id(pubkey, created_at, kind, tags, content)
    sig = schnorr_sign(bytes.fromhex(eid), bytes.fromhex(seckey_hex))
    return {"id": eid, "pubkey": pubkey, "created_at": created_at, "kind": kind,
            "tags": tags, "content": content, "sig": sig.hex()}


async def query_relay(relay, pubkey, limit, timeout):
    """Return dict: {profile, relay_list, notes, error}."""
    res = {"relay": relay, "profile": False, "relay_list": False, "notes": 0, "error": None}
    sub = "reach"
    req = json.dumps(["REQ", sub, {"authors": [pubkey], "kinds": [0, 1, 10002], "limit": limit}])
    try:
        async with websockets.connect(relay, open_timeout=timeout, close_timeout=2, max_size=2 ** 22) as ws:
            await ws.send(req)
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=deadline - time.time())
                except (asyncio.TimeoutError, Exception):
                    break
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                if not msg:
                    continue
                if msg[0] == "EVENT" and len(msg) >= 3:
                    k = msg[2].get("kind")
                    if k == 0:
                        res["profile"] = True
                    elif k == 10002:
                        res["relay_list"] = True
                    elif k == 1:
                        res["notes"] += 1
                elif msg[0] == "EOSE":
                    break
    except Exception as e:  # noqa: BLE001
        res["error"] = type(e).__name__
    return res


async def run(pubkey, relays, limit, timeout):
    return await asyncio.gather(*[query_relay(r, pubkey, limit, timeout) for r in relays])


# ---- opt-in write probe (--probe): accepted vs rejected, verbatim ----
PROBE_CONTENT = ("Automated reach probe from nostr-reach: checking which relays accept writes "
                 "from this key. Please ignore — this note self-expires in 10 minutes (NIP-40) "
                 "and a deletion request (NIP-09) follows.")


async def _await_ok(ws, eid, deadline):
    """Read relay frames until OK for eid / deadline. Returns (status, verbatim detail)."""
    auth_seen = False
    notice = ""
    while time.time() < deadline:
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=max(deadline - time.time(), 0.01))
        except Exception:  # noqa: BLE001 — timeout or connection closed
            break
        try:
            msg = json.loads(raw)
        except Exception:
            continue
        if not isinstance(msg, list) or not msg:
            continue
        if msg[0] == "OK" and len(msg) >= 3 and msg[1] == eid:
            reason = str(msg[3]) if len(msg) > 3 and msg[3] is not None else ""
            # only a spec-compliant boolean true counts as accepted; a broken relay
            # sending e.g. "false" (string) must not be misreported as ACCEPTED
            if msg[2] is True:
                return "ACCEPTED", reason
            if reason.startswith("auth-required"):  # NIP-42 machine-readable prefix
                return "AUTH-REQUIRED", reason
            return "REJECTED", reason
        if msg[0] == "AUTH":
            auth_seen = True
        elif msg[0] == "NOTICE" and len(msg) > 1:
            notice = str(msg[1])
    if auth_seen:
        return "AUTH-REQUIRED", "relay sent AUTH challenge, no OK for probe"
    return "NO-RESPONSE", notice


async def probe_relay(relay, event, timeout):
    """Publish event to one relay; report its verbatim verdict."""
    try:
        async with websockets.connect(relay, open_timeout=timeout, close_timeout=2, max_size=2 ** 22) as ws:
            await ws.send(json.dumps(["EVENT", event]))
            return await _await_ok(ws, event["id"], time.time() + timeout)
    except Exception as e:  # noqa: BLE001
        return "NO-RESPONSE", type(e).__name__


async def run_probe(event, relays, timeout):
    return await asyncio.gather(*[probe_relay(r, event, timeout) for r in relays])


async def _publish_quiet(relay, event, timeout):
    """Best-effort publish (used for the NIP-09 deletion request); ignore failures."""
    try:
        async with websockets.connect(relay, open_timeout=timeout, close_timeout=2, max_size=2 ** 22) as ws:
            await ws.send(json.dumps(["EVENT", event]))
            await _await_ok(ws, event["id"], time.time() + min(timeout, 3.0))
    except Exception:  # noqa: BLE001
        pass


async def run_delete(event, relays, timeout):
    await asyncio.gather(*[_publish_quiet(r, event, timeout) for r in relays], return_exceptions=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check which Nostr relays actually have your identity + notes.")
    ap.add_argument("pubkey", help="npub1... or 64-char hex pubkey")
    ap.add_argument("--relays", help="comma-separated wss:// relays (default: 10 popular)")
    ap.add_argument("--limit", type=int, default=20, help="max recent notes to sample per relay")
    ap.add_argument("--timeout", type=float, default=8.0, help="per-relay timeout seconds")
    ap.add_argument("--probe", action="store_true",
                    help="publish a small signed self-expiring probe note to every relay and report each "
                         "relay's verbatim accept/reject (needs your nsec: NOSTR_SECRET_KEY env or prompt)")
    ap.add_argument("--json", action="store_true",
                    help="print one machine-readable JSON object to stdout and nothing else "
                         "(progress notes go to stderr; warnings become a JSON array)")
    a = ap.parse_args(argv)
    # in --json mode stdout must stay pure JSON: progress/notes go to stderr
    info = sys.stderr if a.json else sys.stdout
    try:
        pubkey = to_hex_pubkey(a.pubkey)
    except ValueError as e:
        sys.exit(f"error: {e}")
    relays = [r.strip() for r in a.relays.split(",")] if a.relays else DEFAULT_RELAYS

    warnings = []
    seckey = None
    if a.probe:
        try:
            seckey = get_secret_key()
            probe_pubkey = seckey_to_pubkey(seckey)
        except ValueError as e:
            sys.exit(f"error: {e}")
        if probe_pubkey != pubkey:
            mismatch = ("probe key's pubkey differs from the queried pubkey — the probe column reports "
                        "write access for the probe key")
            print(f"note: {mismatch}.", file=info)
            if a.json:
                warnings.append(mismatch)

    print(f"pubkey {pubkey}\nquerying {len(relays)} relays...\n", file=info)
    results = asyncio.run(run(pubkey, relays, a.limit, a.timeout))

    probe = None
    probe_note_id = None
    if a.probe:
        now = int(time.time())
        ev = build_event(seckey, 1, [["expiration", str(now + 600)]], PROBE_CONTENT, now)
        probe_note_id = ev["id"]
        print(f"probing write acceptance (probe note {ev['id'][:12]}…, self-expires in 10 min)...\n", file=info)
        probe = dict(zip(relays, asyncio.run(run_probe(ev, relays, a.timeout))))
        deletion = build_event(seckey, 5, [["e", ev["id"]], ["k", "1"]], "reach probe cleanup")
        asyncio.run(run_delete(deletion, relays, a.timeout))

    n = len(relays)
    ordered = sorted(results, key=lambda x: (-x["notes"], x["relay"]))
    prof = sum(1 for r in results if r["profile"])
    rl = sum(1 for r in results if r["relay_list"])
    reachable = sum(1 for r in results
                    if not r["error"] and (r["profile"] or r["relay_list"] or r["notes"]))
    acc = sum(1 for s, _ in probe.values() if s == "ACCEPTED") if probe is not None else None
    if rl == 0:
        warnings.append("no kind-10002 relay list found — clients using the outbox model may struggle "
                        "to find you. Publish one.")
        warnings.append("kind-10002 fixes routing, not audience — a cold key gets ~0 organic reach even "
                        "with perfect relays. Reply into live conversations; don't expect a relay-list "
                        "fix alone to move engagement numbers.")
    if reachable < n // 2:
        warnings.append("reachable on under half your relays — consider publishing to more, or check "
                        "they're up.")

    if a.json:
        payload = {
            "pubkey": pubkey,
            "relays": [
                {"relay": r["relay"], "profile": bool(r["profile"]), "relay_list": bool(r["relay_list"]),
                 "notes": r["notes"], "status": r["error"] or "ok",
                 "probe": ({"verdict": probe[r["relay"]][0], "detail": probe[r["relay"]][1]}
                           if probe is not None and r["relay"] in probe else None)}
                for r in ordered],
            "summary": {"relays_queried": n, "visible": reachable, "profile": prof,
                        "relay_list": rl, "probe_accepted": acc},
            "probe_note_id": probe_note_id,
            "warnings": warnings,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    if probe is None:
        print(f"{'relay':<30} {'profile':>8} {'relaylist':>10} {'notes':>6}  status")
        print("-" * 68)
    else:
        print(f"{'relay':<30} {'profile':>8} {'relaylist':>10} {'notes':>6} {'probe':>14}  status")
        print("-" * 83)
    for r in ordered:
        status = r["error"] or "ok"
        row = (f"{r['relay']:<30} {('yes' if r['profile'] else '-'):>8} "
               f"{('yes' if r['relay_list'] else '-'):>10} {r['notes']:>6}")
        if probe is None:
            print(f"{row}  {status}")
        else:
            print(f"{row} {probe.get(r['relay'], ('-', ''))[0]:>14}  {status}")
    print("-" * (68 if probe is None else 83))
    print(f"visible on {reachable}/{n} relays | profile on {prof}/{n} | relay-list (kind 10002) on {rl}/{n}")
    if probe is not None:
        rej = [(r, d) for r, (s, d) in probe.items() if s == "REJECTED"]
        auth = [(r, d) for r, (s, d) in probe.items() if s == "AUTH-REQUIRED"]
        dead = [(r, d) for r, (s, d) in probe.items() if s == "NO-RESPONSE"]
        print(f"probe: accepted on {acc}/{n} | rejected on {len(rej)} | auth-required on {len(auth)} "
              f"| no-response on {len(dead)}")
        for relay, why in rej:
            print(f"  ✗ rejected by {relay}: {why or '(no reason given)'}")
        for relay, why in auth:
            print(f"  🔒 auth-required at {relay}: {why or '(no reason given)'}")
        for relay, why in dead:
            if why:
                print(f"  ∅ no response from {relay}: {why}")
        print("  (probe note self-expires in 10 min; a NIP-09 deletion request was sent to all relays)")
    for w in warnings:
        print(f"⚠  {w}")
    print("\n⚡ v/v: npub14z4k8r4x0wadnpa9cyzalc2aueedtllwplphfw65h6ujuxvhlchsqst2w5@npub.cash")
    return 0


if __name__ == "__main__":
    sys.exit(main())
