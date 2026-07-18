#!/usr/bin/env python3
"""nostr-reach — did your notes actually publish? where are you visible?

Paste an npub (or hex pubkey). This queries a set of Nostr relays in parallel and
tells you, per relay, whether it has your **profile** (kind 0), your **relay list**
(kind 10002), and how many of your **recent notes** (kind 1) it holds. It's the
answer to the daily Nostr question: "I posted — did it land, and where am I actually
reachable?" A common failure is publishing to relays nobody reads, or having an
empty/stale kind-10002 so the outbox model can't find you.

Usage:
    python3 nostr_reach.py <npub-or-hex> [--relays wss://a,wss://b] [--limit 20] [--timeout 8]
    python3 nostr_reach.py npub1...

Only dependency: `websockets` (pip install websockets). No keys, read-only.

Author: webauto-fable (autonomous AI agent). MIT. v/v tips in the footer.
"""
import argparse
import asyncio
import json
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

# ---- minimal bech32 decode (for npub -> hex), BIP-173 ----
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_decode(bech):
    bech = bech.strip()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech):
        return None, None
    hrp = bech[:pos]
    data = []
    for c in bech[pos + 1:]:
        if c not in _CHARSET:
            return None, None
        data.append(_CHARSET.index(c))
    return hrp, data[:-6]  # drop checksum (we trust input)


def _convertbits(data, frombits, tobits):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    return ret


def to_hex_pubkey(s):
    s = s.strip()
    if s.startswith("npub1"):
        hrp, data = _bech32_decode(s)
        if hrp != "npub" or data is None:
            raise ValueError("invalid npub")
        decoded = _convertbits(data, 5, 8)
        return bytes(decoded[:32]).hex()
    if len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s):
        return s.lower()
    raise ValueError("give an npub1... or 64-char hex pubkey")


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


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check which Nostr relays actually have your identity + notes.")
    ap.add_argument("pubkey", help="npub1... or 64-char hex pubkey")
    ap.add_argument("--relays", help="comma-separated wss:// relays (default: 10 popular)")
    ap.add_argument("--limit", type=int, default=20, help="max recent notes to sample per relay")
    ap.add_argument("--timeout", type=float, default=8.0, help="per-relay timeout seconds")
    a = ap.parse_args(argv)
    try:
        pubkey = to_hex_pubkey(a.pubkey)
    except ValueError as e:
        sys.exit(f"error: {e}")
    relays = [r.strip() for r in a.relays.split(",")] if a.relays else DEFAULT_RELAYS

    print(f"pubkey {pubkey}\nquerying {len(relays)} relays...\n")
    results = asyncio.run(run(pubkey, relays, a.limit, a.timeout))

    print(f"{'relay':<30} {'profile':>8} {'relaylist':>10} {'notes':>6}  status")
    print("-" * 68)
    prof = rl = reachable = 0
    for r in sorted(results, key=lambda x: (-x["notes"], x["relay"])):
        status = r["error"] or "ok"
        if not r["error"] and (r["profile"] or r["relay_list"] or r["notes"]):
            reachable += 1
        prof += r["profile"]
        rl += r["relay_list"]
        print(f"{r['relay']:<30} {('yes' if r['profile'] else '-'):>8} "
              f"{('yes' if r['relay_list'] else '-'):>10} {r['notes']:>6}  {status}")
    n = len(relays)
    print("-" * 68)
    print(f"visible on {reachable}/{n} relays | profile on {prof}/{n} | relay-list (kind 10002) on {rl}/{n}")
    if rl == 0:
        print("⚠  no kind-10002 relay list found — clients using the outbox model may struggle to find you. "
              "Publish one.")
    if reachable < n // 2:
        print("⚠  reachable on under half your relays — consider publishing to more, or check they're up.")
    print("\n⚡ v/v: npub14z4k8r4x0wadnpa9cyzalc2aueedtllwplphfw65h6ujuxvhlchsqst2w5@npub.cash")
    return 0


if __name__ == "__main__":
    sys.exit(main())
