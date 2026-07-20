"""Tests for nostr_reach. No network: websockets are mocked, crypto is checked
against official BIP-340 test vectors and NIP-19 spec vectors."""
import asyncio
import hashlib
import json
import time

import pytest

import nostr_reach as nr

# NIP-19 spec test vectors
NPUB = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg"
NPUB_HEX = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"
NSEC = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"
NSEC_HEX = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa"


# ---- key parsing ----

def test_npub_decodes_to_hex():
    assert nr.to_hex_pubkey(NPUB) == NPUB_HEX


def test_pubkey_hex_passthrough_and_lowercasing():
    assert nr.to_hex_pubkey(NPUB_HEX) == NPUB_HEX
    assert nr.to_hex_pubkey(NPUB_HEX.upper()) == NPUB_HEX
    assert nr.to_hex_pubkey("  " + NPUB + "\n") == NPUB_HEX


@pytest.mark.parametrize("bad", ["", "npub1", "nsec1" + "q" * 58, "abc123", "g" * 64, NPUB[:-1] + "b"])
def test_pubkey_invalid_inputs_raise(bad):
    with pytest.raises(ValueError):
        nr.to_hex_pubkey(bad)


def test_nsec_decodes_to_hex():
    assert nr.to_hex_seckey(NSEC) == NSEC_HEX


def test_seckey_hex_passthrough():
    assert nr.to_hex_seckey(NSEC_HEX.upper()) == NSEC_HEX
    assert nr.to_hex_seckey(NSEC_HEX + "\n") == NSEC_HEX


@pytest.mark.parametrize("bad", ["", "npub1" + "q" * 58, "deadbeef", "x" * 64])
def test_seckey_invalid_inputs_raise(bad):
    with pytest.raises(ValueError):
        nr.to_hex_seckey(bad)


# ---- strict bech32: checksum + exact 32-byte payload (a typo'd nsec must FAIL,
# ---- never silently decode to a different key) ----

def _enc_convertbits(data, frombits, tobits):
    """Encoder-side bit regrouping with padding (test helper only)."""
    acc = bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def bech32_encode(hrp, payload):
    """Valid BIP-173 bech32 encode (test helper) — lets us build wrong-length
    payloads whose checksums are nonetheless correct."""
    data = _enc_convertbits(list(payload), 8, 5)
    values = nr._bech32_hrp_expand(hrp) + data + [0] * 6
    polymod = nr._bech32_polymod(values) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(nr._CHARSET[d] for d in data + checksum)


def test_bech32_encode_helper_roundtrips_spec_vectors():
    assert bech32_encode("nsec", bytes.fromhex(NSEC_HEX)) == NSEC
    assert bech32_encode("npub", bytes.fromhex(NPUB_HEX)) == NPUB


def test_nsec_single_char_typo_rejected():
    # flip one data character: without checksum verification this decoded to a
    # DIFFERENT secret key and --probe published from the wrong identity
    i = 20
    wrong = nr._CHARSET[(nr._CHARSET.index(NSEC[i]) + 1) % 32]
    typo = NSEC[:i] + wrong + NSEC[i + 1:]
    assert typo != NSEC
    with pytest.raises(ValueError):
        nr.to_hex_seckey(typo)


def test_nsec_short_payload_rejected_even_with_valid_checksum():
    short = bech32_encode("nsec", bytes.fromhex(NSEC_HEX)[:12])  # 12-byte key
    with pytest.raises(ValueError):
        nr.to_hex_seckey(short)


def test_nsec_overlong_payload_rejected_not_truncated():
    overlong = bech32_encode("nsec", bytes.fromhex(NSEC_HEX) + b"\x00" * 8)  # 40 bytes
    with pytest.raises(ValueError):
        nr.to_hex_seckey(overlong)


def test_npub_wrong_length_and_typo_rejected():
    with pytest.raises(ValueError):
        nr.to_hex_pubkey(bech32_encode("npub", bytes.fromhex(NPUB_HEX)[:16]))
    i = 25
    wrong = nr._CHARSET[(nr._CHARSET.index(NPUB[i]) + 1) % 32]
    with pytest.raises(ValueError):
        nr.to_hex_pubkey(NPUB[:i] + wrong + NPUB[i + 1:])


def test_mixed_case_bech32_rejected():
    mixed = NSEC[:10] + NSEC[10:].upper()
    with pytest.raises(ValueError):
        nr.to_hex_seckey(mixed)


def test_all_uppercase_bech32_accepted():
    assert nr.to_hex_seckey(NSEC.upper()) == NSEC_HEX
    assert nr.to_hex_pubkey(NPUB.upper()) == NPUB_HEX


def test_get_secret_key_from_env(monkeypatch):
    monkeypatch.setenv("NOSTR_SECRET_KEY", NSEC)
    assert nr.get_secret_key() == NSEC_HEX


def test_get_secret_key_prompts_when_env_missing(monkeypatch):
    monkeypatch.delenv("NOSTR_SECRET_KEY", raising=False)
    monkeypatch.setattr(nr.getpass, "getpass", lambda prompt: NSEC)
    assert nr.get_secret_key() == NSEC_HEX


def test_cli_has_no_secret_key_argument():
    # the secret must never be accepted via argv (shell history leak)
    with pytest.raises(SystemExit):
        nr.main([NPUB, "--nsec", NSEC_HEX])


# ---- BIP-340 Schnorr, official test vectors (bip-0340/test-vectors.csv) ----

SIGN_VECTORS = [  # (index, seckey, pubkey, aux_rand, message, signature)
    (0,
     "0000000000000000000000000000000000000000000000000000000000000003",
     "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
     "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"),
    (1,
     "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
     "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
     "0000000000000000000000000000000000000000000000000000000000000001",
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
     "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"),
    (2,
     "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
     "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
     "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
     "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
     "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1B"
     "AB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7"),
    (3,  # test fails if msg is reduced modulo p or n
     "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
     "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
     "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC"
     "97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3"),
]

VERIFY_VECTORS = [  # (index, pubkey, message, signature, expected, comment)
    (4,
     "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
     "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
     "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63"
     "76AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
     True, "valid"),
    (5,
     "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
     "69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
     False, "public key not on the curve"),
    (6,
     "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556"
     "3CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
     False, "has_even_y(R) is false"),
    (7,
     "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F"
     "28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
     False, "negated message"),
    (8,
     "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
     "961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
     False, "negated s value"),
]


@pytest.mark.parametrize("idx,seckey,pubkey,aux,msg,sig", SIGN_VECTORS,
                         ids=[f"vector-{v[0]}" for v in SIGN_VECTORS])
def test_bip340_sign_official_vectors(idx, seckey, pubkey, aux, msg, sig):
    got = nr.schnorr_sign(bytes.fromhex(msg), bytes.fromhex(seckey), bytes.fromhex(aux))
    assert got.hex().upper() == sig
    assert nr.seckey_to_pubkey(seckey) == pubkey.lower()


@pytest.mark.parametrize("idx,pubkey,msg,sig,expected,comment", VERIFY_VECTORS,
                         ids=[f"vector-{v[0]}-{v[5].replace(' ', '-')}" for v in VERIFY_VECTORS])
def test_bip340_verify_official_vectors(idx, pubkey, msg, sig, expected, comment):
    assert nr.schnorr_verify(bytes.fromhex(msg), bytes.fromhex(pubkey), bytes.fromhex(sig)) is expected


def test_sign_with_random_aux_verifies():
    msg = hashlib.sha256(b"nostr-reach probe").digest()
    sig = nr.schnorr_sign(msg, bytes.fromhex(NSEC_HEX))  # aux from os.urandom
    pub = bytes.fromhex(nr.seckey_to_pubkey(NSEC_HEX))
    assert nr.schnorr_verify(msg, pub, sig)
    assert not nr.schnorr_verify(hashlib.sha256(b"other").digest(), pub, sig)


def test_sign_rejects_out_of_range_seckey():
    with pytest.raises(ValueError):
        nr.schnorr_sign(b"\x00" * 32, b"\x00" * 32)
    with pytest.raises(ValueError):
        nr.schnorr_sign(b"\x00" * 32, b"\xff" * 32)  # >= curve order n


# ---- NIP-01 event id + event building ----

def test_event_id_matches_hand_computed_serialization():
    # hand-written canonical NIP-01 serialization: [0,pubkey,created_at,kind,tags,content],
    # no whitespace, raw UTF-8 (no \\uXXXX escaping), quotes escaped
    ser = ('[0,"' + NPUB_HEX + '",1721000000,1,[["expiration","1721000600"]],'
           '"probe: \\"hi\\" ✓\\nbye"]')
    expected = hashlib.sha256(ser.encode()).hexdigest()
    got = nr.event_id(NPUB_HEX, 1721000000, 1, [["expiration", "1721000600"]],
                      'probe: "hi" ✓\nbye')
    assert got == expected


def test_event_id_simple_ascii():
    ser = '[0,"' + "a" * 64 + '",1700000000,5,[],"hello"]'
    assert nr.event_id("a" * 64, 1700000000, 5, [], "hello") == hashlib.sha256(ser.encode()).hexdigest()


def test_build_event_is_complete_signed_and_valid():
    tags = [["expiration", "1721000600"]]
    ev = nr.build_event(NSEC_HEX, 1, tags, nr.PROBE_CONTENT, created_at=1721000000)
    assert ev["pubkey"] == nr.seckey_to_pubkey(NSEC_HEX)
    assert ev["kind"] == 1 and ev["tags"] == tags and ev["created_at"] == 1721000000
    assert ev["id"] == nr.event_id(ev["pubkey"], 1721000000, 1, tags, nr.PROBE_CONTENT)
    assert nr.schnorr_verify(bytes.fromhex(ev["id"]), bytes.fromhex(ev["pubkey"]),
                             bytes.fromhex(ev["sig"]))


def test_build_event_defaults_created_at_to_now():
    before = int(time.time())
    ev = nr.build_event(NSEC_HEX, 5, [["e", "f" * 64]], "cleanup")
    assert before <= ev["created_at"] <= int(time.time())


# ---- relay OK / AUTH / NOTICE handling (mocked websocket, no network) ----

EID = "e" * 64


class FakeWS:
    """Feeds canned frames to _await_ok / probe_relay, records sends, then 'closes'."""

    def __init__(self, frames):
        self.frames = list(frames)
        self.sent = []

    async def recv(self):
        if not self.frames:
            raise ConnectionError("closed")
        return self.frames.pop(0)

    async def send(self, data):
        self.sent.append(data)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def collect(frames, eid=EID, window=2.0):
    return asyncio.run(nr._await_ok(FakeWS(frames), eid, time.time() + window))


def test_ok_true_is_accepted():
    assert collect([json.dumps(["OK", EID, True, ""])]) == ("ACCEPTED", "")


def test_ok_false_is_rejected_with_verbatim_reason():
    reason = "rate-limited: slow down there chief"
    assert collect([json.dumps(["OK", EID, False, reason])]) == ("REJECTED", reason)


def test_ok_false_without_reason():
    assert collect([json.dumps(["OK", EID, False])]) == ("REJECTED", "")


def test_ok_non_boolean_truthy_is_not_accepted():
    # a broken relay sending the string "false" (truthy in Python) must not
    # be misreported as ACCEPTED — only boolean true counts
    assert collect([json.dumps(["OK", EID, "false", "blocked"])]) == ("REJECTED", "blocked")
    assert collect([json.dumps(["OK", EID, 1, "huh"])]) == ("REJECTED", "huh")


def test_ok_false_auth_required_prefix_maps_to_auth_required():
    reason = "auth-required: we only accept events from registered users"
    assert collect([json.dumps(["OK", EID, False, reason])]) == ("AUTH-REQUIRED", reason)


def test_auth_challenge_without_ok_is_auth_required():
    status, detail = collect([json.dumps(["AUTH", "challenge-string"])])
    assert status == "AUTH-REQUIRED"
    assert "AUTH" in detail


def test_notice_then_silence_is_no_response_with_notice_detail():
    status, detail = collect([json.dumps(["NOTICE", "restricted: bye"])])
    assert (status, detail) == ("NO-RESPONSE", "restricted: bye")


def test_silence_is_no_response():
    assert collect([]) == ("NO-RESPONSE", "")


def test_ok_for_other_event_id_is_ignored():
    frames = [json.dumps(["OK", "f" * 64, False, "not ours"]),
              json.dumps(["OK", EID, True, ""])]
    assert collect(frames) == ("ACCEPTED", "")


def test_garbage_frames_are_ignored():
    frames = ["not json", json.dumps({"kind": 1}), json.dumps([]),
              json.dumps(["OK", EID, True, "stored"])]
    assert collect(frames) == ("ACCEPTED", "stored")


def test_probe_relay_sends_event_and_reports(monkeypatch):
    ev = nr.build_event(NSEC_HEX, 1, [], "probe")
    ws = FakeWS([json.dumps(["OK", ev["id"], False, "blocked: paid relay"])])
    monkeypatch.setattr(nr.websockets, "connect", lambda *a, **k: ws)
    status, detail = asyncio.run(nr.probe_relay("wss://fake", ev, 2.0))
    assert (status, detail) == ("REJECTED", "blocked: paid relay")
    assert json.loads(ws.sent[0]) == ["EVENT", ev]


def test_probe_relay_connection_failure_is_no_response(monkeypatch):
    def boom(*a, **k):
        raise OSError("connection refused")
    monkeypatch.setattr(nr.websockets, "connect", boom)
    assert asyncio.run(nr.probe_relay("wss://down", {"id": EID}, 0.2)) == ("NO-RESPONSE", "OSError")


def test_publish_quiet_swallows_failures(monkeypatch):
    def boom(*a, **k):
        raise OSError("connection refused")
    monkeypatch.setattr(nr.websockets, "connect", boom)
    asyncio.run(nr.run_delete({"id": EID}, ["wss://a", "wss://b"], 0.2))  # must not raise


# ---- --json output (machine-readable; stdout must be pure JSON) ----

CANNED = [
    {"relay": "wss://a", "profile": True, "relay_list": False, "notes": 3, "error": None},
    {"relay": "wss://b", "profile": False, "relay_list": False, "notes": 0, "error": "TimeoutError"},
]


def _fake_run(canned):
    async def fake(pubkey, relays, limit, timeout):
        return canned
    return fake


def test_json_output_readonly(monkeypatch, capsys):
    monkeypatch.setattr(nr, "run", _fake_run(CANNED))
    rc = nr.main([NPUB, "--json", "--relays", "wss://a,wss://b"])
    assert rc == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)  # stdout is exactly one JSON object
    assert payload["pubkey"] == NPUB_HEX
    assert payload["summary"] == {"relays_queried": 2, "visible": 1, "profile": 1,
                                  "relay_list": 0, "probe_accepted": None}
    assert payload["relays"][0] == {"relay": "wss://a", "profile": True, "relay_list": False,
                                    "notes": 3, "status": "ok", "probe": None}
    assert payload["relays"][1]["status"] == "TimeoutError"
    assert payload["probe_note_id"] is None
    assert any("kind-10002" in w for w in payload["warnings"])
    assert "querying" in captured.err  # progress went to stderr, not stdout


def test_json_output_with_probe(monkeypatch, capsys):
    monkeypatch.setenv("NOSTR_SECRET_KEY", NSEC)
    own_pub = nr.seckey_to_pubkey(NSEC_HEX)
    canned = [{"relay": "wss://a", "profile": True, "relay_list": True, "notes": 1, "error": None}]

    async def fake_probe(event, relays, timeout):
        return [("ACCEPTED", "stored")]

    async def fake_delete(event, relays, timeout):
        return None

    monkeypatch.setattr(nr, "run", _fake_run(canned))
    monkeypatch.setattr(nr, "run_probe", fake_probe)
    monkeypatch.setattr(nr, "run_delete", fake_delete)
    rc = nr.main([own_pub, "--json", "--probe", "--relays", "wss://a"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["relays"][0]["probe"] == {"verdict": "ACCEPTED", "detail": "stored"}
    assert payload["summary"]["probe_accepted"] == 1
    assert len(payload["probe_note_id"]) == 64
    assert payload["warnings"] == []


def test_json_probe_pubkey_mismatch_is_a_warning(monkeypatch, capsys):
    monkeypatch.setenv("NOSTR_SECRET_KEY", NSEC)
    canned = [{"relay": "wss://a", "profile": True, "relay_list": True, "notes": 1, "error": None}]

    async def fake_probe(event, relays, timeout):
        return [("REJECTED", "blocked")]

    async def fake_delete(event, relays, timeout):
        return None

    monkeypatch.setattr(nr, "run", _fake_run(canned))
    monkeypatch.setattr(nr, "run_probe", fake_probe)
    monkeypatch.setattr(nr, "run_delete", fake_delete)
    rc = nr.main(["ab" * 32, "--json", "--probe", "--relays", "wss://a"])  # queried key != probe key
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert any("differs from the queried pubkey" in w for w in payload["warnings"])
    assert payload["relays"][0]["probe"] == {"verdict": "REJECTED", "detail": "blocked"}
    assert payload["summary"]["probe_accepted"] == 0


def test_table_output_unchanged_without_json(monkeypatch, capsys):
    monkeypatch.setattr(nr, "run", _fake_run(CANNED))
    rc = nr.main([NPUB, "--relays", "wss://a,wss://b"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "relay" in out and "profile" in out and "visible on 1/2 relays" in out
    with pytest.raises(json.JSONDecodeError):
        json.loads(out.splitlines()[0])
