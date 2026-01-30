import argparse
import hashlib
import re
from dataclasses import dataclass
from typing import List, Tuple

import base58
from ecdsa import SigningKey, SECP256k1, util

from rpc import BitcoinRPC, default_cookie_path

HEX_PUB_RE = re.compile(r"^(02|03)[0-9a-fA-F]{64}$")

SIGHASH_ALL = 0x01

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def dsha256(b: bytes) -> bytes:
    return sha256(sha256(b))

def ripemd160(b: bytes) -> bytes:
    return hashlib.new("ripemd160", b).digest()

def h160(b: bytes) -> bytes:
    return ripemd160(sha256(b))

def varint(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xffffffff:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")

def pushdata(data: bytes) -> bytes:
    l = len(data)
    if l < 0x4c:
        return bytes([l]) + data
    if l <= 0xff:
        return b"\x4c" + bytes([l]) + data
    if l <= 0xffff:
        return b"\x4d" + l.to_bytes(2, "little") + data
    return b"\x4e" + l.to_bytes(4, "little") + data

def decode_base58check(s: str) -> Tuple[int, bytes]:
    raw = base58.b58decode(s)
    if len(raw) < 5:
        raise SystemExit("ERROR: Base58Check string too short")

    data, chk = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4] != chk:
        raise SystemExit("ERROR: Bad Base58Check checksum")

    version = data[0]
    payload = data[1:]
    return version, payload


def p2pkh_scriptpubkey_from_address(addr: str) -> bytes:
    ver, payload = decode_base58check(addr)
    # payload is 20-byte hash160
    if len(payload) != 20:
        raise SystemExit("ERROR: destination address payload not 20 bytes (not P2PKH?)")
    # OP_DUP OP_HASH160 <20> h160 OP_EQUALVERIFY OP_CHECKSIG
    return b"\x76\xa9" + b"\x14" + payload + b"\x88\xac"

def compress_pubkey_from_priv(privkey32: bytes) -> bytes:
    sk = SigningKey.from_string(privkey32, curve=SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    prefix = 0x02 if (y % 2 == 0) else 0x03
    return bytes([prefix]) + x.to_bytes(32, "big")

def wif_to_privkey(wif: str) -> Tuple[bytes, bool]:
    # Base58Check decode: [version][32-byte key][optional 0x01][4-byte checksum]
    raw = base58.b58decode(wif)

    if len(raw) not in (37, 38):
        raise SystemExit(f"ERROR: WIF decoded length unexpected: {len(raw)}")

    data, chk = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4] != chk:
        raise SystemExit("ERROR: Bad WIF checksum")

    version = data[0]
    if version != 0xEF:
        raise SystemExit(f"ERROR: expected regtest/testnet/signet WIF version 0xEF, got {hex(version)}")

    if len(data) == 33:
        # uncompressed (rare nowadays)
        key = data[1:33]
        return key, False

    if len(data) == 34:
        # compressed WIF has trailing 0x01
        if data[-1] != 0x01:
            raise SystemExit("ERROR: expected 0x01 compression flag in WIF")
        key = data[1:33]
        return key, True

    raise SystemExit("ERROR: unexpected WIF payload length")

def redeem_script_2of3(pubkeys: List[bytes]) -> bytes:
    # OP_2 <33>pub1 <33>pub2 <33>pub3 OP_3 OP_CHECKMULTISIG
    out = bytearray()
    out.append(0x52)
    for pk in pubkeys:
        if len(pk) != 33:
            raise SystemExit("ERROR: pubkey not 33 bytes compressed")
        out.append(0x21)
        out.extend(pk)
    out.append(0x53)
    out.append(0xAE)
    return bytes(out)

def p2sh_address_from_redeem(redeem: bytes) -> str:
    # regtest/testnet/signet P2SH prefix 0xC4
    payload = bytes([0xC4]) + h160(redeem)
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + chk).decode()


@dataclass
class UTXO:
    txid: str
    vout: int
    amount_sats: int

def scan_utxos(rpc: BitcoinRPC, address: str) -> List[UTXO]:
    # scantxoutset "start" ["addr(<address>)"]
    res = rpc.call("scantxoutset", ["start", [f"addr({address})"]])
    utxos = []
    for u in res.get("unspents", []):
        sats = int(round(u["amount"] * 100_000_000))
        utxos.append(UTXO(txid=u["txid"], vout=u["vout"], amount_sats=sats))
    return utxos

def estimate_feerate_sat_vb(rpc: BitcoinRPC, fallback: int) -> int:
    try:
        r = rpc.call("estimatesmartfee", [6])
        feerate = r.get("feerate")  # BTC/kvB
        if feerate is None:
            return fallback
        return max(1, int(round((feerate * 100_000_000) / 1000)))  # sat/vB
    except Exception:
        return fallback

def serialize_tx(version: int, inputs: List[bytes], outputs: List[bytes], locktime: int) -> bytes:
    return version.to_bytes(4, "little") + varint(len(inputs)) + b"".join(inputs) + varint(len(outputs)) + b"".join(outputs) + locktime.to_bytes(4, "little")

def serialize_input(prev_txid_hex: str, vout: int, script_sig: bytes, sequence: int = 0xFFFFFFFF) -> bytes:
    prev = bytes.fromhex(prev_txid_hex)[::-1]
    return prev + vout.to_bytes(4, "little") + varint(len(script_sig)) + script_sig + sequence.to_bytes(4, "little")

def serialize_output(value_sats: int, script_pubkey: bytes) -> bytes:
    return value_sats.to_bytes(8, "little") + varint(len(script_pubkey)) + script_pubkey

def sighash_all_legacy(tx_version: int, utxos: List[UTXO], script_codes: List[bytes], outputs: List[bytes], locktime: int, input_index: int) -> bytes:
    # Legacy sighash: for each input, scriptSig empty except current input uses scriptCode
    ins = []
    for i, u in enumerate(utxos):
        sc = script_codes[i] if i == input_index else b""
        ins.append(serialize_input(u.txid, u.vout, sc))
    preimage = serialize_tx(tx_version, ins, outputs, locktime) + SIGHASH_ALL.to_bytes(4, "little")
    return dsha256(preimage)

def der_sig_low_s(privkey32: bytes, sighash: bytes) -> bytes:
    sk = SigningKey.from_string(privkey32, curve=SECP256k1)
    n = SECP256k1.order
    sig = sk.sign_digest_deterministic(
        sighash,
        hashfunc=hashlib.sha256,
        sigencode=util.sigencode_string,
    )
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if s > n // 2:
        s = n - s
    der = util.sigencode_der(r, s, n)
    return der + bytes([SIGHASH_ALL])

def build_scriptsig_multisig(sig1: bytes, sig2: bytes, redeem: bytes) -> bytes:
    # scriptSig: OP_0 <sig1> <sig2> <redeem>
    return b"\x00" + pushdata(sig1) + pushdata(sig2) + pushdata(redeem)

def estimate_vbytes(n_in: int, redeem_len: int) -> int:
    # rough legacy estimate for 2-of-3 P2SH multisig
    # per input approx: 32+4+1 + (OP_0 + sig + sig + redeem pushes) + 4
    # sigs around 73 each DER+hashtype, redeem ~105 bytes
    per_in = 32+4+1 + (1 + (1+74) + (1+74) + (1+redeem_len)) + 4
    base = 4 + 1 + 1 + 4  # version + varints + locktime (approx)
    out = 8 + 1 + 25      # one P2PKH output ~34 bytes
    return base + n_in * per_in + out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--network", choices=["regtest", "testnet", "signet"], default="regtest")
    ap.add_argument("--p2sh", required=True, help="Source P2SH address")
    ap.add_argument("--to", required=True, help="Destination P2PKH address")
    ap.add_argument("--priv1", required=True, help="WIF private key 1 (testnet/regtest/signet)")
    ap.add_argument("--priv2", required=True, help="WIF private key 2 (testnet/regtest/signet)")
    ap.add_argument("--pub3", required=True, help="3rd compressed pubkey hex (02/03...)")

    ap.add_argument("--rpchost", default="127.0.0.1")
    ap.add_argument("--rpcport", type=int, default=None)
    ap.add_argument("--cookie", default=None, help="Path to .cookie (optional; default from APPDATA)")
    ap.add_argument("--fallback-fee", type=int, default=2, help="sat/vB if estimatesmartfee fails")
    args = ap.parse_args()

    if not HEX_PUB_RE.match(args.pub3.strip()):
        raise SystemExit("ERROR: pub3 must be compressed hex (66 chars, starts 02/03).")

    if args.rpcport is None:
        args.rpcport = {"regtest": 18443, "testnet": 18332, "signet": 38332}[args.network]

    cookie = args.cookie or default_cookie_path(args.network)
    rpc = BitcoinRPC(args.rpchost, args.rpcport, cookie)

    # keys
    priv1_32, _ = wif_to_privkey(args.priv1)
    priv2_32, _ = wif_to_privkey(args.priv2)
    pub1 = compress_pubkey_from_priv(priv1_32)
    pub2 = compress_pubkey_from_priv(priv2_32)
    pub3 = bytes.fromhex(args.pub3.strip().lower())

    # IMPORTANT: order must match how address was created
    pubkeys = [pub1, pub2, pub3]
    redeem = redeem_script_2of3(pubkeys)

    computed_p2sh = p2sh_address_from_redeem(redeem)
    if computed_p2sh != args.p2sh:
        raise SystemExit(
            "ERROR: P2SH address mismatch.\n"
            f"  Provided: {args.p2sh}\n"
            f"  Computed: {computed_p2sh}\n"
            "This means pubkey order differs from when the address was created."
        )

    utxos = scan_utxos(rpc, args.p2sh)
    if not utxos:
        print("No UTXOs found for:", args.p2sh)
        return

    total_in = sum(u.amount_sats for u in utxos)

    feerate = estimate_feerate_sat_vb(rpc, args.fallback_fee)
    est_vb = estimate_vbytes(len(utxos), len(redeem))
    fee = feerate * est_vb
    send_value = total_in - fee
    if send_value <= 0:
        raise SystemExit(f"ERROR: not enough funds. total={total_in} fee={fee}")

    # outputs
    script_pubkey = p2pkh_scriptpubkey_from_address(args.to)
    outputs = [serialize_output(send_value, script_pubkey)]

    # UNSIGNED tx (empty scriptsigs)
    version = 1
    locktime = 0
    unsigned_inputs = [serialize_input(u.txid, u.vout, b"") for u in utxos]
    unsigned_tx = serialize_tx(version, unsigned_inputs, outputs, locktime)
    print("Unsigned raw tx:", unsigned_tx.hex())

    # SIGN each input: sighash uses redeem as scriptCode for P2SH
    signed_inputs = []
    for i, u in enumerate(utxos):
        # scriptCode list: redeem for all inputs (only the one being signed is used)
        script_codes = [redeem] * len(utxos)
        sigh = sighash_all_legacy(version, utxos, script_codes, outputs, locktime, i)

        sig1 = der_sig_low_s(priv1_32, sigh)
        sig2 = der_sig_low_s(priv2_32, sigh)

        # scriptSig: OP_0 <sig1> <sig2> <redeem>
        ss = build_scriptsig_multisig(sig1, sig2, redeem)
        signed_inputs.append(serialize_input(u.txid, u.vout, ss))

    signed_tx = serialize_tx(version, signed_inputs, outputs, locktime)
    signed_hex = signed_tx.hex()
    txid = dsha256(signed_tx)[::-1].hex()

    print("Signed raw tx:", signed_hex)
    print("TxID:", txid)

    # verify policy acceptance
    verdict = rpc.call("testmempoolaccept", [[signed_hex]])
    print("testmempoolaccept:", verdict)
    if not verdict or not verdict[0].get("allowed", False):
        raise SystemExit("Transaction NOT accepted. Not broadcasting.")

    # broadcast
    broadcast_txid = rpc.call("sendrawtransaction", [signed_hex])
    print("Broadcasted txid:", broadcast_txid)

if __name__ == "__main__":
    main()


