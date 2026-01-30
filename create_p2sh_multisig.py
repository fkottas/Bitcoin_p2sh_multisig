"""
create_p2sh_multisig.py

Creates a legacy P2SH address that locks funds with a 2-of-3 MULTISIG redeem script.

Redeem script (2-of-3):
    OP_2 <PubKey1> <PubKey2> <PubKey3> OP_3 OP_CHECKMULTISIG

P2SH scriptPubKey (locking script on chain):
    OP_HASH160 <Hash160(redeemScript)> OP_EQUAL

Notes:
- This script expects *compressed* public keys (33 bytes) in hex form:
  starts with 02 or 03 and length is 66 hex chars.
- The order of pubkeys matters because it changes the redeem script,
  which changes the P2SH address. You MUST use the same order when spending.
- Prefix 0xC4 is the P2SH version byte for testnet/regtest/signet.
"""
import argparse, hashlib, re, base58

# Compressed pubkey: 33 bytes => 66 hex chars, prefix 02/03
HEX_PUB_RE = re.compile(r"^(02|03)[0-9a-fA-F]{64}$")

def sha256(b: bytes) -> bytes: return hashlib.sha256(b).digest()
def ripemd160(b: bytes) -> bytes: return hashlib.new("ripemd160", b).digest()
def h160(b: bytes) -> bytes: return ripemd160(sha256(b)) #HASH160 = RIPEMD160(SHA256(x))

def build_redeem_script_2of3(pubs_hex):
    """
Manually construct the redeem script using Bitcoin Script opcodes.

Format:
    OP_2 <33B pub1> <33B pub2> <33B pub3> OP_3 OP_CHECKMULTISIG

Opcodes used:
    OP_2           = 0x52
    OP_3           = 0x53
    OP_CHECKMULTISIG = 0xAE
"""
    out = bytearray()
    out.append(0x52)  # OP_2
    for pk in pubs_hex:
        pkb = bytes.fromhex(pk)
        out.append(0x21)  # push 33 bytes
        out.extend(pkb)
    out.append(0x53)  # OP_3
    out.append(0xAE)  # OP_CHECKMULTISIG
    return bytes(out)

def p2sh_address_from_redeem(redeem: bytes) -> str:
    """
Compute the P2SH Base58Check address:

payload = <version_byte> + HASH160(redeem_script)

For regtest/testnet/signet P2SH version byte = 0xC4.
Base58Check encoding = base58(payload + checksum),
checksum = first 4 bytes of double-SHA256(payload).
"""
    payload = bytes([0xC4]) + h160(redeem)  # P2SH prefix for regtest/testnet/signet
    chk = sha256(sha256(payload))[:4]
    return base58.b58encode(payload + chk).decode()

def main():
    ap = argparse.ArgumentParser(
        description="Create a regtest/testnet/signet P2SH address for a 2-of-3 multisig redeem script."
    )
    ap.add_argument("--pub1", required=True, help="Compressed pubkey hex (02/03...)")
    ap.add_argument("--pub2", required=True, help="Compressed pubkey hex (02/03...)")
    ap.add_argument("--pub3", required=True, help="Compressed pubkey hex (02/03...)")
    args = ap.parse_args()

    # Normalize to lowercase/no spaces
    pubs = [args.pub1.strip().lower(), args.pub2.strip().lower(), args.pub3.strip().lower()]

    # Validate inputs
    for i, p in enumerate(pubs, start=1):
        if not HEX_PUB_RE.match(p):
            raise SystemExit(
                f"ERROR: pub{i} is not a compressed pubkey.\n"
                f"Got: {p}\n"
                "Expected: 66 hex chars starting with 02 or 03."
            )

    redeem = build_redeem_script_2of3(pubs)
    p2sh_addr = p2sh_address_from_redeem(redeem)

    print("Redeem script hex:", redeem.hex())
    print("P2SH address:", p2sh_addr)
    print("IMPORTANT: Keep pubkey order the same when spending!")


if __name__ == "__main__":
    main()



