#!/usr/bin/env python3

"""
Generate the XMSS key encoding test data in src/tests/data/x509/xmss/

The files exercise the OID based selection of the key encoding in
XMSS_PublicKey and XMSS_PrivateKey (see src/tests/test_xmss.cpp):

  xmss_rfc9802_pubkey.pem                 RFC 9802 OID, raw public key (valid)
  xmss_rfc9802_pubkey_wrapped_invalid.pem RFC 9802 OID, OCTET STRING wrapped key (invalid)
  xmss_legacy_pubkey_raw_invalid.pem      draft-vangeest OID, raw public key (invalid)
  xmss_unknown_oid_pubkey_invalid.pem     pre-2.13 private arc OID, raw public key (invalid)
  xmss_rfc9802_privkey.pem                PKCS #8, RFC 9802 OID, OCTET STRING payload (valid)
  xmss_rfc9802_privkey_raw_invalid.pem    PKCS #8, RFC 9802 OID, raw payload (invalid)
  xmss_legacy_privkey.pem                 PKCS #8, draft-vangeest OID, OCTET STRING payload
                                          as written by Botan 2.13 to 3.13 (valid)

All files are derived from one XMSS-SHA2_10_256 key pair. The key is read from
xmss_rfc9802_privkey.pem if that file exists, so re-running the script
reproduces the other files; otherwise a fresh key is generated.

Run from the repository root with the Python binding on the path, e.g.
  LD_LIBRARY_PATH=. PYTHONPATH=src/python python3 src/scripts/dev_tools/gen_xmss_encoding_testdata.py

(C) 2026 Falko Strenzke - MTG AG

Botan is released under the Simplified BSD License (see license.txt)
"""

import base64
import os
import sys

import botan3 as botan

OID_RFC9802 = "1.3.6.1.5.5.7.6.34"
OID_DRAFT_VANGEEST = "0.4.0.127.0.15.1.1.13.0"
OID_BOTAN_PRE_2_13 = "1.3.6.1.4.1.25258.1.8"

# --- minimal DER helpers ---------------------------------------------------

def der_len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body

def der_tlv(tag, content):
    return bytes([tag]) + der_len(len(content)) + content

def der_read_tlv(data, pos=0):
    """Return (tag, content, next_pos) of the TLV starting at pos"""
    tag = data[pos]
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    return tag, data[pos:pos + length], pos + length

def der_oid(dotted):
    arcs = [int(a) for a in dotted.split(".")]
    out = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        enc = bytearray([arc & 0x7F])
        arc >>= 7
        while arc:
            enc.insert(0, 0x80 | (arc & 0x7F))
            arc >>= 7
        out += enc
    return der_tlv(0x06, bytes(out))

def alg_id(dotted):
    # AlgorithmIdentifier with absent parameters, as XMSS uses
    return der_tlv(0x30, der_oid(dotted))

def spki(oid, key_bits):
    return der_tlv(0x30, alg_id(oid) + der_tlv(0x03, b"\x00" + key_bits))

def pkcs8(oid, private_key_payload):
    return der_tlv(0x30, der_tlv(0x02, b"\x00") + alg_id(oid) + der_tlv(0x04, private_key_payload))

def pem(label, der):
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, "\n".join(lines), label)

def unpem(text):
    body = "".join(line for line in text.splitlines() if not line.startswith("-----"))
    return base64.b64decode(body)

# --- extract the raw keys from the library's encodings ---------------------

def raw_public_key_from_spki(der):
    _, seq, _ = der_read_tlv(der)
    _, _, after_alg = der_read_tlv(seq)
    tag, bits, _ = der_read_tlv(seq, after_alg)
    assert tag == 0x03 and bits[0] == 0
    return bits[1:]

def raw_private_key_from_pkcs8(der):
    _, seq, _ = der_read_tlv(der)
    _, _, pos = der_read_tlv(seq)         # version
    _, _, pos = der_read_tlv(seq, pos)    # AlgorithmIdentifier
    tag, payload, _ = der_read_tlv(seq, pos)
    assert tag == 0x04
    tag, raw, _ = der_read_tlv(payload)   # the OCTET STRING the library wraps the raw key in
    assert tag == 0x04
    return raw

def main(argv):
    out_dir = argv[1] if len(argv) > 1 else "src/tests/data/x509/xmss"
    priv_file = os.path.join(out_dir, "xmss_rfc9802_privkey.pem")

    if os.path.exists(priv_file):
        with open(priv_file, encoding="ascii") as f:
            sk = botan.PrivateKey.load(unpem(f.read()))
    else:
        sk = botan.PrivateKey.create("XMSS", "XMSS-SHA2_10_256", botan.RandomNumberGenerator("system"))

    sk_der = sk.to_der()
    pk_der = sk.get_public_key().to_der()

    raw_pk = raw_public_key_from_spki(pk_der)
    raw_sk = raw_private_key_from_pkcs8(sk_der)
    assert raw_pk[:4] == raw_sk[:4] == b"\x00\x00\x00\x01"  # XMSS-SHA2_10_256

    files = {
        "xmss_rfc9802_pubkey.pem": ("PUBLIC KEY", spki(OID_RFC9802, raw_pk)),
        "xmss_rfc9802_pubkey_wrapped_invalid.pem": ("PUBLIC KEY", spki(OID_RFC9802, der_tlv(0x04, raw_pk))),
        "xmss_legacy_pubkey_raw_invalid.pem": ("PUBLIC KEY", spki(OID_DRAFT_VANGEEST, raw_pk)),
        "xmss_unknown_oid_pubkey_invalid.pem": ("PUBLIC KEY", spki(OID_BOTAN_PRE_2_13, raw_pk)),
        "xmss_rfc9802_privkey.pem": ("PRIVATE KEY", pkcs8(OID_RFC9802, der_tlv(0x04, raw_sk))),
        "xmss_rfc9802_privkey_raw_invalid.pem": ("PRIVATE KEY", pkcs8(OID_RFC9802, raw_sk)),
        "xmss_legacy_privkey.pem": ("PRIVATE KEY", pkcs8(OID_DRAFT_VANGEEST, der_tlv(0x04, raw_sk))),
    }

    # The library's own encodings must match the ones constructed here
    assert files["xmss_rfc9802_pubkey.pem"][1] == pk_der
    assert files["xmss_rfc9802_privkey.pem"][1] == sk_der

    os.makedirs(out_dir, exist_ok=True)
    for name, (label, der) in files.items():
        with open(os.path.join(out_dir, name), "w", encoding="ascii") as f:
            f.write(pem(label, der))
        print("wrote", name)

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
