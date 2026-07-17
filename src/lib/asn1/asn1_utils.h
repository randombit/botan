/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASN1_UTILS_H_
#define BOTAN_ASN1_UTILS_H_

#include <botan/asn1_obj.h>
#include <span>
#include <vector>

namespace Botan {

class BigInt;

}

namespace Botan::ASN1 {

/**
* Return the contents octets of the DER encoding of the INTEGER @p n:
* big-endian two's complement, minimal length. Zero encodes as a single
* 0x00 octet.
*/
std::vector<uint8_t> integer_contents(const BigInt& n);

/**
* Decode the contents octets of a BER INTEGER (big-endian two's
* complement). Redundant leading octets are accepted; an empty input is
* rejected.
*/
BigInt integer_from_contents(std::span<const uint8_t> contents);

/*
* Return true if the bytes are exactly one DER-encoded value of the expected
* type and class, that is a TLV whose tag plus length header plus contents
* span the entire buffer with no trailing data. The contents themselves are
* not otherwise validated.
*/
bool is_single_der_object(std::span<const uint8_t> bytes, ASN1_Type expected_type, ASN1_Class expected_class);

/**
* Return true if the bytes are exactly one DER-encoded SEQUENCE, that is a
* SEQUENCE whose tag plus length header plus contents span the entire buffer
* with no trailing data. The contents themselves are not otherwise validated.
*/
bool is_der_sequence_header(std::span<const uint8_t> bytes);

}  // namespace Botan::ASN1

#endif
