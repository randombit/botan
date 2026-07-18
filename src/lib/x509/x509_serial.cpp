/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkix_types.h>

#include <botan/assert.h>
#include <botan/ber_dec.h>
#include <botan/bigint.h>
#include <botan/der_enc.h>
#include <botan/hex.h>
#include <botan/rng.h>
#include <botan/internal/asn1_utils.h>
#include <cstring>

namespace Botan {

X509_Serial_Number::X509_Serial_Number(const BigInt& value) : m_contents(ASN1::integer_contents(value)) {}

X509_Serial_Number X509_Serial_Number::from_bytes(std::span<const uint8_t> bytes) {
   while(!bytes.empty() && bytes.front() == 0x00) {
      bytes = bytes.subspan(1);
   }

   if(bytes.empty()) {
      return X509_Serial_Number();  // zero
   }

   X509_Serial_Number sn;
   sn.m_contents.clear();
   if((bytes.front() & 0x80) == 0x80) {
      sn.m_contents.push_back(0x00);
   }
   sn.m_contents.insert(sn.m_contents.end(), bytes.begin(), bytes.end());
   return sn;
}

X509_Serial_Number X509_Serial_Number::from_der_contents(std::span<const uint8_t> contents) {
   if(contents.empty()) {
      throw Decoding_Error("Serial number INTEGER encoding has no contents octets");
   }

   // Normalize away redundant leading octets a BER encoding may carry
   size_t offset = 0;
   while(offset + 1 < contents.size() && ((contents[offset] == 0x00 && (contents[offset + 1] & 0x80) == 0x00) ||
                                          (contents[offset] == 0xFF && (contents[offset + 1] & 0x80) == 0x80))) {
      offset += 1;
   }

   X509_Serial_Number sn;
   sn.m_contents.assign(contents.begin() + offset, contents.end());
   return sn;
}

X509_Serial_Number X509_Serial_Number::random(RandomNumberGenerator& rng) {
   std::array<uint8_t, 16> bytes{};
   rng.randomize(bytes);
   bytes[0] &= 0x7F;  // clear bit 128
   bytes[0] |= 0x40;  // set bit 127
   return X509_Serial_Number::from_bytes(bytes);
}

bool X509_Serial_Number::is_negative() const {
   BOTAN_STATE_CHECK(!m_contents.empty());
   return (m_contents[0] & 0x80) == 0x80;
}

bool X509_Serial_Number::is_zero() const {
   return m_contents.size() == 1 && m_contents[0] == 0x00;
}

std::vector<uint8_t> X509_Serial_Number::magnitude() const {
   BOTAN_STATE_CHECK(!m_contents.empty());

   if(is_zero()) {
      return {};
   } else if(is_negative()) {
      return to_bigint().serialize();
   } else if(m_contents[0] == 0x00) {
      // Positive value whose leading magnitude bit is set; skip the sign octet
      return {m_contents.begin() + 1, m_contents.end()};
   } else {
      return m_contents;
   }
}

BigInt X509_Serial_Number::to_bigint() const {
   BOTAN_STATE_CHECK(!m_contents.empty());
   return ASN1::integer_from_contents(m_contents);
}

std::string X509_Serial_Number::to_string() const {
   BOTAN_STATE_CHECK(!m_contents.empty());
   if(is_zero()) {
      return "00";
   }
   const std::string hex = hex_encode(magnitude());
   return is_negative() ? "-" + hex : hex;
}

void X509_Serial_Number::encode_into(DER_Encoder& to) const {
   BOTAN_STATE_CHECK(!m_contents.empty());
   to.add_object(ASN1_Type::Integer, ASN1_Class::Universal, m_contents);
}

void X509_Serial_Number::decode_from(BER_Decoder& from) {
   // Decode via BigInt so the decoder's limits apply, in particular the
   // rejection of non-minimal INTEGER encodings in DER mode
   BigInt value;
   from.decode(value);
   *this = X509_Serial_Number(value);
}

std::strong_ordering X509_Serial_Number::operator<=>(const X509_Serial_Number& other) const {
   BOTAN_STATE_CHECK(!m_contents.empty());

   const bool neg = is_negative();

   if(neg != other.is_negative()) {
      return neg ? std::strong_ordering::less : std::strong_ordering::greater;
   }

   // Same sign: for positive values the longer encoding is the larger value,
   // for negative values the longer encoding is the smaller (more negative)
   if(m_contents.size() != other.m_contents.size()) {
      const bool shorter = m_contents.size() < other.m_contents.size();
      return (shorter != neg) ? std::strong_ordering::less : std::strong_ordering::greater;
   }

   /*
   * When comparing two values of the same sign in two's complement
   * encoding, the lexicographic ordering is correct for both signs,
   * for instance -2 (0xFE) is less than -1 (0xFF)
   */
   const int cmp = std::memcmp(m_contents.data(), other.m_contents.data(), m_contents.size());
   if(cmp < 0) {
      return std::strong_ordering::less;
   } else if(cmp > 0) {
      return std::strong_ordering::greater;
   } else {
      return std::strong_ordering::equal;
   }
}

}  // namespace Botan
