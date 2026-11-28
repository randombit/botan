/*
* OctetString
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/symkey.h>

#include <botan/hex.h>
#include <botan/mem_ops.h>
#include <botan/rng.h>
#include <algorithm>

namespace Botan {

/*
* Create an OctetString from RNG output
*/
OctetString::OctetString(RandomNumberGenerator& rng, size_t len) {
   rng.random_vec(m_data, len);
}

/*
* Create an OctetString from a hex string
*/
OctetString::OctetString(std::string_view hex_string) {
   if(!hex_string.empty()) {
      m_data.resize(1 + hex_string.length() / 2);
      m_data.resize(hex_decode(m_data.data(), hex_string));
   }
}

/*
* Create an OctetString from a byte string
*/
OctetString::OctetString(const uint8_t in[], size_t n) {
   m_data.assign(in, in + n);
}

namespace {

uint8_t odd_parity_of(uint8_t x) {
   uint8_t f = x | 0x01;
   f ^= (f >> 4);
   f ^= (f >> 2);
   f ^= (f >> 1);

   return (x & 0xFE) ^ (f & 0x01);
}

}  // namespace

/*
* Set the parity of each key byte to odd
*/
void OctetString::set_odd_parity() {
   for(auto& b : m_data) {
      b = odd_parity_of(b);
   }
}

/*
* Hex encode an OctetString
*/
std::string OctetString::to_string() const {
   return hex_encode(m_data.data(), m_data.size());
}

/*
* XOR Operation for OctetStrings
*/
OctetString& OctetString::operator^=(const OctetString& k) {
   if(&k == this) {
      zeroise(m_data);
      return (*this);
   }
   const auto len = std::min(length(), k.length());
   xor_buf(std::span{m_data}.first(len), std::span{k}.first(len));
   return (*this);
}

/*
* Equality Operation for OctetStrings
*/
bool operator==(const OctetString& s1, const OctetString& s2) {
   return (s1.bits_of() == s2.bits_of());
}

/*
* Inequality Operation for OctetStrings
*/
bool operator!=(const OctetString& s1, const OctetString& s2) {
   return !(s1 == s2);
}

/*
* Append Operation for OctetStrings
*/
OctetString operator+(const OctetString& k1, const OctetString& k2) {
   secure_vector<uint8_t> out;
   out += k1.bits_of();
   out += k2.bits_of();
   return OctetString(out);
}

/*
* XOR Operation for OctetStrings
*/
OctetString operator^(const OctetString& k1, const OctetString& k2) {
   secure_vector<uint8_t> out(std::max(k1.length(), k2.length()));

   copy_mem(std::span{out}.first(k1.length()), k1.bits_of());
   xor_buf(std::span{out}.first(k2.length()), k2.bits_of());
   return OctetString(out);
}

}  // namespace Botan
