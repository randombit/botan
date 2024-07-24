/*
* RFC 6979 Deterministic Nonce Generator
* (C) 2014,2015,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/rfc6979.h>

#include <botan/hmac_drbg.h>
#include <botan/mac.h>
#include <botan/internal/fmt.h>

namespace Botan {

RFC6979_Nonce_Generator::~RFC6979_Nonce_Generator() = default;

RFC6979_Nonce_Generator::RFC6979_Nonce_Generator(std::string_view hash, size_t order_bits, const BigInt& x) :
      m_qlen(order_bits), m_rlen((m_qlen + 7) / 8), m_rng_in(m_rlen * 2), m_rng_out(m_rlen) {
   m_hmac_drbg = std::make_unique<HMAC_DRBG>(MessageAuthenticationCode::create_or_throw(fmt("HMAC({})", hash)));

   x.serialize_to(std::span{m_rng_in}.first(m_rlen));
}

BigInt RFC6979_Nonce_Generator::nonce_for(const BigInt& order, const BigInt& m) {
   BOTAN_DEBUG_ASSERT(order.bits() == m_qlen);

   m.serialize_to(std::span{m_rng_in}.last(m_rlen));

   m_hmac_drbg->initialize_with(m_rng_in);

   const size_t shift = 8 * m_rlen - m_qlen;
   BOTAN_ASSERT_NOMSG(shift < 8);

   BigInt k;

   do {
      m_hmac_drbg->randomize(m_rng_out);
      k._assign_from_bytes(m_rng_out);

      if(shift > 0) {
         k >>= shift;
      }
   } while(k == 0 || k >= order);

   return k;
}

#if defined(BOTAN_HAS_ECC_GROUP)
RFC6979_Nonce_Generator::RFC6979_Nonce_Generator(std::string_view hash, size_t order_bits, const EC_Scalar& scalar) :
      m_qlen(order_bits), m_rlen((m_qlen + 7) / 8), m_rng_in(m_rlen * 2), m_rng_out(m_rlen) {
   m_hmac_drbg = std::make_unique<HMAC_DRBG>(MessageAuthenticationCode::create_or_throw(fmt("HMAC({})", hash)));

   scalar.serialize_to(std::span{m_rng_in}.first(m_rlen));
}

EC_Scalar RFC6979_Nonce_Generator::nonce_for(const EC_Group& group, const EC_Scalar& m) {
   m.serialize_to(std::span{m_rng_in}.last(m_rlen));

   m_hmac_drbg->initialize_with(m_rng_in);

   const size_t shift = 8 * m_rlen - m_qlen;
   BOTAN_ASSERT_NOMSG(shift < 8);

   for(;;) {
      m_hmac_drbg->randomize(m_rng_out);

      if(shift > 0) {
         uint8_t carry = 0;
         for(uint8_t& b : m_rng_out) {
            const uint8_t w = b;
            b = (w >> shift) | carry;
            carry = w << (8 - shift);
         }
      }

      if(auto k = EC_Scalar::deserialize(group, m_rng_out)) {
         return *k;
      }
   }
}
#endif

}  // namespace Botan
