/*
* RFC 6979 Deterministic Nonce Generator
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/rfc6979.h>

#include <botan/hmac_drbg.h>
#include <botan/mac.h>
#include <botan/internal/fmt.h>

namespace Botan {

RFC6979_Nonce_Generator::RFC6979_Nonce_Generator(std::string_view hash, const BigInt& order, const BigInt& x) :
      m_order(order),
      m_qlen(m_order.bits()),
      m_rlen(m_qlen / 8 + (m_qlen % 8 ? 1 : 0)),
      m_rng_in(m_rlen * 2),
      m_rng_out(m_rlen) {
   m_hmac_drbg = std::make_unique<HMAC_DRBG>(MessageAuthenticationCode::create_or_throw(fmt("HMAC({})", hash)));

   x.serialize_to(std::span{m_rng_in}.first(m_rlen));
}

RFC6979_Nonce_Generator::~RFC6979_Nonce_Generator() = default;

const BigInt& RFC6979_Nonce_Generator::nonce_for(const BigInt& m) {
   m.serialize_to(std::span{m_rng_in}.subspan(m_rlen));
   m_hmac_drbg->clear();
   m_hmac_drbg->initialize_with(m_rng_in.data(), m_rng_in.size());

   do {
      m_hmac_drbg->randomize(m_rng_out.data(), m_rng_out.size());
      m_k._assign_from_bytes(m_rng_out);
      m_k >>= (8 * m_rlen - m_qlen);
   } while(m_k == 0 || m_k >= m_order);

   return m_k;
}

BigInt generate_rfc6979_nonce(const BigInt& x, const BigInt& q, const BigInt& h, std::string_view hash) {
   RFC6979_Nonce_Generator gen(hash, q, x);
   BigInt k = gen.nonce_for(h);
   return k;
}

}  // namespace Botan
