/*
* RFC 6979 Deterministic Nonce Generator
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rfc6979.h>
#include <botan/hmac_drbg.h>
#include <botan/scan_name.h>
#include <botan/lookup.h>

namespace Botan {

std::string hash_for_deterministic_signature(const std::string& emsa)
   {
   SCAN_Name emsa_name(emsa);

   if(emsa_name.arg_count() > 0)
      {
      const std::string pos_hash = emsa_name.arg(0);
      return pos_hash;
      }

   return "SHA-512"; // safe default if nothing we understand
   }

RFC6979_Nonce_Generator::RFC6979_Nonce_Generator(const std::string& hash,
                                                 const BigInt& order,
                                                 const BigInt& x) :
   m_order(order),
   m_qlen(m_order.bits()),
   m_rlen(m_qlen / 8 + (m_qlen % 8 ? 1 : 0)),
   m_hmac_drbg(new HMAC_DRBG(make_message_auth("HMAC(" + hash + ")").release())),
   m_rng_in(m_rlen * 2),
   m_rng_out(m_rlen)
   {
   BigInt::encode_1363(&m_rng_in[0], m_rlen, x);
   }

const BigInt& RFC6979_Nonce_Generator::nonce_for(const BigInt& m)
   {
   BigInt::encode_1363(&m_rng_in[m_rlen], m_rlen, m);
   m_hmac_drbg->clear();
   m_hmac_drbg->add_entropy(&m_rng_in[0], m_rng_in.size());

   do
      {
      m_hmac_drbg->randomize(&m_rng_out[0], m_rng_out.size());
      m_k.binary_decode(&m_rng_out[0], m_rng_out.size());
      m_k >>= (8*m_rlen - m_qlen);
      }
   while(m_k == 0 || m_k >= m_order);

   return m_k;
   }

BigInt generate_rfc6979_nonce(const BigInt& x,
                              const BigInt& q,
                              const BigInt& h,
                              const std::string& hash)
   {
   RFC6979_Nonce_Generator gen(hash, q, x);
   BigInt k = gen.nonce_for(h);
   return k;
   }

}
