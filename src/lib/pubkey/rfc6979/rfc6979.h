/*
* RFC 6979 Deterministic Nonce Generator
* (C) 2014,2015,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_RFC6979_GENERATOR_H_
#define BOTAN_RFC6979_GENERATOR_H_

#include <botan/bigint.h>
#include <memory>
#include <span>
#include <string_view>

#if defined(BOTAN_HAS_ECC_GROUP)
   #include <botan/ec_scalar.h>
#endif

namespace Botan {

class HMAC_DRBG;

class BOTAN_TEST_API RFC6979_Nonce_Generator final {
   public:
      RFC6979_Nonce_Generator(std::string_view hash, size_t order_bits, const BigInt& x);

      BigInt nonce_for(const BigInt& group_order, const BigInt& m);

#if defined(BOTAN_HAS_ECC_GROUP)
      RFC6979_Nonce_Generator(std::string_view hash, size_t order_bits, const EC_Scalar& scalar);

      EC_Scalar nonce_for(const EC_Group& group, const EC_Scalar& m);
#endif

      ~RFC6979_Nonce_Generator();

   private:
      size_t m_qlen;
      size_t m_rlen;
      std::unique_ptr<HMAC_DRBG> m_hmac_drbg;
      secure_vector<uint8_t> m_rng_in;
      secure_vector<uint8_t> m_rng_out;
};

/**
* @param x the secret (EC)DSA key
* @param q the group order
* @param h the message hash already reduced mod q
* @param hash the hash function used to generate h
*/
inline BigInt generate_rfc6979_nonce(const BigInt& x, const BigInt& q, const BigInt& h, std::string_view hash) {
   RFC6979_Nonce_Generator gen(hash, q.bits(), x);
   return gen.nonce_for(q, h);
}

}  // namespace Botan

#endif
