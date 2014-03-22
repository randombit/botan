/*
* RFC 6979 Deterministic Nonce Generator
* (C) 2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/rfc6979.h>
#include <botan/hmac_drbg.h>
#include <botan/libstate.h>

#include <botan/hex.h>
#include <iostream>

namespace Botan {

BigInt generate_rfc6979_nonce(const BigInt& x,
                              const BigInt& q,
                              const BigInt& h,
                              const std::string& hash)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();

   HMAC_DRBG rng(af.make_mac("HMAC(" + hash + ")"), nullptr);

   const size_t qlen = q.bits();
   const size_t rlen = qlen / 8 + (qlen % 8 ? 1 : 0);

   secure_vector<byte> input = BigInt::encode_1363(x, rlen);

   input += BigInt::encode_1363(h, rlen);

   rng.add_entropy(&input[0], input.size());

   BigInt k;

   secure_vector<byte> kbits(rlen);

   while(k == 0 || k >= q)
      {
      rng.randomize(&kbits[0], kbits.size());
      k = BigInt::decode(kbits) >> (8*rlen - qlen);
      }

   return k;
   }

}
