/*
* RFC 6979 Deterministic Nonce Generator
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rfc6979.h>
#include <botan/hmac_drbg.h>
#include <botan/scan_name.h>
#include <botan/internal/algo_registry.h>

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

BigInt generate_rfc6979_nonce(const BigInt& x,
                              const BigInt& q,
                              const BigInt& h,
                              const std::string& hash)
   {
   auto& macs = Algo_Registry<MessageAuthenticationCode>::global_registry();
   HMAC_DRBG rng(macs.make("HMAC(" + hash + ")"), nullptr);

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
