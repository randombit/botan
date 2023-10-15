/*
* Ed25519
* (C) 2017 Ribose Inc
*
* Based on the public domain code from SUPERCOP ref10 by
* Peter Schwabe, Daniel J. Bernstein, Niels Duif, Tanja Lange, Bo-Yin Yang
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ed25519.h>

#include <botan/rng.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/ed25519_internal.h>
#include <botan/internal/sha2_64.h>

namespace Botan {

void ed25519_gen_keypair(uint8_t* pk, uint8_t* sk, const uint8_t seed[32]) {
   uint8_t az[64];

   SHA_512 sha;
   sha.update(seed, 32);
   sha.final(az);
   az[0] &= 248;
   az[31] &= 63;
   az[31] |= 64;

   ge_scalarmult_base(pk, az);

   // todo copy_mem
   copy_mem(sk, seed, 32);
   copy_mem(sk + 32, pk, 32);
}

void ed25519_sign(uint8_t sig[64],
                  const uint8_t m[],
                  size_t mlen,
                  const uint8_t sk[64],
                  const uint8_t domain_sep[],
                  size_t domain_sep_len) {
   uint8_t az[64];
   uint8_t nonce[64];
   uint8_t hram[64];

   SHA_512 sha;

   sha.update(sk, 32);
   sha.final(az);
   az[0] &= 248;
   az[31] &= 63;
   az[31] |= 64;

   sha.update(domain_sep, domain_sep_len);
   sha.update(az + 32, 32);
   sha.update(m, mlen);
   sha.final(nonce);

   sc_reduce(nonce);
   ge_scalarmult_base(sig, nonce);

   sha.update(domain_sep, domain_sep_len);
   sha.update(sig, 32);
   sha.update(sk + 32, 32);
   sha.update(m, mlen);
   sha.final(hram);

   sc_reduce(hram);
   sc_muladd(sig + 32, hram, az, nonce);
}

bool ed25519_verify(const uint8_t* m,
                    size_t mlen,
                    const uint8_t sig[64],
                    const uint8_t* pk,
                    const uint8_t domain_sep[],
                    size_t domain_sep_len) {
   uint8_t h[64];
   uint8_t rcheck[32];
   ge_p3 A;
   SHA_512 sha;

   if(sig[63] & 224) {
      return false;
   }
   if(ge_frombytes_negate_vartime(&A, pk) != 0) {
      return false;
   }

   const uint64_t CURVE25519_ORDER[4] = {
      0x1000000000000000,
      0x0000000000000000,
      0x14def9dea2f79cd6,
      0x5812631a5cf5d3ed,
   };

   const uint64_t s[4] = {load_le<uint64_t>(sig + 32, 3),
                          load_le<uint64_t>(sig + 32, 2),
                          load_le<uint64_t>(sig + 32, 1),
                          load_le<uint64_t>(sig + 32, 0)};

   // RFC 8032 adds the requirement that we verify that s < order in
   // the signature; this did not exist in the original Ed25519 spec.
   for(size_t i = 0; i != 4; ++i) {
      if(s[i] > CURVE25519_ORDER[i]) {
         return false;
      }
      if(s[i] < CURVE25519_ORDER[i]) {
         break;
      }
      if(i == 3) {  // here s == order
         return false;
      }
   }

   sha.update(domain_sep, domain_sep_len);
   sha.update(sig, 32);
   sha.update(pk, 32);
   sha.update(m, mlen);
   sha.final(h);
   sc_reduce(h);

   ge_double_scalarmult_vartime(rcheck, h, &A, sig + 32);

   return CT::is_equal(rcheck, sig, 32).as_bool();
}

}  // namespace Botan
