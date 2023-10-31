/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sodium.h>

#include <botan/mem_ops.h>
#include <botan/secmem.h>

namespace Botan {

int Sodium::crypto_box_curve25519xsalsa20poly1305_seed_keypair(uint8_t pk[32], uint8_t sk[32], const uint8_t seed[32]) {
   secure_vector<uint8_t> digest(64);
   crypto_hash_sha512(digest.data(), seed, 32);
   copy_mem(sk, digest.data(), 32);
   return crypto_scalarmult_curve25519_base(pk, sk);
}

int Sodium::crypto_box_curve25519xsalsa20poly1305_keypair(uint8_t pk[32], uint8_t sk[32]) {
   randombytes_buf(sk, 32);
   return crypto_scalarmult_curve25519_base(pk, sk);
}

int Sodium::crypto_box_curve25519xsalsa20poly1305_beforenm(uint8_t key[], const uint8_t pk[32], const uint8_t sk[32]) {
   const uint8_t zero[16] = {0};
   secure_vector<uint8_t> shared(32);

   if(crypto_scalarmult_curve25519(shared.data(), sk, pk) != 0) {
      return -1;
   }

   return crypto_core_hsalsa20(key, zero, shared.data(), nullptr);
}

int Sodium::crypto_box_curve25519xsalsa20poly1305(uint8_t ctext[],
                                                  const uint8_t ptext[],
                                                  size_t ptext_len,
                                                  const uint8_t nonce[],
                                                  const uint8_t pk[32],
                                                  const uint8_t sk[32]) {
   secure_vector<uint8_t> shared(32);

   if(crypto_box_curve25519xsalsa20poly1305_beforenm(shared.data(), pk, sk) != 0) {
      return -1;
   }

   return crypto_box_curve25519xsalsa20poly1305_afternm(ctext, ptext, ptext_len, nonce, shared.data());
}

int Sodium::crypto_box_curve25519xsalsa20poly1305_open(uint8_t ptext[],
                                                       const uint8_t ctext[],
                                                       size_t ctext_len,
                                                       const uint8_t nonce[],
                                                       const uint8_t pk[32],
                                                       const uint8_t sk[32]) {
   secure_vector<uint8_t> shared(32);

   if(crypto_box_curve25519xsalsa20poly1305_beforenm(shared.data(), pk, sk) != 0) {
      return -1;
   }

   return crypto_box_curve25519xsalsa20poly1305_open_afternm(ptext, ctext, ctext_len, nonce, shared.data());
}

int Sodium::crypto_box_detached(uint8_t ctext[],
                                uint8_t mac[],
                                const uint8_t ptext[],
                                size_t ptext_len,
                                const uint8_t nonce[],
                                const uint8_t pk[32],
                                const uint8_t sk[32]) {
   secure_vector<uint8_t> shared(32);

   if(crypto_box_beforenm(shared.data(), pk, sk) != 0) {
      return -1;
   }

   return crypto_box_detached_afternm(ctext, mac, ptext, ptext_len, nonce, shared.data());
}

int Sodium::crypto_box_open_detached(uint8_t ptext[],
                                     const uint8_t ctext[],
                                     const uint8_t mac[],
                                     size_t ctext_len,
                                     const uint8_t nonce[],
                                     const uint8_t pk[32],
                                     const uint8_t sk[32]) {
   secure_vector<uint8_t> shared(32);

   if(crypto_box_beforenm(shared.data(), pk, sk) != 0) {
      return -1;
   }

   return crypto_box_open_detached_afternm(ptext, ctext, mac, ctext_len, nonce, shared.data());
}

}  // namespace Botan
