/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sodium.h>

#include <botan/ed25519.h>
#include <botan/x25519.h>

namespace Botan {

int Sodium::crypto_scalarmult_curve25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
   curve25519_donna(out, scalar, point);
   return 0;
}

int Sodium::crypto_scalarmult_curve25519_base(uint8_t out[32], const uint8_t scalar[32]) {
   curve25519_basepoint(out, scalar);
   return 0;
}

int Sodium::crypto_sign_ed25519_detached(
   uint8_t sig[], unsigned long long* sig_len, const uint8_t msg[], size_t msg_len, const uint8_t sk[32]) {
   ed25519_sign(sig, msg, msg_len, sk, nullptr, 0);

   if(sig_len) {
      *sig_len = 64;
   }
   return 0;
}

int Sodium::crypto_sign_ed25519_verify_detached(const uint8_t sig[],
                                                const uint8_t msg[],
                                                size_t msg_len,
                                                const uint8_t pk[32]) {
   const bool ok = ed25519_verify(msg, msg_len, sig, pk, nullptr, 0);
   return ok ? 0 : -1;
}

int Sodium::crypto_sign_ed25519_keypair(uint8_t pk[32], uint8_t sk[64]) {
   secure_vector<uint8_t> seed(32);
   randombytes_buf(seed.data(), seed.size());
   return crypto_sign_ed25519_seed_keypair(pk, sk, seed.data());
}

int Sodium::crypto_sign_ed25519_seed_keypair(uint8_t pk[], uint8_t sk[], const uint8_t seed[]) {
   ed25519_gen_keypair(pk, sk, seed);
   return 0;
}

}  // namespace Botan
