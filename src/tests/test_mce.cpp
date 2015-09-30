/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_MCELIECE)

#include <botan/mceliece.h>
#include <botan/mce_kem.h>
#include <botan/hmac_drbg.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

std::string hash_bytes(const byte b[], size_t len)
   {
   std::unique_ptr<HashFunction> hash(HashFunction::create("SHA-256"));
   hash->update(b, len);
   return hex_encode(hash->final());
   }

template<typename A>
std::string hash_bytes(const std::vector<byte, A>& v)
   {
   return hash_bytes(v.data(), v.size());
   }

size_t mce_test(const std::string& key_seed_hex,
                size_t n, size_t t,
                const std::string& exp_fingerprint_pub,
                const std::string& exp_fingerprint_priv,
                const std::string& encrypt_rng_seed_hex,
                const std::string& ct_hex,
                const std::string& shared_key_hex)
   {
   const secure_vector<byte> keygen_seed = hex_decode_locked(key_seed_hex);
   const secure_vector<byte> encrypt_seed = hex_decode_locked(encrypt_rng_seed_hex);

   Test_State _test;

   HMAC_DRBG rng("HMAC(SHA-384)");

   rng.add_entropy(keygen_seed.data(), keygen_seed.size());

   McEliece_PrivateKey mce_priv(rng, n, t);

   const std::string f_pub = hash_bytes(mce_priv.x509_subject_public_key());
   const std::string f_priv = hash_bytes(mce_priv.pkcs8_private_key());

   BOTAN_TEST(f_pub, exp_fingerprint_pub, "Public fingerprint");
   BOTAN_TEST(f_priv, exp_fingerprint_priv, "Private fingerprint");

   rng.clear();
   rng.add_entropy(encrypt_seed.data(), encrypt_seed.size());

   McEliece_KEM_Encryptor kem_enc(mce_priv);
   McEliece_KEM_Decryptor kem_dec(mce_priv);

   const std::pair<secure_vector<byte>,secure_vector<byte> > ciphertext__sym_key = kem_enc.encrypt(rng);
   const secure_vector<byte>& ciphertext = ciphertext__sym_key.first;
   const secure_vector<byte>& sym_key_encr = ciphertext__sym_key.second;

   const secure_vector<byte> sym_key_decr = kem_dec.decrypt(ciphertext.data(), ciphertext.size());

   BOTAN_TEST(ct_hex, hex_encode(ciphertext), "Ciphertext");
   BOTAN_TEST(hex_encode(sym_key_encr), shared_key_hex, "Encrypted key");
   BOTAN_TEST(hex_encode(sym_key_decr), shared_key_hex, "Decrypted key");

   return _test.failed();
   }

}

size_t test_mce()
   {

   std::ifstream vec(TEST_DATA_DIR "/pubkey/mce.vec");
   return run_tests_bb(vec, "McElieceSeed", "Ciphertext", true,
                       [](std::map<std::string, std::string> m) -> size_t
                       {
                       return mce_test(m["McElieceSeed"],
                                       to_u32bit(m["KeyN"]),
                                       to_u32bit(m["KeyT"]),
                                       m["PublicKeyFingerprint"],
                                       m["PrivateKeyFingerprint"],
                                       m["EncryptPRNGSeed"],
                                       m["Ciphertext"],
                                       m["SharedKey"]);
                       });
   }

#else

SKIP_TEST(mce);

#endif
