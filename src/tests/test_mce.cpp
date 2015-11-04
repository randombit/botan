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
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_MCELIECE)

std::vector<byte> hash_bytes(const byte b[], size_t len, const std::string& hash_fn = "SHA-256")
   {
   std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create(hash_fn));
   hash->update(b, len);
   std::vector<byte> r(hash->output_length());
   hash->final(r.data());
   return r;
   }

template<typename A>
std::vector<byte> hash_bytes(const std::vector<byte, A>& v)
   {
   return hash_bytes(v.data(), v.size());
   }

class McEliece_Keygen_Encrypt_Test : public Text_Based_Test
   {
   public:
      McEliece_Keygen_Encrypt_Test() :
         Text_Based_Test("McEliece",
                         Test::data_file("pubkey/mce.vec"),
                         {"McElieceSeed", "KeyN","KeyT","PublicKeyFingerprint",
                          "PrivateKeyFingerprint", "EncryptPRNGSeed",
                            "SharedKey", "Ciphertext" })
         {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         const std::vector<byte> keygen_seed  = get_req_bin(vars, "McElieceSeed");
         const std::vector<byte> fprint_pub   = get_req_bin(vars, "PublicKeyFingerprint");
         const std::vector<byte> fprint_priv  = get_req_bin(vars, "PrivateKeyFingerprint");
         const std::vector<byte> encrypt_seed = get_req_bin(vars, "EncryptPRNGSeed");
         const std::vector<byte> ciphertext   = get_req_bin(vars, "Ciphertext");
         const std::vector<byte> shared_key   = get_req_bin(vars, "SharedKey");
         const size_t keygen_n = get_req_sz(vars, "KeyN");
         const size_t keygen_t = get_req_sz(vars, "KeyT");

         Botan::HMAC_DRBG rng("HMAC(SHA-384)");

         rng.add_entropy(keygen_seed.data(), keygen_seed.size());
         Botan::McEliece_PrivateKey mce_priv(rng, keygen_n, keygen_t);

         Test::Result result("McEliece keygen");

         result.test_eq("public key fingerprint", hash_bytes(mce_priv.x509_subject_public_key()), fprint_pub);
         result.test_eq("private key fingerprint", hash_bytes(mce_priv.pkcs8_private_key()), fprint_priv);

         rng.clear();
         rng.add_entropy(encrypt_seed.data(), encrypt_seed.size());

         Botan::McEliece_KEM_Encryptor kem_enc(mce_priv);
         Botan::McEliece_KEM_Decryptor kem_dec(mce_priv);

         const auto kem = kem_enc.encrypt(rng);
         result.test_eq("ciphertext", kem.first, ciphertext);
         result.test_eq("encrypt shared", kem.second, shared_key);
         result.test_eq("decrypt shared", kem_dec.decrypt_vec(kem.first), shared_key);
         return result;
         }

   };

BOTAN_REGISTER_TEST("mce_keygen", McEliece_Keygen_Encrypt_Test);

#endif

}

}
