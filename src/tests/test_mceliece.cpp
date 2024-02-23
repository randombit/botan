/*
* (C) 2014 cryptosource GmbH
* (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_MCELIECE)

   #include <botan/hash.h>
   #include <botan/hex.h>
   #include <botan/mceliece.h>
   #include <botan/pubkey.h>
   #include <botan/internal/loadstor.h>

   #if defined(BOTAN_HAS_HMAC_DRBG)
      #include <botan/hmac_drbg.h>
   #endif

#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_MCELIECE)

   #if defined(BOTAN_HAS_HMAC_DRBG) && defined(BOTAN_HAS_SHA2_32) && defined(BOTAN_HAS_SHA2_64)
class McEliece_Keygen_Encrypt_Test final : public Text_Based_Test {
   public:
      McEliece_Keygen_Encrypt_Test() :
            Text_Based_Test("pubkey/mce.vec",
                            "McElieceSeed,KeyN,KeyT,PublicKeyFingerprint,PrivateKeyFingerprint,"
                            "EncryptPRNGSeed,SharedKey,Ciphertext",
                            "") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         const std::vector<uint8_t> keygen_seed = vars.get_req_bin("McElieceSeed");
         const std::vector<uint8_t> fprint_pub = vars.get_req_bin("PublicKeyFingerprint");
         const std::vector<uint8_t> fprint_priv = vars.get_req_bin("PrivateKeyFingerprint");
         const std::vector<uint8_t> encrypt_seed = vars.get_req_bin("EncryptPRNGSeed");
         const std::vector<uint8_t> ciphertext = vars.get_req_bin("Ciphertext");
         const std::vector<uint8_t> shared_key = vars.get_req_bin("SharedKey");
         const size_t keygen_n = vars.get_req_sz("KeyN");
         const size_t keygen_t = vars.get_req_sz("KeyT");

         Test::Result result("McEliece keygen");
         result.start_timer();

         if(Test::run_long_tests() == false && keygen_n > 3072) {
            result.test_note("Skipping because long");
            return result;
         }

         Botan::HMAC_DRBG rng("SHA-384");
         rng.initialize_with(keygen_seed.data(), keygen_seed.size());
         Botan::McEliece_PrivateKey mce_priv(rng, keygen_n, keygen_t);

         result.test_eq("public key fingerprint", hash_bytes(mce_priv.public_key_bits()), fprint_pub);
         result.test_eq("private key fingerprint", hash_bytes(mce_priv.private_key_bits()), fprint_priv);

         rng.clear();
         rng.initialize_with(encrypt_seed.data(), encrypt_seed.size());

         try {
            Botan::PK_KEM_Encryptor kem_enc(mce_priv, "KDF1(SHA-512)");
            Botan::PK_KEM_Decryptor kem_dec(mce_priv, this->rng(), "KDF1(SHA-512)");

            const auto kem_result = kem_enc.encrypt(rng, 64);

            Botan::secure_vector<uint8_t> dec_shared_key =
               kem_dec.decrypt(kem_result.encapsulated_shared_key(), 64, {});

            result.test_eq("ciphertext", kem_result.encapsulated_shared_key(), ciphertext);
            result.test_eq("encrypt shared", kem_result.shared_key(), shared_key);
            result.test_eq("decrypt shared", dec_shared_key, shared_key);
         } catch(Botan::Lookup_Error&) {}

         result.end_timer();
         return result;
      }

   private:
      static std::vector<uint8_t> hash_bytes(const uint8_t b[], size_t len, const std::string& hash_fn = "SHA-256") {
         auto hash = Botan::HashFunction::create(hash_fn);
         hash->update(b, len);
         std::vector<uint8_t> r(hash->output_length());
         hash->final(r.data());
         return r;
      }

      template <typename A>
      std::vector<uint8_t> hash_bytes(const std::vector<uint8_t, A>& v) {
         return hash_bytes(v.data(), v.size());
      }
};

BOTAN_REGISTER_TEST("pubkey", "mce_keygen", McEliece_Keygen_Encrypt_Test);
   #endif

   #if defined(BOTAN_HAS_SHA2_32)

class McEliece_Tests final : public Test {
   public:
      static std::string fingerprint(const Botan::Private_Key& key, const std::string& hash_algo = "SHA-256") {
         auto hash = Botan::HashFunction::create(hash_algo);
         if(!hash) {
            throw Test_Error("Hash " + hash_algo + " not available");
         }

         hash->update(key.private_key_bits());
         return Botan::hex_encode(hash->final());
      }

      static std::string fingerprint(const Botan::Public_Key& key, const std::string& hash_algo = "SHA-256") {
         auto hash = Botan::HashFunction::create(hash_algo);
         if(!hash) {
            throw Test_Error("Hash " + hash_algo + " not available");
         }

         hash->update(key.public_key_bits());
         return Botan::hex_encode(hash->final());
      }

      std::vector<Test::Result> run() override {
         struct keygen_params {
               size_t code_length, t_min, t_max;
         };

         const keygen_params param_sets[] = {
            {256, 5, 15}, {512, 5, 33}, {1024, 15, 35}, {2048, 33, 50}, {6624, 110, 115}};

         std::vector<Test::Result> results;

         for(size_t i = 0; i < sizeof(param_sets) / sizeof(param_sets[0]); ++i) {
            if(Test::run_long_tests() == false && param_sets[i].code_length >= 2048) {
               continue;
            }

            for(size_t t = param_sets[i].t_min; t <= param_sets[i].t_max; ++t) {
               Test::Result result("McEliece keygen");
               result.start_timer();

               Botan::McEliece_PrivateKey sk1(this->rng(), param_sets[i].code_length, t);
               const Botan::McEliece_PublicKey& pk1 = sk1;

               const std::vector<uint8_t> pk_enc = pk1.public_key_bits();
               const Botan::secure_vector<uint8_t> sk_enc = sk1.private_key_bits();

               Botan::McEliece_PublicKey pk(pk_enc);
               Botan::McEliece_PrivateKey sk(sk_enc);

               result.test_eq("decoded public key equals original", fingerprint(pk1), fingerprint(pk));
               result.test_eq("decoded private key equals original", fingerprint(sk1), fingerprint(sk));
               result.test_eq("key validation passes", sk.check_key(this->rng(), false), true);
               result.end_timer();

               result.end_timer();

               results.push_back(result);

      #if defined(BOTAN_HAS_KDF2)
               results.push_back(test_kem(sk, pk, this->rng()));
      #endif
            }
         }

         return results;
      }

   private:
      static Test::Result test_kem(const Botan::McEliece_PrivateKey& sk,
                                   const Botan::McEliece_PublicKey& pk,
                                   Botan::RandomNumberGenerator& rng) {
         Test::Result result("McEliece KEM");
         result.start_timer();

         Botan::PK_KEM_Encryptor enc_op(pk, "KDF2(SHA-256)");
         Botan::PK_KEM_Decryptor dec_op(sk, rng, "KDF2(SHA-256)");

         const size_t trials = (Test::run_long_tests() ? 30 : 10);
         for(size_t i = 0; i < trials; i++) {
            Botan::secure_vector<uint8_t> salt = rng.random_vec(i);

            const auto kem_result = enc_op.encrypt(rng, 64, salt);

            Botan::secure_vector<uint8_t> shared_key2 = dec_op.decrypt(kem_result.encapsulated_shared_key(), 64, salt);

            result.test_eq("same key", kem_result.shared_key(), shared_key2);
         }
         result.end_timer();
         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "mceliece", McEliece_Tests);

   #endif

#endif

}  // namespace

}  // namespace Botan_Tests
