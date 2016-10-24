/*
* (C) 2014 cryptosource GmbH
* (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_MCELIECE)

#include <botan/mceliece.h>
#include <botan/pubkey.h>
#include <botan/oids.h>
#include <botan/hmac_drbg.h>
#include <botan/loadstor.h>
#include <botan/hash.h>
#include <botan/hex.h>

#if defined(BOTAN_HAS_MCEIES)
#include <botan/mceies.h>
#endif

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
                         "pubkey/mce.vec",
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

         Botan::HMAC_DRBG rng("SHA-384");
         rng.initialize_with(keygen_seed.data(), keygen_seed.size());
         Botan::McEliece_PrivateKey mce_priv(rng, keygen_n, keygen_t);

         Test::Result result("McEliece keygen");

         result.test_eq("public key fingerprint", hash_bytes(mce_priv.x509_subject_public_key()), fprint_pub);
         result.test_eq("private key fingerprint", hash_bytes(mce_priv.pkcs8_private_key()), fprint_priv);

         rng.clear();
         rng.initialize_with(encrypt_seed.data(), encrypt_seed.size());

         try
            {
            Botan::PK_KEM_Encryptor kem_enc(mce_priv, Test::rng(), "KDF1(SHA-512)");
            Botan::PK_KEM_Decryptor kem_dec(mce_priv, Test::rng(), "KDF1(SHA-512)");

            Botan::secure_vector<byte> encap_key, prod_shared_key;
            kem_enc.encrypt(encap_key, prod_shared_key, 64, rng);

            Botan::secure_vector<byte> dec_shared_key = kem_dec.decrypt(encap_key.data(), encap_key.size(), 64);

            result.test_eq("ciphertext", encap_key, ciphertext);
            result.test_eq("encrypt shared", prod_shared_key, shared_key);
            result.test_eq("decrypt shared", dec_shared_key, shared_key);
            }
         catch(Botan::Lookup_Error&)
            {
            }

         return result;
         }

   };

BOTAN_REGISTER_TEST("mce_keygen", McEliece_Keygen_Encrypt_Test);

class McEliece_Tests : public Test
   {
   public:

      std::string fingerprint(const Botan::Private_Key& key, const std::string& hash_algo = "SHA-256")
         {
         std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create(hash_algo));
         if(!hash)
            throw Test_Error("Hash " + hash_algo + " not available");

         hash->update(key.pkcs8_private_key());
         return Botan::hex_encode(hash->final());
         }

      std::string fingerprint(const Botan::Public_Key& key, const std::string& hash_algo = "SHA-256")
         {
         std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create(hash_algo));
         if(!hash)
            throw Test_Error("Hash " + hash_algo + " not available");

         hash->update(key.x509_subject_public_key());
         return Botan::hex_encode(hash->final());
         }

      std::vector<Test::Result> run() override
         {
         struct keygen_params { size_t code_length, t_min, t_max; };

         const keygen_params param_sets[] = { { 256, 5, 15 },
                                              { 512, 5, 33 },
                                              { 1024, 15, 35 },
                                              { 2048, 33, 50 },
                                              { 6624, 110, 115 } };

         std::vector<Test::Result> results;

         for(size_t i = 0; i < sizeof(param_sets)/sizeof(param_sets[0]); ++i)
            {
            for(size_t t = param_sets[i].t_min; t <= param_sets[i].t_max; ++t)
               {
               Botan::McEliece_PrivateKey sk1(Test::rng(), param_sets[i].code_length, t);
               const Botan::McEliece_PublicKey& pk1 = sk1;

               const std::vector<byte> pk_enc = pk1.x509_subject_public_key();
               const Botan::secure_vector<byte> sk_enc = sk1.pkcs8_private_key();

               Botan::McEliece_PublicKey pk(pk_enc);
               Botan::McEliece_PrivateKey sk(sk_enc);

               Test::Result result("McEliece keygen");

               result.test_eq("decoded public key equals original", fingerprint(pk1), fingerprint(pk));

               result.test_eq("decoded private key equals original", fingerprint(sk1), fingerprint(sk));

               result.test_eq("key validation passes", sk.check_key(Test::rng(), false), true);

               results.push_back(result);

               results.push_back(test_kem(sk, pk));

#if defined(BOTAN_HAS_MCEIES)
               results.push_back(test_mceies(sk, pk));
#endif
               }
            }

         return results;
         }

   private:
      Test::Result test_kem(const Botan::McEliece_PrivateKey& sk,
                            const Botan::McEliece_PublicKey& pk)
         {
         Test::Result result("McEliece KEM");

         Botan::PK_KEM_Encryptor enc_op(pk, Test::rng(), "KDF2(SHA-256)");
         Botan::PK_KEM_Decryptor dec_op(sk, Test::rng(), "KDF2(SHA-256)");

         for(size_t i = 0; i <= Test::soak_level(); i++)
            {
            Botan::secure_vector<byte> salt = Test::rng().random_vec(i);

            Botan::secure_vector<byte> encap_key, shared_key;
            enc_op.encrypt(encap_key, shared_key, 64, Test::rng(), salt);

            Botan::secure_vector<byte> shared_key2 = dec_op.decrypt(encap_key, 64, salt);

            result.test_eq("same key", shared_key, shared_key2);
            }
         return result;
         }

#if defined(BOTAN_HAS_MCEIES)
      Test::Result test_mceies(const Botan::McEliece_PrivateKey& sk,
                               const Botan::McEliece_PublicKey& pk)
         {
         Test::Result result("McEliece IES");

         for(size_t i = 0; i <= Test::soak_level(); ++i)
            {
            uint8_t ad[8];
            Botan::store_be(static_cast<Botan::u64bit>(i), ad);
            const size_t ad_len = sizeof(ad);

            const Botan::secure_vector<byte> pt = Test::rng().random_vec(Test::rng().next_byte());

            const Botan::secure_vector<byte> ct = mceies_encrypt(pk, pt.data(), pt.size(), ad, ad_len, Test::rng());
            const Botan::secure_vector<byte> dec = mceies_decrypt(sk, ct.data(), ct.size(), ad, ad_len);

            result.test_eq("decrypted ok", dec, pt);

            Botan::secure_vector<byte> bad_ct = ct;
            for(size_t j = 0; j != 3; ++j)
               {
               bad_ct = mutate_vec(ct, true);

               try
                  {
                  mceies_decrypt(sk, bad_ct.data(), bad_ct.size(), ad, ad_len);
                  result.test_failure("AEAD decrypted manipulated ciphertext");
                  result.test_note("Manipulated text was " + Botan::hex_encode(bad_ct));
                  }
               catch(Botan::Integrity_Failure&)
                  {
                  result.test_note("AEAD rejected manipulated ciphertext");
                  }
               catch(std::exception& e)
                  {
                  result.test_failure("AEAD rejected manipulated ciphertext with unexpected error", e.what());
                  }
               }
            }

         return result;
         }
#endif

   };

BOTAN_REGISTER_TEST("mceliece", McEliece_Tests);

#endif

}

}
