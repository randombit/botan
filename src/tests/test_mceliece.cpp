/*
* (C) 2014 cryptosource GmbH
* (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_MCELIECE)

#include <botan/pubkey.h>
#include <botan/hash.h>
#include <botan/oids.h>
#include <botan/mceliece.h>
#include <botan/internal/code_based_util.h>
#include <botan/mce_kem.h>
#include <botan/loadstor.h>
#include <botan/hex.h>

#if defined(BOTAN_HAS_MCEIES)
#include <botan/mceies.h>
#endif

#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_MCELIECE)

class McEliece_Tests : public Test
   {
   public:

      std::string fingerprint(const Botan::Private_Key& key, const std::string& hash_algo = "SHA-256")
         {
         std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create(hash_algo));
         if(!hash)
            throw std::runtime_error("Hash " + hash_algo + " not available");

         hash->update(key.pkcs8_private_key());
         return Botan::hex_encode(hash->final());
         }

      std::string fingerprint(const Botan::Public_Key& key, const std::string& hash_algo = "SHA-256")
         {
         std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create(hash_algo));
         if(!hash)
            throw std::runtime_error("Hash " + hash_algo + " not available");

         hash->update(key.x509_subject_public_key());
         return Botan::hex_encode(hash->final());
         }

      std::vector<Test::Result> run() override
         {
         size_t params__n__t_min_max[] = {
            256, 5, 15,
            512, 5, 33,
            1024, 15, 35,
            2048, 33, 50,
            2960, 50, 56,
            6624, 110, 115
         };

         std::vector<Test::Result> results;

         for(size_t i = 0; i < sizeof(params__n__t_min_max)/sizeof(params__n__t_min_max[0]); i+=3)
            {
            const size_t code_length = params__n__t_min_max[i];
            for(size_t t = params__n__t_min_max[i+1]; t <= params__n__t_min_max[i+2]; t++)
               {
               Botan::McEliece_PrivateKey sk1(Test::rng(), code_length, t);
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

         Botan::McEliece_KEM_Encryptor pub_op(pk);
         Botan::McEliece_KEM_Decryptor priv_op(sk);

         for(size_t i = 0; i <= Test::soak_level(); i++)
            {
            const std::pair<Botan::secure_vector<byte>,Botan::secure_vector<byte> > ciphertext__sym_key = pub_op.encrypt(Test::rng());
            const Botan::secure_vector<byte>& ciphertext = ciphertext__sym_key.first;
            const Botan::secure_vector<byte>& sym_key_encr = ciphertext__sym_key.second;

            const Botan::secure_vector<byte> sym_key_decr = priv_op.decrypt(ciphertext.data(), ciphertext.size());

            result.test_eq("same key", sym_key_decr, sym_key_encr);
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
                  }
               catch(Botan::Integrity_Failure& e)
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

size_t test_mceliece()
   {
   return Botan_Tests::basic_error_report("mceliece");
   }
