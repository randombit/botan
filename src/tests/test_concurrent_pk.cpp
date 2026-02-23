/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO) && defined(BOTAN_TARGET_OS_HAS_THREADS)
   #include <botan/pk_algs.h>
   #include <botan/pubkey.h>
   #include <botan/rng.h>
   #include <botan/internal/fmt.h>
   #include <future>
   #include <sstream>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO) && defined(BOTAN_TARGET_OS_HAS_THREADS)

/*
* Test that public key operations (signing, verification, encryption, decryption, KEM, key
* agreement) with a shared key from multiple threads produce correct results without racing.
*
* TODO: Add concurrent test for ECIES handling
*/

namespace {

constexpr size_t ConcurrentThreads = 10;  // arbitrary

class ConcurrentPkTestCase {
   public:
      ConcurrentPkTestCase(std::string_view pk_algo, std::string_view keygen_params, std::string_view op_params = "") :
            m_pk_algo(pk_algo), m_keygen_params(keygen_params), m_op_params(op_params) {}

      const std::string& algo_name() const { return m_pk_algo; }

      const std::string& op_params() const { return m_op_params; }

      Test::Result result(std::string_view operation) const {
         std::ostringstream name;
         name << "Concurrent " << m_pk_algo;
         if(!m_keygen_params.empty()) {
            name << " " << m_keygen_params;
         }
         if(!m_op_params.empty()) {
            name << " " << m_op_params;
         }
         name << " " << operation;

         return Test::Result(name.str());
      }

      Test::Result skip_missing(std::string_view operation) const {
         auto result = this->result(operation);
         result.test_note("Skipping due to missing algorithm", this->algo_name());
         return result;
      }

      std::unique_ptr<Botan::Private_Key> try_create_key(Botan::RandomNumberGenerator& rng) const {
         try {
            return Botan::create_private_key(m_pk_algo, rng, m_keygen_params);
         } catch(Botan::Lookup_Error&) {
            return nullptr;
         } catch(Botan::Not_Implemented&) {
            return nullptr;
         }
      }

   private:
      std::string m_pk_algo;
      std::string m_keygen_params;
      std::string m_op_params;
};

Test::Result test_concurrent_signing(const ConcurrentPkTestCase& tc,
                                     const Botan::Private_Key& privkey,
                                     const Botan::Public_Key& pubkey) {
   auto result = tc.result("signing");
   auto rng = Test::new_rng(result.who());
   const auto test_message = rng->random_vec(32);

   const auto operations_remaining_at_start = privkey.remaining_operations();

   std::vector<std::future<std::vector<uint8_t>>> futures;
   futures.reserve(ConcurrentThreads);

   for(size_t i = 0; i != ConcurrentThreads; ++i) {
      futures.push_back(std::async(std::launch::async, [&, i]() -> std::vector<uint8_t> {
         auto thread_rng = Test::new_rng(Botan::fmt("{} thread {}", result.who(), i));
         Botan::PK_Signer signer(privkey, *thread_rng, tc.op_params());
         return signer.sign_message(test_message, *thread_rng);
      }));
   }

   Botan::PK_Verifier verifier(pubkey, tc.op_params());

   for(size_t i = 0; i != ConcurrentThreads; ++i) {
      try {
         const auto signature = futures[i].get();

         if(signature.empty()) {
            result.test_failure(Botan::fmt("Thread {} produced empty signature", i));
         } else {
            const bool valid = verifier.verify_message(test_message, signature);
            result.test_is_true(Botan::fmt("Thread {} signature is valid", i), valid);
         }
      } catch(std::exception& e) {
         result.test_failure(Botan::fmt("Thread {} failed: {}", i, e.what()));
      }
   }

   if(operations_remaining_at_start.has_value()) {
      result.test_is_true("Private key should be stateful", privkey.stateful_operation());
      const auto left_at_end = privkey.remaining_operations();

      if(left_at_end.has_value()) {
         result.test_u64_lt(
            "Number of operations went down", left_at_end.value(), operations_remaining_at_start.value());

         const uint64_t consumed = operations_remaining_at_start.value() - left_at_end.value();

         result.test_u64_eq(
            "Private key should have consumed exactly ConcurrentThreads many operations", consumed, ConcurrentThreads);
      } else {
         result.test_failure("Private key remaining_operations should return something both times");
      }
   } else {
      result.test_is_false("Private key should not be stateful", privkey.stateful_operation());
   }

   return result;
}

Test::Result test_concurrent_verification(const ConcurrentPkTestCase& tc,
                                          const Botan::Private_Key& privkey,
                                          const Botan::Public_Key& pubkey) {
   auto result = tc.result("verification");
   auto rng = Test::new_rng(result.who());
   const auto test_message = rng->random_vec(32);

   Botan::PK_Signer signer(privkey, *rng, tc.op_params());
   const auto signature = signer.sign_message(test_message, *rng);

   std::vector<std::future<bool>> futures;
   futures.reserve(ConcurrentThreads);

   for(size_t i = 0; i != ConcurrentThreads; ++i) {
      futures.push_back(std::async(std::launch::async, [&]() -> bool {
         Botan::PK_Verifier verifier(pubkey, tc.op_params());
         return verifier.verify_message(test_message, signature);
      }));
   }

   for(size_t i = 0; i != ConcurrentThreads; ++i) {
      try {
         const bool valid = futures[i].get();
         result.test_is_true(Botan::fmt("Thread {} verification succeeded", i), valid);
      } catch(std::exception& e) {
         result.test_failure(Botan::fmt("Thread {} threw: {}", i, e.what()));
      }
   }

   return result;
}

Test::Result test_concurrent_encryption(const ConcurrentPkTestCase& tc,
                                        const Botan::Private_Key& privkey,
                                        const Botan::Public_Key& pubkey) {
   auto result = tc.result("encryption");
   auto rng = Test::new_rng(result.who());
   const auto test_message = rng->random_vec(32);

   std::vector<std::future<std::vector<uint8_t>>> futures;
   futures.reserve(ConcurrentThreads);

   for(size_t i = 0; i != ConcurrentThreads; ++i) {
      futures.push_back(std::async(std::launch::async, [&, i]() -> std::vector<uint8_t> {
         auto thread_rng = Test::new_rng(Botan::fmt("{} thread {}", result.who(), i));
         const Botan::PK_Encryptor_EME encryptor(pubkey, *thread_rng, tc.op_params());
         return encryptor.encrypt(test_message, *thread_rng);
      }));
   }

   const Botan::PK_Decryptor_EME decryptor(privkey, *rng, tc.op_params());

   for(size_t i = 0; i != ConcurrentThreads; ++i) {
      try {
         const auto ciphertext = futures[i].get();
         const auto plaintext = decryptor.decrypt(ciphertext);
         result.test_bin_eq(Botan::fmt("Thread {} decrypts correctly", i), plaintext, test_message);
      } catch(std::exception& e) {
         result.test_failure(Botan::fmt("Thread {} encrypt threw: {}", i, e.what()));
      }
   }

   return result;
}

Test::Result test_concurrent_decryption(const ConcurrentPkTestCase& tc,
                                        const Botan::Private_Key& privkey,
                                        const Botan::Public_Key& pubkey) {
   auto result = tc.result("decryption");
   auto rng = Test::new_rng(result.who());
   const auto test_message = rng->random_vec(32);

   const Botan::PK_Encryptor_EME encryptor(pubkey, *rng, tc.op_params());
   const auto ciphertext = encryptor.encrypt(test_message, *rng);

   std::vector<std::future<Botan::secure_vector<uint8_t>>> futures;
   futures.reserve(ConcurrentThreads);

   for(size_t i = 0; i != ConcurrentThreads; ++i) {
      futures.push_back(std::async(std::launch::async, [&, i]() -> Botan::secure_vector<uint8_t> {
         auto thread_rng = Test::new_rng(Botan::fmt("{} thread {}", result.who(), i));
         const Botan::PK_Decryptor_EME decryptor(privkey, *thread_rng, tc.op_params());
         return decryptor.decrypt(ciphertext);
      }));
   }

   for(size_t i = 0; i != ConcurrentThreads; ++i) {
      try {
         const auto plaintext = futures[i].get();
         result.test_bin_eq(Botan::fmt("Thread {} decrypts correctly", i), plaintext, test_message);
      } catch(std::exception& e) {
         result.test_failure(Botan::fmt("Thread {} decrypt threw: {}", i, e.what()));
      }
   }

   return result;
}

Test::Result test_concurrent_kem_encap(const ConcurrentPkTestCase& tc,
                                       const Botan::Private_Key& privkey,
                                       const Botan::Public_Key& pubkey) {
   auto result = tc.result("KEM encapsulate");
   auto rng = Test::new_rng(result.who());

   std::vector<std::future<Botan::KEM_Encapsulation>> futures;
   futures.reserve(ConcurrentThreads);

   for(size_t i = 0; i != ConcurrentThreads; ++i) {
      futures.push_back(std::async(std::launch::async, [&, i]() -> Botan::KEM_Encapsulation {
         auto thread_rng = Test::new_rng(Botan::fmt("{} thread {}", result.who(), i));
         Botan::PK_KEM_Encryptor encryptor(pubkey, tc.op_params());
         return encryptor.encrypt(*thread_rng);
      }));
   }

   Botan::PK_KEM_Decryptor decryptor(privkey, *rng, tc.op_params());

   for(size_t i = 0; i != ConcurrentThreads; ++i) {
      try {
         const auto kr = futures[i].get();
         const auto shared_key = decryptor.decrypt(kr.encapsulated_shared_key(), 32);
         result.test_bin_eq(Botan::fmt("Thread {} shared key matches", i), shared_key, kr.shared_key());
      } catch(std::exception& e) {
         result.test_failure(Botan::fmt("Thread {} encapsulate threw: {}", i, e.what()));
      }
   }

   return result;
}

Test::Result test_concurrent_kem_decap(const ConcurrentPkTestCase& tc,
                                       const Botan::Private_Key& privkey,
                                       const Botan::Public_Key& pubkey) {
   auto result = tc.result("KEM decapsulate");
   auto rng = Test::new_rng(result.who());

   Botan::PK_KEM_Encryptor encryptor(pubkey, tc.op_params());
   auto kem_enc = encryptor.encrypt(*rng);

   std::vector<std::future<Botan::secure_vector<uint8_t>>> futures;
   futures.reserve(ConcurrentThreads);

   for(size_t i = 0; i != ConcurrentThreads; ++i) {
      futures.push_back(std::async(std::launch::async, [&, i]() -> Botan::secure_vector<uint8_t> {
         auto thread_rng = Test::new_rng(Botan::fmt("{} thread {}", result.who(), i));
         Botan::PK_KEM_Decryptor decryptor(privkey, *thread_rng, tc.op_params());
         return decryptor.decrypt(kem_enc.encapsulated_shared_key(), 0);
      }));
   }

   for(size_t i = 0; i != ConcurrentThreads; ++i) {
      try {
         const auto shared_key = futures[i].get();
         result.test_bin_eq(Botan::fmt("Thread {} shared key matches", i), shared_key, kem_enc.shared_key());
      } catch(std::exception& e) {
         result.test_failure(Botan::fmt("Thread {} decapsulate threw: {}", i, e.what()));
      }
   }

   return result;
}

Test::Result test_concurrent_key_agreement(const ConcurrentPkTestCase& tc) {
   auto result = tc.result("key agreement");

   auto rng = Test::new_rng(result.who());
   auto our_key = tc.try_create_key(*rng);
   if(!our_key) {
      result.test_note("Skipping due to missing algorithm");
      return result;
   }

   auto peer_key = tc.try_create_key(*rng);

   const auto* our_ka_key = dynamic_cast<Botan::PK_Key_Agreement_Key*>(our_key.get());
   const auto* peer_ka_key = dynamic_cast<Botan::PK_Key_Agreement_Key*>(peer_key.get());
   if(our_ka_key == nullptr || peer_ka_key == nullptr) {
      result.test_failure("Key does not support key agreement");
      return result;
   }

   const auto peer_public = peer_ka_key->public_value();

   // Compute reference shared secret single-threaded
   const Botan::PK_Key_Agreement ref_ka(*our_key, *rng, tc.op_params());
   const auto reference_secret = ref_ka.derive_key(32, peer_public).bits_of();

   std::vector<std::future<std::vector<uint8_t>>> futures;
   futures.reserve(ConcurrentThreads);

   for(size_t i = 0; i != ConcurrentThreads; ++i) {
      futures.push_back(std::async(std::launch::async, [&, i]() -> std::vector<uint8_t> {
         auto thread_rng = Test::new_rng(Botan::fmt("{} thread {}", result.who(), i));
         const Botan::PK_Key_Agreement ka(*our_key, *thread_rng, tc.op_params());
         return Botan::unlock(ka.derive_key(32, peer_public).bits_of());
      }));
   }

   for(size_t i = 0; i != ConcurrentThreads; ++i) {
      try {
         const auto shared_secret = futures[i].get();
         result.test_bin_eq(Botan::fmt("Thread {} shared secret matches", i), shared_secret, reference_secret);
      } catch(std::exception& e) {
         result.test_failure(Botan::fmt("Thread {} threw: {}", i, e.what()));
      }
   }

   return result;
}

Test::Result test_concurrent_key_generation(const ConcurrentPkTestCase& tc) {
   auto result = tc.result("key generation");

   auto rng = Test::new_rng(result.who());

   if(tc.try_create_key(*rng) == nullptr) {
      result.test_note("Keygen not available");
      return result;
   }

   std::vector<std::future<std::unique_ptr<Botan::Private_Key>>> futures;
   futures.reserve(ConcurrentThreads);

   for(size_t i = 0; i != ConcurrentThreads; ++i) {
      futures.push_back(std::async(std::launch::async, [&, i]() -> std::unique_ptr<Botan::Private_Key> {
         auto thread_rng = Test::new_rng(Botan::fmt("{} thread {}", result.who(), i));
         return tc.try_create_key(*thread_rng);
      }));
   }

   for(size_t i = 0; i != ConcurrentThreads; ++i) {
      try {
         const auto sk = futures[i].get();
         result.test_not_null(Botan::fmt("Thread {} generated a key", i), sk.get());

         if(sk) {
            result.test_is_true(Botan::fmt("Thread {} generated key seems valid", i), sk->check_key(*rng, true));
         }
      } catch(std::exception& e) {
         result.test_failure(Botan::fmt("Thread {} threw: {}", i, e.what()));
      }
   }

   return result;
}

class Concurrent_Public_Key_Operations_Test : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         concurrent_signing_and_verification_tests(results);
         concurrent_encryption_tests(results);
         concurrent_kem_tests(results);
         concurrent_key_agreement_tests(results);
         concurrent_key_generation_tests(results);

         return results;
      }

   private:
      void concurrent_signing_and_verification_tests(std::vector<Test::Result>& results) {
         const std::vector<ConcurrentPkTestCase> test_cases = {
            ConcurrentPkTestCase("RSA", "1536", "PKCS1v15(SHA-256)"),
            ConcurrentPkTestCase("ECDSA", "secp256r1", "SHA-256"),
            ConcurrentPkTestCase("ECKCDSA", "secp256r1", "SHA-256"),
            ConcurrentPkTestCase("ECGDSA", "secp256r1", "SHA-256"),
            ConcurrentPkTestCase("DSA", "dsa/jce/1024", "SHA-256"),
            ConcurrentPkTestCase("SM2", "sm2p256v1", "SM3"),
            ConcurrentPkTestCase("Ed25519", "", "Pure"),
            ConcurrentPkTestCase("Ed448", "", "Pure"),
            ConcurrentPkTestCase("ML-DSA", "ML-DSA-4x4"),
            ConcurrentPkTestCase("Dilithium", "Dilithium-4x4-r3"),
            ConcurrentPkTestCase("Dilithium", "Dilithium-4x4-AES-r3"),
            ConcurrentPkTestCase("SLH-DSA", "SLH-DSA-SHA2-128f"),
            ConcurrentPkTestCase("HSS-LMS", "SHA-256,HW(5,8)"),
            ConcurrentPkTestCase("XMSS", "XMSS-SHA2_10_256"),
         };

         for(const auto& tc : test_cases) {
            auto rng = Test::new_rng(tc.algo_name());

            if(auto privkey = tc.try_create_key(*rng)) {
               auto pubkey = privkey->public_key();
               results.push_back(test_concurrent_signing(tc, *privkey, *pubkey));
               results.push_back(test_concurrent_verification(tc, *privkey, *pubkey));
            } else {
               results.push_back(tc.skip_missing("signing"));
            }
         }
      }

      void concurrent_encryption_tests(std::vector<Test::Result>& results) {
         const std::vector<ConcurrentPkTestCase> test_cases = {
            ConcurrentPkTestCase("RSA", "1536", "OAEP(SHA-256)"),
            ConcurrentPkTestCase("ElGamal", "modp/ietf/1536", "PKCS1v15"),
         };

         for(const auto& tc : test_cases) {
            auto rng = Test::new_rng(tc.algo_name());

            if(auto privkey = tc.try_create_key(*rng)) {
               auto pubkey = privkey->public_key();
               results.push_back(test_concurrent_encryption(tc, *privkey, *pubkey));
               results.push_back(test_concurrent_decryption(tc, *privkey, *pubkey));
            } else {
               results.push_back(tc.skip_missing("encryption"));
            }
         }
      }

      void concurrent_kem_tests(std::vector<Test::Result>& results) {
         const std::vector<ConcurrentPkTestCase> test_cases = {
            ConcurrentPkTestCase("RSA", "1536", "Raw"),
            ConcurrentPkTestCase("ClassicMcEliece", "348864f", "Raw"),
            ConcurrentPkTestCase("McEliece", "1632,33", "Raw"),
            ConcurrentPkTestCase("FrodoKEM", "FrodoKEM-640-SHAKE", "Raw"),
            ConcurrentPkTestCase("FrodoKEM", "FrodoKEM-640-AES", "Raw"),
            ConcurrentPkTestCase("ML-KEM", "ML-KEM-512", "Raw"),
            ConcurrentPkTestCase("Kyber", "Kyber-512-90s-r3", "Raw"),
            ConcurrentPkTestCase("Kyber", "Kyber-512-r3", "Raw"),
         };

         for(const auto& tc : test_cases) {
            auto rng = Test::new_rng(tc.algo_name());
            if(auto privkey = tc.try_create_key(*rng)) {
               auto pubkey = privkey->public_key();
               results.push_back(test_concurrent_kem_encap(tc, *privkey, *pubkey));
               results.push_back(test_concurrent_kem_decap(tc, *privkey, *pubkey));
            } else {
               results.push_back(tc.skip_missing("KEM encapsulate"));
            }
         }
      }

      void concurrent_key_agreement_tests(std::vector<Test::Result>& results) {
         const std::vector<ConcurrentPkTestCase> test_cases = {
            ConcurrentPkTestCase("DH", "modp/ietf/1536", "Raw"),
            ConcurrentPkTestCase("ECDH", "secp256r1", "Raw"),
            ConcurrentPkTestCase("X25519", "", "Raw"),
            ConcurrentPkTestCase("X448", "", "Raw"),
         };

         for(const auto& tc : test_cases) {
            results.push_back(test_concurrent_key_agreement(tc));
         }
      }

      void concurrent_key_generation_tests(std::vector<Test::Result>& results) {
         const std::vector<ConcurrentPkTestCase> test_cases = {
            ConcurrentPkTestCase("ClassicMcEliece", "348864f"),
            ConcurrentPkTestCase("DH", "modp/ietf/1536"),
            ConcurrentPkTestCase("DSA", "dsa/jce/1024"),
            ConcurrentPkTestCase("ECDH", "secp256r1"),
            ConcurrentPkTestCase("ECDSA", "secp256r1"),
            ConcurrentPkTestCase("ECGDSA", "secp256r1"),
            ConcurrentPkTestCase("ECKCDSA", "secp256r1"),
            ConcurrentPkTestCase("Ed25519", ""),
            ConcurrentPkTestCase("Ed448", ""),
            ConcurrentPkTestCase("HSS-LMS", "SHA-256,HW(5,8)"),
            ConcurrentPkTestCase("RSA", "1536"),
            ConcurrentPkTestCase("SLH-DSA", "SLH-DSA-SHA2-128f"),
            ConcurrentPkTestCase("SM2", "sm2p256v1"),
            ConcurrentPkTestCase("X25519", ""),
            ConcurrentPkTestCase("X448", ""),
         };

         for(const auto& tc : test_cases) {
            results.push_back(test_concurrent_key_generation(tc));
         }
      }
};

BOTAN_REGISTER_SERIALIZED_TEST("pubkey", "pk_concurrent_ops", Concurrent_Public_Key_Operations_Test);

}  // namespace

#endif

}  // namespace Botan_Tests
