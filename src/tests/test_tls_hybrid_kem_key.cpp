/*
* (C) 2023 Jack Lloyd
* (C) 2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS_13_PQC) && defined(BOTAN_HAS_KYBER) && defined(BOTAN_HAS_DIFFIE_HELLMAN) && \
   defined(BOTAN_HAS_ECDSA)

   #include <botan/pk_algs.h>
   #include <botan/rng.h>
   #include <botan/internal/hybrid_public_key.h>
   #include <botan/internal/kex_to_kem_adapter.h>
   #include <botan/internal/stl_util.h>
   #include <algorithm>

namespace Botan_Tests {

namespace {

// For convenience, we register a test-global RNG instance at the beginning of
// this test suite. This RNG instance is used by all test cases in this file.
Botan::RandomNumberGenerator& global_test_rng() {
   static auto test_global_rng = Test::new_rng(__func__);
   return *test_global_rng;
}

// The concrete key pairs are not relevant for these test cases. For convenience
// and performance reasons, kem(), kex_dh(), kex_ecdh(), and sig() generate only
// a single key pair and return a copy of it with every invocation. Note that
// the tests assume that those methods always return the same key.

std::unique_ptr<Botan::Private_Key> kem() {
   static auto kem_key = Botan::create_private_key("Kyber", global_test_rng(), "Kyber-512-r3");
   return Botan::load_private_key(kem_key->algorithm_identifier(), kem_key->private_key_bits());
}

std::unique_ptr<Botan::PK_Key_Agreement_Key> kex_dh() {
   static auto kex_key = Botan::create_private_key("DH", global_test_rng(), "ffdhe/ietf/2048");
   auto sk = Botan::load_private_key(kex_key->algorithm_identifier(), kex_key->private_key_bits());
   auto* kex_sk = dynamic_cast<Botan::PK_Key_Agreement_Key*>(sk.get());
   if(kex_sk != nullptr) {
      // NOLINTNEXTLINE(bugprone-unused-return-value)
      (void)sk.release();
      return std::unique_ptr<Botan::PK_Key_Agreement_Key>(kex_sk);
   } else {
      throw Test_Error("something went wrong when generating a PK_Key_Agreement_Key");
   }
}

std::unique_ptr<Botan::PK_Key_Agreement_Key> kex_ecdh() {
   static auto kex_key = Botan::create_private_key("ECDH", global_test_rng(), "secp256r1");
   auto sk = Botan::load_private_key(kex_key->algorithm_identifier(), kex_key->private_key_bits());
   auto* kex_sk = dynamic_cast<Botan::PK_Key_Agreement_Key*>(sk.get());
   if(kex_sk != nullptr) {
      // NOLINTNEXTLINE(bugprone-unused-return-value)
      (void)sk.release();
      return std::unique_ptr<Botan::PK_Key_Agreement_Key>(kex_sk);
   } else {
      throw Test_Error("something went wrong when generating a PK_Key_Agreement_Key");
   }
}

std::unique_ptr<Botan::Private_Key> sig() {
   static auto sig_key = Botan::create_private_key("ECDSA", global_test_rng(), "secp256r1");
   return Botan::load_private_key(sig_key->algorithm_identifier(), sig_key->private_key_bits());
}

template <typename T>
std::unique_ptr<Botan::Public_Key> as_public_key(T private_key) {
   if constexpr(std::is_same_v<T, std::nullptr_t>) {
      return nullptr;
   } else {
      return private_key->public_key();
   }
}

size_t length_of_hybrid_shared_key(const Botan::PairOfPrivateKeys& private_keys) {
   auto shared_secret_length = [](const std::unique_ptr<Botan::Private_Key>& key) {
      if(key->supports_operation(Botan::PublicKeyOperation::KeyAgreement)) {
         const Botan::PK_Key_Agreement ka(*key, global_test_rng(), "Raw");
         return ka.agreed_value_size();
      } else {
         const Botan::PK_KEM_Encryptor enc(*key, "Raw");
         return enc.shared_key_length(0);
      }
   };

   return (shared_secret_length(private_keys.first) + shared_secret_length(private_keys.second));
}

size_t length_of_hybrid_ciphertext(const Botan::PairOfPrivateKeys& private_keys) {
   auto ciphertext_length = [](const std::unique_ptr<Botan::Private_Key>& key) {
      if(key->supports_operation(Botan::PublicKeyOperation::KeyAgreement)) {
         const auto* kex_key = dynamic_cast<const Botan::PK_Key_Agreement_Key*>(key.get());
         BOTAN_ASSERT_NONNULL(kex_key);
         return kex_key->public_value().size();
      } else {
         const Botan::PK_KEM_Encryptor enc(*key, "Raw");
         return enc.encapsulated_key_length();
      }
   };

   return (ciphertext_length(private_keys.first) + ciphertext_length(private_keys.second));
}

size_t length_of_hybrid_public_value(const Botan::PairOfPrivateKeys& private_keys) {
   auto public_value_length = [](const std::unique_ptr<Botan::Private_Key>& key) {
      if(key->supports_operation(Botan::PublicKeyOperation::KeyAgreement)) {
         const auto* kex_key = dynamic_cast<const Botan::PK_Key_Agreement_Key*>(key.get());
         BOTAN_ASSERT_NONNULL(kex_key);
         return kex_key->public_value().size();
      } else {
         return key->public_key_bits().size();
      }
   };

   return (public_value_length(private_keys.first) + public_value_length(private_keys.second));
}

/// Public_Key::key_length()
size_t key_length_of_hybrid_public_key(const Botan::PairOfPrivateKeys& private_keys) {
   return std::max(private_keys.first->key_length(), private_keys.second->key_length());
}

size_t estimated_strength_of_hybrid_public_key(const Botan::PairOfPrivateKeys& private_keys) {
   return std::max(private_keys.first->estimated_strength(), private_keys.second->estimated_strength());
}

void roundtrip_test(Test::Result& result, Botan::PairOfPrivateKeys private_keys) {
   const auto expected_shared_secret_length = length_of_hybrid_shared_key(private_keys);
   const auto expected_ciphertext_length = length_of_hybrid_ciphertext(private_keys);
   const auto expected_public_key_length = length_of_hybrid_public_value(private_keys);
   const auto expected_key_length = key_length_of_hybrid_public_key(private_keys);
   const auto expected_strength = estimated_strength_of_hybrid_public_key(private_keys);

   const Botan::TLS::Hybrid_TLS_KEM_PrivateKey hybrid_key(std::move(private_keys));
   const auto hybrid_public_key = hybrid_key.public_key();

   auto& rng = global_test_rng();

   Botan::PK_KEM_Encryptor encryptor(*hybrid_public_key, "Raw");
   const auto kem_result = encryptor.encrypt(rng);

   result.test_sz_eq(
      "ciphertext has expected length", kem_result.encapsulated_shared_key().size(), expected_ciphertext_length);
   result.test_sz_eq(
      "shared secret has expected length", kem_result.shared_key().size(), expected_shared_secret_length);
   result.test_sz_eq(
      "expected length of ciphertext is as expected", encryptor.encapsulated_key_length(), expected_ciphertext_length);
   result.test_sz_eq(
      "shared secret has expected length", encryptor.shared_key_length(0), expected_shared_secret_length);

   Botan::PK_KEM_Decryptor decryptor(hybrid_key, rng, "Raw");
   Botan::secure_vector<uint8_t> decaps_shared_secret = decryptor.decrypt(kem_result.encapsulated_shared_key(), 0, {});

   result.test_bin_eq("shared secret after KEM roundtrip matches", decaps_shared_secret, kem_result.shared_key());
   result.test_sz_eq(
      "expected shared secret has expected length", decryptor.shared_key_length(0), expected_shared_secret_length);
   result.test_sz_eq("shared secret has expected length", decaps_shared_secret.size(), expected_shared_secret_length);

   result.test_sz_eq("public key bits is the sum of its parts",
                     hybrid_public_key->raw_public_key_bits().size(),
                     expected_public_key_length);

   result.test_sz_eq(
      "Public_Key::key_length is the maximum of its parts", hybrid_public_key->key_length(), expected_key_length);
   result.test_sz_eq("Public_Key::estimated_strength is the maximum of its parts",
                     hybrid_public_key->estimated_strength(),
                     expected_strength);
}

std::vector<Test::Result> hybrid_kem_keypair() {
   return {
      CHECK("public key handles nullptr",
            [&](auto& result) {
               result.test_throws("hybrid KEM key does not accept nullptr keys",
                                  [] { Botan::TLS::Hybrid_TLS_KEM_PublicKey({nullptr, nullptr}); });
               result.test_throws("hybrid KEM key does not accept nullptr keys along with KEM",
                                  [&] { Botan::TLS::Hybrid_TLS_KEM_PublicKey({nullptr, as_public_key(kem())}); });
               result.test_throws("hybrid KEM key does not accept nullptr keys along with KEX",
                                  [&] { Botan::TLS::Hybrid_TLS_KEM_PublicKey({as_public_key(kex_dh()), nullptr}); });
            }),

      CHECK("private key handles nullptr",
            [&](auto& result) {
               result.test_throws("hybrid KEM key does not accept nullptr keys",
                                  [] { Botan::TLS::Hybrid_TLS_KEM_PrivateKey({nullptr, nullptr}); });
               result.test_throws("hybrid KEM key does not accept nullptr keys along with KEM",
                                  [&] { Botan::TLS::Hybrid_TLS_KEM_PrivateKey({nullptr, kem()}); });
               result.test_throws("hybrid KEM key does not accept nullptr keys along with KEX",
                                  [&] { Botan::TLS::Hybrid_TLS_KEM_PrivateKey({kex_dh(), nullptr}); });
            }),

      CHECK("handles incompatible keys (non-KEM, non-KEX)",
            [&](auto& result) {
               result.test_throws("hybrid KEM key does not accept signature keys",
                                  [&] { Botan::TLS::Hybrid_TLS_KEM_PrivateKey({sig(), kem()}); });
               result.test_throws("signature keys aren't allowed along with KEM keys",
                                  [&] { Botan::TLS::Hybrid_TLS_KEM_PrivateKey({sig(), kem()}); });
               result.test_throws("signature keys aren't allowed along with KEX keys",
                                  [&] { Botan::TLS::Hybrid_TLS_KEM_PrivateKey({kex_dh(), sig()}); });
            }),

      CHECK("dual KEM key", [&](auto& result) { roundtrip_test(result, {kem(), kem()}); }),
      CHECK("dual KEX key", [&](auto& result) { roundtrip_test(result, {kex_dh(), kex_ecdh()}); }),
      CHECK("hybrid KEX/KEM key", [&](auto& result) { roundtrip_test(result, {kex_dh(), kem()}); }),
   };
}

void kex_to_kem_roundtrip(Test::Result& result, std::unique_ptr<Botan::PK_Key_Agreement_Key> kex_private_key) {
   const Botan::KEX_to_KEM_Adapter_PublicKey kexkem_public_key(kex_private_key->public_key());
   const Botan::KEX_to_KEM_Adapter_PrivateKey kexkem_key(std::move(kex_private_key));

   auto& rng = global_test_rng();

   Botan::PK_KEM_Encryptor encryptor(kexkem_public_key, "Raw");
   const auto kem_result = encryptor.encrypt(rng);

   result.test_sz_eq("ciphertext has expected length",
                     kem_result.encapsulated_shared_key().size(),
                     encryptor.encapsulated_key_length());
   result.test_sz_eq(
      "shared secret has expected length", kem_result.shared_key().size(), encryptor.shared_key_length(0));

   Botan::PK_KEM_Decryptor decryptor(kexkem_key, rng, "Raw");

   result.test_sz_eq("encapsulated length matches the decryptor's expectation",
                     kem_result.encapsulated_shared_key().size(),
                     decryptor.encapsulated_key_length());

   Botan::secure_vector<uint8_t> decaps_shared_secret = decryptor.decrypt(kem_result.encapsulated_shared_key(), 0, {});

   result.test_sz_eq(
      "decapsulated shared secret has expected length", decaps_shared_secret.size(), decryptor.shared_key_length(0));

   result.test_bin_eq("shared secret after KEM roundtrip matches", decaps_shared_secret, kem_result.shared_key());
}

std::vector<Test::Result> kex_to_kem_adapter() {
   return {
      Botan_Tests::CHECK("handles nullptr",
                         [](auto& result) {
                            result.test_throws("private KEM adapter handles nullptr",
                                               [] { Botan::KEX_to_KEM_Adapter_PrivateKey(nullptr); });
                            result.test_throws("public KEM adapter handles nullptr",
                                               [] { Botan::KEX_to_KEM_Adapter_PublicKey(nullptr); });
                         }),

      Botan_Tests::CHECK("handles non-KEX keys",
                         [](auto& result) {
                            result.test_throws("public KEM adapter does not work with KEM keys",
                                               [] { Botan::KEX_to_KEM_Adapter_PublicKey{kem()}; });
                         }),

      CHECK("Diffie-Hellman roundtrip", [](auto& result) { kex_to_kem_roundtrip(result, kex_dh()); }),
      CHECK("ECDH roundtrip", [](auto& result) { kex_to_kem_roundtrip(result, kex_ecdh()); }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tls", "tls_hybrid_kem_keypair", hybrid_kem_keypair, kex_to_kem_adapter);

}  // namespace Botan_Tests

#endif
