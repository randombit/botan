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
   #include <botan/internal/hybrid_public_key.h>
   #include <botan/internal/kex_to_kem_adapter.h>
   #include <botan/internal/stl_util.h>

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
   auto kex_sk = dynamic_cast<Botan::PK_Key_Agreement_Key*>(sk.get());
   if(kex_sk) {
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
   auto kex_sk = dynamic_cast<Botan::PK_Key_Agreement_Key*>(sk.get());
   if(kex_sk) {
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

template <typename... KeyTs>
auto keys(KeyTs... keys) {
   std::vector<std::unique_ptr<Botan::Private_Key>> vec;
   (vec.push_back(std::forward<KeyTs>(keys)), ...);
   return vec;
}

template <typename T>
std::unique_ptr<Botan::Public_Key> as_public_key(T private_key) {
   if constexpr(std::is_same_v<T, std::nullptr_t>) {
      return nullptr;
   } else {
      return private_key->public_key();
   }
}

template <typename... KeyTs>
auto pubkeys(KeyTs... keys) {
   std::vector<std::unique_ptr<Botan::Public_Key>> vec;
   (vec.push_back(as_public_key(std::forward<KeyTs>(keys))), ...);
   return vec;
}

template <typename... Ts>
size_t length_of_hybrid_shared_key(Ts... kex_kem_fn) {
   Botan::overloaded f{[](const Botan::PK_Key_Agreement_Key& kex_key) {
                          Botan::PK_Key_Agreement ka(kex_key, global_test_rng(), "Raw");
                          return ka.agreed_value_size();
                       },
                       [](const Botan::Private_Key& kem_key) {
                          Botan::PK_KEM_Encryptor enc(kem_key, "Raw");
                          return enc.shared_key_length(0);
                       }};

   return (f(*kex_kem_fn()) + ...);
}

template <typename... Ts>
size_t length_of_hybrid_ciphertext(Ts... kex_kem_fn) {
   Botan::overloaded f{[](const Botan::PK_Key_Agreement_Key& kex_key) { return kex_key.public_value().size(); },
                       [](const Botan::Private_Key& kem_key) {
                          Botan::PK_KEM_Encryptor enc(kem_key, "Raw");
                          return enc.encapsulated_key_length();
                       }};

   return (f(*kex_kem_fn()) + ...);
}

template <typename... Ts>
size_t length_of_hybrid_public_value(Ts... kex_kem_fn) {
   Botan::overloaded f{[](const Botan::PK_Key_Agreement_Key& kex_key) { return kex_key.public_value().size(); },
                       [](const Botan::Private_Key& kem_key) { return kem_key.public_key_bits().size(); }};

   return (f(*kex_kem_fn()) + ...);
}

/// Public_Key::key_length()
template <typename... Ts>
size_t key_length_of_hybrid_public_key(Ts... kex_kem_fn) {
   std::vector<size_t> key_lengths = {kex_kem_fn()->key_length()...};
   return *std::max_element(key_lengths.begin(), key_lengths.end());
}

template <typename... Ts>
size_t estimated_strength_of_hybrid_public_key(Ts... kex_kem_fn) {
   std::vector<size_t> strengths = {kex_kem_fn()->estimated_strength()...};
   return *std::max_element(strengths.begin(), strengths.end());
}

template <typename... Ts>
void roundtrip_test(Test::Result& result, Ts... kex_kem_fn) {
   Botan::TLS::Hybrid_KEM_PrivateKey hybrid_key(keys(kex_kem_fn()...));
   Botan::TLS::Hybrid_KEM_PublicKey hybrid_public_key(pubkeys(kex_kem_fn()...));

   auto& rng = global_test_rng();

   Botan::PK_KEM_Encryptor encryptor(hybrid_public_key, "Raw");
   const auto kem_result = encryptor.encrypt(rng);

   const auto expected_shared_secret_length = length_of_hybrid_shared_key(kex_kem_fn...);
   const auto expected_ciphertext_length = length_of_hybrid_ciphertext(kex_kem_fn...);
   const auto expected_public_key_length = length_of_hybrid_public_value(kex_kem_fn...);
   const auto expected_key_length = key_length_of_hybrid_public_key(kex_kem_fn...);
   const auto expected_strength = estimated_strength_of_hybrid_public_key(kex_kem_fn...);

   result.test_eq(
      "ciphertext has expected length", kem_result.encapsulated_shared_key().size(), expected_ciphertext_length);
   result.test_eq("shared secret has expected length", kem_result.shared_key().size(), expected_shared_secret_length);
   result.test_eq(
      "expected length of ciphertext is as expected", encryptor.encapsulated_key_length(), expected_ciphertext_length);
   result.test_eq("shared secret has expected length", encryptor.shared_key_length(0), expected_shared_secret_length);

   Botan::PK_KEM_Decryptor decryptor(hybrid_key, rng, "Raw");
   Botan::secure_vector<uint8_t> decaps_shared_secret = decryptor.decrypt(kem_result.encapsulated_shared_key(), 0, {});

   result.test_eq("shared secret after KEM roundtrip matches", decaps_shared_secret, kem_result.shared_key());
   result.test_eq(
      "expected shared secret has expected length", decryptor.shared_key_length(0), expected_shared_secret_length);
   result.test_eq("shared secret has expected length", decaps_shared_secret.size(), expected_shared_secret_length);

   result.test_eq("public key bits is the sum of its parts",
                  hybrid_public_key.raw_public_key_bits().size(),
                  expected_public_key_length);

   result.test_eq(
      "Public_Key::key_length is the maximum of its parts", hybrid_public_key.key_length(), expected_key_length);
   result.test_eq("Public_Key::estimated_strength is the maximum of its parts",
                  hybrid_public_key.estimated_strength(),
                  expected_strength);
}

std::vector<Test::Result> hybrid_kem_keypair() {
   return {
      Botan_Tests::CHECK("public handles empty list",
                         [](auto& result) {
                            result.test_throws("hybrid KEM key does not accept an empty list of keys", [] {
                               Botan::TLS::Hybrid_KEM_PublicKey(std::vector<std::unique_ptr<Botan::Public_Key>>(0));
                            });
                         }),

      Botan_Tests::CHECK("private handles empty list",
                         [](auto& result) {
                            result.test_throws("hybrid KEM key does not accept an empty list of keys", [] {
                               Botan::TLS::Hybrid_KEM_PrivateKey(std::vector<std::unique_ptr<Botan::Private_Key>>(0));
                            });
                         }),

      CHECK("public key handles nullptr",
            [&](auto& result) {
               result.test_throws("hybrid KEM key does not accept nullptr keys",
                                  [] { Botan::TLS::Hybrid_KEM_PublicKey(pubkeys(nullptr)); });
               result.test_throws("hybrid KEM key does not accept nullptr keys along with KEM",
                                  [&] { Botan::TLS::Hybrid_KEM_PublicKey(pubkeys(nullptr, kem())); });
               result.test_throws("hybrid KEM key does not accept nullptr keys along with KEX",
                                  [&] { Botan::TLS::Hybrid_KEM_PublicKey(pubkeys(nullptr, kex_dh())); });
            }),

      CHECK("private key handles nullptr",
            [&](auto& result) {
               result.test_throws("hybrid KEM key does not accept nullptr keys",
                                  [] { Botan::TLS::Hybrid_KEM_PrivateKey(keys(nullptr)); });
               result.test_throws("hybrid KEM key does not accept nullptr keys along with KEM",
                                  [&] { Botan::TLS::Hybrid_KEM_PrivateKey(keys(nullptr, kem())); });
               result.test_throws("hybrid KEM key does not accept nullptr keys along with KEX",
                                  [&] { Botan::TLS::Hybrid_KEM_PrivateKey(keys(nullptr, kex_dh())); });
            }),

      CHECK("handles incompatible keys (non-KEM, non-KEX)",
            [&](auto& result) {
               result.test_throws("hybrid KEM key does not accept signature keys",
                                  [&] { Botan::TLS::Hybrid_KEM_PrivateKey(keys(sig())); });
               result.test_throws("signature keys aren't allowed along with KEM keys",
                                  [&] { Botan::TLS::Hybrid_KEM_PrivateKey(keys(sig(), kem())); });
               result.test_throws("signature keys aren't allowed along with KEX keys",
                                  [&] { Botan::TLS::Hybrid_KEM_PrivateKey(keys(sig(), kex_dh())); });
            }),

      CHECK("single KEM key",
            [&](auto& result) { result.test_throws("need at least two keys", [&] { roundtrip_test(result, kem); }); }),
      CHECK("dual KEM key", [&](auto& result) { roundtrip_test(result, kem, kem); }),
      CHECK(
         "single KEX key",
         [&](auto& result) { result.test_throws("need at least two keys", [&] { roundtrip_test(result, kex_dh); }); }),
      CHECK("dual KEX key", [&](auto& result) { roundtrip_test(result, kex_dh, kex_ecdh); }),
      CHECK("hybrid KEX/KEM key", [&](auto& result) { roundtrip_test(result, kex_dh, kem); }),
      CHECK("hybrid triple key", [&](auto& result) { roundtrip_test(result, kex_dh, kem, kex_ecdh); }),
   };
}

void kex_to_kem_roundtrip(Test::Result& result,
                          const std::function<std::unique_ptr<Botan::PK_Key_Agreement_Key>()>& kex_fn) {
   Botan::KEX_to_KEM_Adapter_PrivateKey kexkem_key(kex_fn());
   Botan::KEX_to_KEM_Adapter_PublicKey kexkem_public_key(kex_fn());

   auto& rng = global_test_rng();

   Botan::PK_KEM_Encryptor encryptor(kexkem_public_key, "Raw");
   const auto kem_result = encryptor.encrypt(rng);

   result.test_eq("ciphertext has expected length",
                  kem_result.encapsulated_shared_key().size(),
                  encryptor.encapsulated_key_length());
   result.test_eq("shared secret has expected length", kem_result.shared_key().size(), encryptor.shared_key_length(0));

   Botan::PK_KEM_Decryptor decryptor(kexkem_key, rng, "Raw");

   result.test_eq("encapsulated length matches the decryptor's expectation",
                  kem_result.encapsulated_shared_key().size(),
                  decryptor.encapsulated_key_length());

   Botan::secure_vector<uint8_t> decaps_shared_secret = decryptor.decrypt(kem_result.encapsulated_shared_key(), 0, {});

   result.test_eq(
      "decapsulated shared secret has expected length", decaps_shared_secret.size(), decryptor.shared_key_length(0));

   result.test_eq("shared secret after KEM roundtrip matches", decaps_shared_secret, kem_result.shared_key());
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

      CHECK("Diffie-Hellman roundtrip", [](auto& result) { kex_to_kem_roundtrip(result, kex_dh); }),
      CHECK("ECDH roundtrip", [](auto& result) { kex_to_kem_roundtrip(result, kex_ecdh); }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tls", "tls_hybrid_kem_keypair", hybrid_kem_keypair, kex_to_kem_adapter);

}  // namespace Botan_Tests

#endif
