/*
 * Tests for Crystals Kyber
 * - simple roundtrip test
 * - KAT tests using the KAT vectors from
 *   https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/Kyber-Round3.zip
 *
 * (C) 2021-2022 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 * (C) 2023      René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "test_pubkey_pqc.h"
#include "test_rng.h"
#include "tests.h"

#include <iterator>
#include <memory>

#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S)
   #include "test_pubkey.h"
   #include <botan/hex.h>
   #include <botan/kyber.h>
   #include <botan/pubkey.h>
   #include <botan/rng.h>
   #include <botan/internal/fmt.h>
   #include <botan/internal/stl_util.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S)

class KYBER_Tests final : public Test {
   public:
      static Test::Result run_kyber_test(const char* test_name, Botan::KyberMode mode, size_t strength) {
         Test::Result result(test_name);

         const std::vector<uint8_t> empty_salt;

         // Alice
         const Botan::Kyber_PrivateKey priv_key(Test::rng(), mode);
         const auto pub_key = priv_key.public_key();

         result.test_eq("estimated strength private", priv_key.estimated_strength(), strength);
         result.test_eq("estimated strength public", pub_key->estimated_strength(), strength);

         // Serialize
         const auto priv_key_bits = priv_key.private_key_bits();
         const auto pub_key_bits = pub_key->public_key_bits();

         // Bob (reading from serialized public key)
         Botan::Kyber_PublicKey alice_pub_key(pub_key_bits, mode);
         auto enc = Botan::PK_KEM_Encryptor(alice_pub_key, "Raw", "base");
         const auto kem_result = enc.encrypt(Test::rng());

         // Alice (reading from serialized private key)
         Botan::Kyber_PrivateKey alice_priv_key(priv_key_bits, mode);
         auto dec = Botan::PK_KEM_Decryptor(alice_priv_key, Test::rng(), "Raw", "base");
         const auto key_alice = dec.decrypt(kem_result.encapsulated_shared_key(), 0 /* no KDF */, empty_salt);
         result.test_eq("shared secrets are equal", key_alice, kem_result.shared_key());

         //
         // negative tests
         //

         // Broken cipher_text from Alice (wrong length)
         result.test_throws("fail to read cipher_text", "Kyber: unexpected ciphertext length", [&] {
            auto short_cipher_text = kem_result.encapsulated_shared_key();
            short_cipher_text.pop_back();
            dec.decrypt(short_cipher_text, 0, empty_salt);
         });

         // Invalid cipher_text from Alice
         Botan::secure_vector<uint8_t> reverse_cipher_text;
         std::copy(kem_result.encapsulated_shared_key().crbegin(),
                   kem_result.encapsulated_shared_key().crend(),
                   std::back_inserter(reverse_cipher_text));
         const auto key_alice_rev = dec.decrypt(reverse_cipher_text, 0, empty_salt);
         result.confirm("shared secrets are not equal", key_alice != key_alice_rev);

         // Try to decrypt the valid ciphertext again
         const auto key_alice_try2 = dec.decrypt(kem_result.encapsulated_shared_key(), 0 /* no KDF */, empty_salt);
         result.test_eq("shared secrets are equal", key_alice_try2, kem_result.shared_key());

         return result;
      }

      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

   #if defined(BOTAN_HAS_KYBER_90S)
         results.push_back(run_kyber_test("Kyber512_90s API", Botan::KyberMode::Kyber512_90s, 128));
         results.push_back(run_kyber_test("Kyber768_90s API", Botan::KyberMode::Kyber768_90s, 192));
         results.push_back(run_kyber_test("Kyber1024_90s API", Botan::KyberMode::Kyber1024_90s, 256));
   #endif
   #if defined(BOTAN_HAS_KYBER)
         results.push_back(run_kyber_test("Kyber512 API", Botan::KyberMode::Kyber512_R3, 128));
         results.push_back(run_kyber_test("Kyber768 API", Botan::KyberMode::Kyber768_R3, 192));
         results.push_back(run_kyber_test("Kyber1024 API", Botan::KyberMode::Kyber1024_R3, 256));
   #endif

         return results;
      }
};

BOTAN_REGISTER_TEST("kyber", "kyber_pairwise", KYBER_Tests);

namespace {

class Kyber_KAT_Tests_Impl {
   public:
      using public_key_t = Botan::Kyber_PublicKey;
      using private_key_t = Botan::Kyber_PrivateKey;

      static constexpr const char* algo_name = "Kyber";
      static constexpr const char* input_file = "pubkey/kyber_kat.vec";

   public:
      Kyber_KAT_Tests_Impl(std::string_view algo_spec) : m_mode(algo_spec) {}

      decltype(auto) mode() const { return m_mode; }

      bool available() const { return m_mode.is_available(); }

      std::vector<uint8_t> map_value(std::span<const uint8_t> value) const {
         // We use different hash functions for Kyber 90s and Kyber "modern", as
         // those are consistent with the requirements of the implementations.
         std::string_view hash_name = m_mode.is_modern() ? "SHAKE-256(128)" : "SHA-256";

         auto hash = Botan::HashFunction::create_or_throw(hash_name);
         const auto digest = hash->process(value);
         return {digest.begin(), digest.begin() + 16};
      }

      auto rng_for_keygen(Botan::RandomNumberGenerator& rng) const {
         const auto seed = rng.random_vec(32);
         const auto z = rng.random_vec(32);
         return Fixed_Output_RNG(Botan::concat(seed, z));
      }

      auto rng_for_encapsulation(Botan::RandomNumberGenerator& rng) const {
         return Fixed_Output_RNG(rng.random_vec(32));
      }

   private:
      Botan::KyberMode m_mode;
};

class Kyber_KAT_Tests : public Botan_Tests::PK_PQC_KEM_KAT_Test<Kyber_KAT_Tests_Impl> {};

}  // namespace

BOTAN_REGISTER_TEST("kyber", "kyber_kat", Kyber_KAT_Tests);

class Kyber_Encoding_Test : public Text_Based_Test {
   public:
      Kyber_Encoding_Test() : Text_Based_Test("pubkey/kyber_encodings.vec", "PrivateRaw,PublicRaw", "Error") {}

   private:
      static Botan::KyberMode name_to_mode(const std::string& algo_name) {
         if(algo_name == "Kyber-512-r3") {
            return Botan::KyberMode::Kyber512_R3;
         }
         if(algo_name == "Kyber-512-90s-r3") {
            return Botan::KyberMode::Kyber512_90s;
         }
         if(algo_name == "Kyber-768-r3") {
            return Botan::KyberMode::Kyber768_R3;
         }
         if(algo_name == "Kyber-768-90s-r3") {
            return Botan::KyberMode::Kyber768_90s;
         }
         if(algo_name == "Kyber-1024-r3") {
            return Botan::KyberMode::Kyber1024_R3;
         }
         if(algo_name == "Kyber-1024-90s-r3") {
            return Botan::KyberMode::Kyber1024_90s;
         }

         throw Botan::Invalid_Argument("don't know kyber mode: " + algo_name);
      }

   public:
      bool skip_this_test(const std::string& algo_name, const VarMap& /*vars*/) override {
         const auto mode = name_to_mode(algo_name);
   #if defined(BOTAN_HAS_KYBER)
         if(!mode.is_90s()) {
            return false;
         }
   #endif
   #if defined(BOTAN_HAS_KYBER_90S)
         if(mode.is_90s()) {
            return false;
         }
   #endif

         BOTAN_UNUSED(algo_name, mode);
         return true;
      }

      Test::Result run_one_test(const std::string& algo_name, const VarMap& vars) override {
         Test::Result result("kyber_encodings");

         const auto mode = name_to_mode(algo_name);

         const auto pk_raw = Botan::hex_decode(vars.get_req_str("PublicRaw"));
         const auto sk_raw = Botan::hex_decode_locked(vars.get_req_str("PrivateRaw"));
         const auto error = vars.get_opt_str("Error", "");

         if(!error.empty()) {
            // negative tests

            result.test_throws("failing decoding", error, [&] {
               if(!sk_raw.empty()) {
                  Botan::Kyber_PrivateKey(sk_raw, mode);
               }
               if(!pk_raw.empty()) {
                  Botan::Kyber_PublicKey(pk_raw, mode);
               }
            });

            return result;
         } else {
            const auto skr = std::make_unique<Botan::Kyber_PrivateKey>(sk_raw, mode);
            const auto pkr = std::make_unique<Botan::Kyber_PublicKey>(pk_raw, mode);

            result.test_eq("sk's encoding of pk", skr->public_key_bits(), pk_raw);
            result.test_eq("sk's encoding of sk", skr->private_key_bits(), sk_raw);
            result.test_eq("pk's encoding of pk", skr->public_key_bits(), pk_raw);
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("kyber", "kyber_encodings", Kyber_Encoding_Test);

class Kyber_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override {
         return {
   #if defined(BOTAN_HAS_KYBER_90S)
            "Kyber-512-90s-r3", "Kyber-768-90s-r3", "Kyber-1024-90s-r3",
   #endif
   #if defined(BOTAN_HAS_KYBER)
               "Kyber-512-r3", "Kyber-768-r3", "Kyber-1024-r3",
   #endif
         };
      }

      std::string algo_name() const override { return "Kyber"; }
};

BOTAN_REGISTER_TEST("kyber", "kyber_keygen", Kyber_Keygen_Tests);
#endif

}  // namespace Botan_Tests
