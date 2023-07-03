/*
 * Tests for Crystals Kyber
 * - simple roundtrip test
 * - KAT tests using the KAT vectors from
 *   https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/Kyber-Round3.zip
 *
 * (C) 2021-2022 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

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
         results.push_back(run_kyber_test("Kyber512 API", Botan::KyberMode::Kyber512, 128));
         results.push_back(run_kyber_test("Kyber768 API", Botan::KyberMode::Kyber768, 192));
         results.push_back(run_kyber_test("Kyber1024 API", Botan::KyberMode::Kyber1024, 256));
   #endif

         return results;
      }
};

BOTAN_REGISTER_TEST("kyber", "kyber_pairwise", KYBER_Tests);

   #if defined(BOTAN_HAS_AES)

namespace {

Test::Result check_kyber_kat(const char* test_name,
                             const VarMap& vars,
                             Botan::KyberMode mode,
                             const std::string& algo_name) {
   Test::Result result(test_name);

   // read input from test file
   const auto pk_in = vars.get_req_bin("PK");
   const auto sk_in = vars.get_req_bin("SK");
   const auto ct_in = vars.get_req_bin("CT");
   const auto ss_in = vars.get_req_bin("SS");

   // Kyber test RNG
   CTR_DRBG_AES256 ctr_drbg(vars.get_req_bin("Seed"));

   // Alice
   Botan::Kyber_PrivateKey priv_key(ctr_drbg, mode);
   const auto pub_key = priv_key.public_key();
   result.test_eq("Public Key Output", priv_key.public_key_bits(), pk_in);
   result.test_eq("Secret Key Output", priv_key.private_key_bits(), sk_in);

   // Bob
   auto enc = Botan::PK_KEM_Encryptor(*pub_key, "Raw", "base");
   const auto kem_result = enc.encrypt(ctr_drbg);
   result.test_eq("Cipher-Text Output", kem_result.encapsulated_shared_key(), ct_in);
   result.test_eq("Key B Output", kem_result.shared_key(), ss_in);

   // Alice
   auto dec = Botan::PK_KEM_Decryptor(priv_key, ctr_drbg, "Raw", "base");
   const auto key_alice = dec.decrypt(kem_result.encapsulated_shared_key(), 0 /* no KDF */, std::vector<uint8_t>());
   result.test_eq("Key A Output", key_alice, ss_in);

   // Algorithm identifiers
   result.test_eq("algo name", priv_key.algo_name(), algo_name);
   result.confirm("algo mode", priv_key.mode() == mode);
   result.test_eq("algo id", priv_key.algorithm_identifier().oid().to_formatted_string(), algo_name);

   return result;
}

}  // namespace

      // NOLINTNEXTLINE(*-macro-usage)
      #define REGISTER_KYBER_KAT_TEST(mode)                                                                    \
         class KYBER_KAT_##mode final : public Text_Based_Test {                                               \
            public:                                                                                            \
               KYBER_KAT_##mode() : Text_Based_Test("pubkey/kyber_" #mode ".vec", "Count,Seed,PK,SK,CT,SS") {} \
                                                                                                               \
               Test::Result run_one_test(const std::string& name, const VarMap& vars) override {               \
                  return check_kyber_kat("Kyber_" #mode, vars, Botan::KyberMode::Kyber##mode, name);           \
               }                                                                                               \
         };                                                                                                    \
         BOTAN_REGISTER_TEST("kyber", "kyber_kat_" #mode, KYBER_KAT_##mode)

      #if defined(BOTAN_HAS_KYBER_90S)
REGISTER_KYBER_KAT_TEST(512_90s);
REGISTER_KYBER_KAT_TEST(768_90s);
REGISTER_KYBER_KAT_TEST(1024_90s);
      #endif

      #if defined(BOTAN_HAS_KYBER)
REGISTER_KYBER_KAT_TEST(512);
REGISTER_KYBER_KAT_TEST(768);
REGISTER_KYBER_KAT_TEST(1024);
      #endif

      #undef REGISTER_KYBER_KAT_TEST

   #endif

class Kyber_Encoding_Test : public Text_Based_Test {
   public:
      Kyber_Encoding_Test() : Text_Based_Test("pubkey/kyber_encodings.vec", "PrivateRaw,PublicRaw", "Error") {}

   private:
      static Botan::KyberMode name_to_mode(const std::string& algo_name) {
         if(algo_name == "Kyber-512-r3") {
            return Botan::KyberMode::Kyber512;
         }
         if(algo_name == "Kyber-512-90s-r3") {
            return Botan::KyberMode::Kyber512_90s;
         }
         if(algo_name == "Kyber-768-r3") {
            return Botan::KyberMode::Kyber768;
         }
         if(algo_name == "Kyber-768-90s-r3") {
            return Botan::KyberMode::Kyber768_90s;
         }
         if(algo_name == "Kyber-1024-r3") {
            return Botan::KyberMode::Kyber1024;
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
