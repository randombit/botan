/*
 * Tests for Crystals Kyber
 * - simple roundtrip test
 * - KAT tests using the KAT vectors from
 *   https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/Kyber-Round3.zip
 *
 * (C) 2021-2024 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 * (C) 2023-2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "test_pubkey_pqc.h"
#include "test_rng.h"
#include "tests.h"

#include <cmath>
#include <iterator>
#include <memory>

#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S) || defined(BOTAN_HAS_ML_KEM)
   #include "test_pubkey.h"
   #include <botan/hex.h>
   #include <botan/kyber.h>
   #include <botan/pubkey.h>
   #include <botan/rng.h>
   #include <botan/internal/fmt.h>
   #include <botan/internal/kyber_constants.h>
   #include <botan/internal/kyber_helpers.h>
   #include <botan/internal/stl_util.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S) || defined(BOTAN_HAS_ML_KEM)

class KYBER_Tests final : public Test {
   public:
      static Test::Result run_kyber_test(const char* test_name, Botan::KyberMode mode, size_t strength, size_t psid) {
         Test::Result result(test_name);

         if(!mode.is_available()) {
            result.note_missing(mode.to_string());
            return result;
         }

         auto rng = Test::new_rng(test_name);

         const std::vector<uint8_t> empty_salt;

         // Alice
         const Botan::Kyber_PrivateKey priv_key(*rng, mode);
         const auto pub_key = priv_key.public_key();

         result.test_eq("estimated strength private", priv_key.estimated_strength(), strength);
         result.test_eq("estimated strength public", pub_key->estimated_strength(), strength);
         result.test_eq("canonical parameter set identifier", priv_key.key_length(), psid);
         result.test_eq("canonical parameter set identifier", pub_key->key_length(), psid);

         // Serialize
         const auto priv_key_bits = priv_key.private_key_bits();
         const auto pub_key_bits = pub_key->public_key_bits();

         // Bob (reading from serialized public key)
         Botan::Kyber_PublicKey alice_pub_key(pub_key_bits, mode);
         auto enc = Botan::PK_KEM_Encryptor(alice_pub_key, "Raw", "base");
         const auto kem_result = enc.encrypt(*rng);

         // Alice (reading from serialized private key)
         Botan::Kyber_PrivateKey alice_priv_key(priv_key_bits, mode);
         auto dec = Botan::PK_KEM_Decryptor(alice_priv_key, *rng, "Raw", "base");
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
         return {
            run_kyber_test("Kyber512_90s API", Botan::KyberMode::Kyber512_90s, 128, 512),
            run_kyber_test("Kyber768_90s API", Botan::KyberMode::Kyber768_90s, 192, 768),
            run_kyber_test("Kyber1024_90s API", Botan::KyberMode::Kyber1024_90s, 256, 1024),
            run_kyber_test("Kyber512 API", Botan::KyberMode::Kyber512_R3, 128, 512),
            run_kyber_test("Kyber768 API", Botan::KyberMode::Kyber768_R3, 192, 768),
            run_kyber_test("Kyber1024 API", Botan::KyberMode::Kyber1024_R3, 256, 1024),
            run_kyber_test("ML-KEM-512 API", Botan::KyberMode::ML_KEM_512, 128, 512),
            run_kyber_test("ML-KEM-768 API", Botan::KyberMode::ML_KEM_768, 192, 768),
            run_kyber_test("ML-KEM-1024 API", Botan::KyberMode::ML_KEM_1024, 256, 1024),
         };
      }
};

BOTAN_REGISTER_TEST("pubkey", "kyber_pairwise", KYBER_Tests);

namespace {

class Kyber_KAT_Tests : public PK_PQC_KEM_KAT_Test {
   protected:
      Kyber_KAT_Tests(const std::string& algo_name,
                      const std::string& kat_file,
                      const std::string& further_optional_keys = "") :
            PK_PQC_KEM_KAT_Test(algo_name, kat_file, further_optional_keys) {}

   private:
      Botan::KyberMode get_mode(const std::string& mode) const { return Botan::KyberMode(mode); }

      bool is_available(const std::string& mode) const final { return get_mode(mode).is_available(); }

      std::vector<uint8_t> map_value(const std::string& mode,
                                     std::span<const uint8_t> value,
                                     VarType var_type) const final {
         if(var_type == VarType::SharedSecret) {
            return {value.begin(), value.end()};
         }

         // We use different hash functions for Kyber 90s, as those are
         // consistent with the algorithm requirements of the implementations.
         std::string_view hash_name = get_mode(mode).is_90s() ? "SHA-256" : "SHAKE-256(128)";

         auto hash = Botan::HashFunction::create_or_throw(hash_name);
         const auto digest = hash->process(value);
         return {digest.begin(), digest.begin() + 16};
      }

      Fixed_Output_RNG rng_for_keygen(const std::string& mode, Botan::RandomNumberGenerator& rng) const final {
         if(get_mode(mode).is_kyber_round3()) {
            const auto seed = rng.random_vec(32);
            const auto z = rng.random_vec(32);
            return Fixed_Output_RNG(Botan::concat(seed, z));
         } else if(get_mode(mode).is_ml_kem()) {
            const auto z = rng.random_vec(32);
            const auto d = rng.random_vec(32);
            return Fixed_Output_RNG(Botan::concat(d, z));
         } else {
            return Fixed_Output_RNG(rng.random_vec(64));
         }
      }

      Fixed_Output_RNG rng_for_encapsulation(const std::string&, Botan::RandomNumberGenerator& rng) const final {
         return Fixed_Output_RNG(rng.random_vec(32));
      }
};

class KyberR3_KAT_Tests : public Kyber_KAT_Tests {
   public:
      KyberR3_KAT_Tests() : Kyber_KAT_Tests("Kyber", "pubkey/kyber_kat.vec") {}
};

class ML_KEM_KAT_Tests : public Kyber_KAT_Tests {
   public:
      ML_KEM_KAT_Tests() : Kyber_KAT_Tests("ML-KEM", "pubkey/ml_kem.vec", "CT_N,SS_N") {}
};

class ML_KEM_ACVP_KAT_KeyGen_Tests : public PK_PQC_KEM_ACVP_KAT_KeyGen_Test {
   public:
      ML_KEM_ACVP_KAT_KeyGen_Tests() :
            PK_PQC_KEM_ACVP_KAT_KeyGen_Test("ML-KEM", "pubkey/ml_kem_acvp_keygen.vec", "Z,D") {}

   private:
      Botan::KyberMode get_mode(const std::string& mode) const { return Botan::KyberMode(mode); }

      bool is_available(const std::string& mode) const final { return get_mode(mode).is_available(); }

      Fixed_Output_RNG rng_for_keygen(const VarMap& vars) const override {
         const auto d = vars.get_req_bin("D");
         const auto z = vars.get_req_bin("Z");
         return Fixed_Output_RNG(Botan::concat(d, z));
      }
};

class ML_KEM_PQC_KEM_ACVP_KAT_Encap_Test : public PK_PQC_KEM_ACVP_KAT_Encap_Test {
   public:
      ML_KEM_PQC_KEM_ACVP_KAT_Encap_Test() : PK_PQC_KEM_ACVP_KAT_Encap_Test("ML-KEM", "pubkey/ml_kem_acvp_encap.vec") {}

   private:
      Botan::KyberMode get_mode(const std::string& mode) const { return Botan::KyberMode(mode); }

      bool is_available(const std::string& mode) const final { return get_mode(mode).is_available(); }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars, const std::string& mode) const final {
         return std::make_unique<Botan::Kyber_PublicKey>(vars.get_req_bin("EK"), get_mode(mode));
      }
};

}  // namespace

BOTAN_REGISTER_TEST("pubkey", "kyber_kat", KyberR3_KAT_Tests);
BOTAN_REGISTER_TEST("pubkey", "ml_kem_kat", ML_KEM_KAT_Tests);
BOTAN_REGISTER_TEST("pubkey", "ml_kem_acvp_kat_keygen", ML_KEM_ACVP_KAT_KeyGen_Tests);
BOTAN_REGISTER_TEST("pubkey", "ml_kem_acvp_kat_encap", ML_KEM_PQC_KEM_ACVP_KAT_Encap_Test);

// Currently we cannot use the ACVP decapsulation tests because they do not
// provide the private key's seed values.
//BOTAN_REGISTER_TEST("pubkey", "ml_kem_acvp_kat_decap", ML_KEM_PQC_KEM_ACVP_KAT_Decap_Test);

class Kyber_Encoding_Test : public Text_Based_Test {
   public:
      Kyber_Encoding_Test() : Text_Based_Test("pubkey/kyber_encodings.vec", "PrivateRaw,PublicRaw", "Error") {}

   public:
      bool skip_this_test(const std::string& algo_name, const VarMap& /*vars*/) override {
         return !Botan::KyberMode(algo_name).is_available();
      }

      Test::Result run_one_test(const std::string& algo_name, const VarMap& vars) override {
         Test::Result result("kyber_encodings");

         const auto mode = Botan::KyberMode(algo_name);
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
            result.test_eq("pk's encoding of pk", pkr->public_key_bits(), pk_raw);

            // expanded vs seed encoding
            if(skr->private_key_format() == Botan::MlPrivateKeyFormat::Seed) {
               result.test_eq("sk's seed encoding of sk",
                              skr->private_key_bits_with_format(Botan::MlPrivateKeyFormat::Seed),
                              sk_raw);
               const auto skr_expanded = std::make_unique<Botan::Kyber_PrivateKey>(
                  skr->private_key_bits_with_format(Botan::MlPrivateKeyFormat::Expanded), mode);
               result.test_eq("sk's expanded encoding consistency",
                              skr->private_key_bits_with_format(Botan::MlPrivateKeyFormat::Expanded),
                              skr_expanded->private_key_bits_with_format(Botan::MlPrivateKeyFormat::Expanded));
               result.test_throws<Botan::Encoding_Error>("expect no seed in expanded sk", [&] {
                  skr_expanded->private_key_bits_with_format(Botan::MlPrivateKeyFormat::Seed);
               });

               const auto encapsulation = Botan::PK_KEM_Encryptor(*pkr, "Raw").encrypt(rng());
               result.test_eq(
                  "expanded sk decapsulation",
                  Botan::PK_KEM_Decryptor(*skr_expanded, rng(), "Raw").decrypt(encapsulation.encapsulated_shared_key()),
                  encapsulation.shared_key());

            } else {
               result.test_eq("sk's expanded encoding of sk",
                              skr->private_key_bits_with_format(Botan::MlPrivateKeyFormat::Expanded),
                              sk_raw);
            }
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "kyber_encodings", Kyber_Encoding_Test);

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
   #if defined(BOTAN_HAS_ML_KEM)
               "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
   #endif
         };
      }

      std::string algo_name(std::string_view param) const override {
         if(param.starts_with("Kyber-")) {
            return "Kyber";
         } else {
            return "ML-KEM";
         }
      }

      std::string algo_name() const override { throw Test_Error("No default algo name set for Kyber"); }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view keygen_params,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> raw_pk) const override {
         return std::make_unique<Botan::Kyber_PublicKey>(raw_pk, Botan::KyberMode(keygen_params));
      }
};

BOTAN_REGISTER_TEST("pubkey", "kyber_keygen", Kyber_Keygen_Tests);

namespace {

template <size_t d>
void test_compress(Test::Result& res) {
   using namespace Botan;
   constexpr auto q = KyberConstants::Q;

   res.start_timer();

   for(uint16_t x = 0; x < q; ++x) {
      const uint32_t c = Kyber_Algos::compress<d>(x);
      constexpr auto twotothed = (uint32_t(1) << d);
      const auto e = ((twotothed * x + (q / 2)) / q) % twotothed;

      if(c != e) {
         res.test_failure(fmt("compress<{}>({}) = {}; expected {}", d, x, c, e));
         return;
      }
   }

   res.end_timer();
   res.test_success();
}

template <size_t d>
void test_decompress(Test::Result& result) {
   using namespace Botan;
   constexpr auto q = KyberConstants::Q;

   result.start_timer();

   using from_t = std::conditional_t<d <= 8, uint8_t, uint16_t>;
   const from_t twotothed = static_cast<from_t>(from_t(1) << d);

   for(from_t y = 0; y < twotothed; ++y) {
      const uint32_t c = Kyber_Algos::decompress<d>(y);
      const uint32_t e = (q * y + (twotothed / 2)) / twotothed;

      if(c != e) {
         result.test_failure(fmt("decompress<{}>({}) = {}; expected {}", d, static_cast<uint16_t>(y), c, e));
         return;
      }
   }

   result.end_timer();
   result.test_success();
}

template <size_t d>
void test_compress_roundtrip(Test::Result& result) {
   using namespace Botan;
   constexpr auto q = KyberConstants::Q;

   result.start_timer();

   for(uint16_t x = 0; x < q && x < (1 << d); ++x) {
      const uint16_t c = Kyber_Algos::compress<d>(Kyber_Algos::decompress<d>(x));
      if(x != c) {
         result.test_failure(fmt("compress<{}>(decompress<{}>({})) != {}", d, d, x, c));
         return;
      }
   }

   result.end_timer();
   result.test_success();
}

std::vector<Test::Result> test_kyber_helpers() {
   return {
      Botan_Tests::CHECK("compress<1>", [](Test::Result& res) { test_compress<1>(res); }),
      Botan_Tests::CHECK("compress<4>", [](Test::Result& res) { test_compress<4>(res); }),
      Botan_Tests::CHECK("compress<5>", [](Test::Result& res) { test_compress<5>(res); }),
      Botan_Tests::CHECK("compress<10>", [](Test::Result& res) { test_compress<10>(res); }),
      Botan_Tests::CHECK("compress<11>", [](Test::Result& res) { test_compress<11>(res); }),

      Botan_Tests::CHECK("decompress<1>", [](Test::Result& res) { test_decompress<1>(res); }),
      Botan_Tests::CHECK("decompress<4>", [](Test::Result& res) { test_decompress<4>(res); }),
      Botan_Tests::CHECK("decompress<5>", [](Test::Result& res) { test_decompress<5>(res); }),
      Botan_Tests::CHECK("decompress<10>", [](Test::Result& res) { test_decompress<10>(res); }),
      Botan_Tests::CHECK("decompress<11>", [](Test::Result& res) { test_decompress<11>(res); }),

      Botan_Tests::CHECK("compress<1>(decompress())", [](Test::Result& res) { test_compress_roundtrip<1>(res); }),
      Botan_Tests::CHECK("compress<4>(decompress())", [](Test::Result& res) { test_compress_roundtrip<4>(res); }),
      Botan_Tests::CHECK("compress<5>(decompress())", [](Test::Result& res) { test_compress_roundtrip<5>(res); }),
      Botan_Tests::CHECK("compress<10>(decompress())>", [](Test::Result& res) { test_compress_roundtrip<10>(res); }),
      Botan_Tests::CHECK("compress<11>(decompress())>", [](Test::Result& res) { test_compress_roundtrip<11>(res); }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("pubkey", "kyber_helpers", test_kyber_helpers);

#endif

}  // namespace Botan_Tests
