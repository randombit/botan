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

#include <iterator>
#include <map>
#include <memory>

#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S) || defined(BOTAN_HAS_ML_KEM)
   #include "test_pubkey.h"
   #include <botan/ber_dec.h>
   #include <botan/data_src.h>
   #include <botan/hex.h>
   #include <botan/kyber.h>
   #include <botan/module_lattice_keys.h>
   #include <botan/pem.h>
   #include <botan/pkcs8.h>
   #include <botan/pubkey.h>
   #include <botan/rng.h>
   #include <botan/internal/concat_util.h>
   #include <botan/internal/fmt.h>
   #include <botan/internal/kyber_constants.h>
   #include <botan/internal/kyber_helpers.h>
#endif

namespace Botan_Tests {

namespace {

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

         result.test_sz_eq("estimated strength private", priv_key.estimated_strength(), strength);
         result.test_sz_eq("estimated strength public", pub_key->estimated_strength(), strength);
         result.test_sz_eq("canonical parameter set identifier", priv_key.key_length(), psid);
         result.test_sz_eq("canonical parameter set identifier", pub_key->key_length(), psid);

         // Serialize
         const auto priv_key_bits = priv_key.private_key_bits();
         const auto pub_key_bits = pub_key->public_key_bits();

         // Bob (reading from serialized public key)
         const Botan::Kyber_PublicKey alice_pub_key(pub_key_bits, mode);
         auto enc = Botan::PK_KEM_Encryptor(alice_pub_key, "Raw", "base");
         const auto kem_result = enc.encrypt(*rng);

         // Alice (reading from serialized private key)
         const Botan::Kyber_PrivateKey alice_priv_key(priv_key_bits, mode);
         auto dec = Botan::PK_KEM_Decryptor(alice_priv_key, *rng, "Raw", "base");
         const auto key_alice = dec.decrypt(kem_result.encapsulated_shared_key(), 0 /* no KDF */, empty_salt);
         result.test_bin_eq("shared secrets are equal", key_alice, kem_result.shared_key());

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
         result.test_is_true("shared secrets are not equal", key_alice != key_alice_rev);

         // Try to decrypt the valid ciphertext again
         const auto key_alice_try2 = dec.decrypt(kem_result.encapsulated_shared_key(), 0 /* no KDF */, empty_salt);
         result.test_bin_eq("shared secrets are equal", key_alice_try2, kem_result.shared_key());

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
         const std::string_view hash_name = get_mode(mode).is_90s() ? "SHA-256" : "SHAKE-256(128)";

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

      Fixed_Output_RNG rng_for_encapsulation(const std::string& /*mode*/,
                                             Botan::RandomNumberGenerator& rng) const final {
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

            using Botan::MlPrivateKeyFormat;
            const auto format = skr->private_key_format();

            result.test_bin_eq("sk's encoding of pk", skr->public_key_bits(), pk_raw);
            result.test_bin_eq("sk's raw encoding of sk", skr->raw_private_key_bits(), sk_raw);
            result.test_bin_eq("pk's encoding of pk", pkr->public_key_bits(), pk_raw);

            const Botan::Private_Key* generic_sk = skr.get();
            result.test_not_null("sk is an ML private key",
                                 dynamic_cast<const Botan::Module_Lattice_PrivateKey*>(generic_sk));
            result.test_bin_eq("private_key_bits() uses private_key_format()",
                               skr->private_key_bits(),
                               skr->formatted_private_key_bits(format));
            result.test_bin_eq("raw_private_key_bits() uses private_key_format()",
                               skr->raw_private_key_bits(),
                               skr->formatted_raw_private_key_bits(format));
            result.test_throws<Botan::Encoding_Error>(
               "no raw encoding of Both", [&] { skr->formatted_raw_private_key_bits(MlPrivateKeyFormat::Both); });

            if(mode.is_ml_kem()) {
               // The PKCS#8 content is the RFC 9935 encoding of the raw key
               Botan::secure_vector<uint8_t> unwrapped;
               if(format == MlPrivateKeyFormat::Seed) {
                  Botan::BER_Decoder(skr->private_key_bits())
                     .decode(unwrapped,
                             Botan::ASN1_Type::OctetString,
                             Botan::ASN1_Type(0),
                             Botan::ASN1_Class::ContextSpecific)
                     .verify_end();
               } else {
                  Botan::BER_Decoder(skr->private_key_bits())
                     .decode(unwrapped, Botan::ASN1_Type::OctetString)
                     .verify_end();
               }
               result.test_bin_eq("RFC 9935 encoding wraps the raw key", unwrapped, sk_raw);

               const Botan::Kyber_PrivateKey reloaded(skr->private_key_bits(), mode);
               result.test_enum_eq(
                  "format is retained by the RFC 9935 encoding", reloaded.private_key_format(), format);
               result.test_bin_eq("RFC 9935 encoding round trip", reloaded.raw_private_key_bits(), sk_raw);
            } else {
               result.test_bin_eq("round 3 sk's encoding of sk", skr->private_key_bits(), sk_raw);
               result.test_throws<Botan::Encoding_Error>(
                  "no Both encoding for round 3", [&] { skr->formatted_private_key_bits(MlPrivateKeyFormat::Both); });
            }

            // expanded vs seed encoding
            if(format == MlPrivateKeyFormat::Seed) {
               result.test_is_true("only ML-KEM supports the seed format", mode.is_ml_kem());
               result.test_bin_eq(
                  "sk's seed encoding of sk", skr->formatted_raw_private_key_bits(MlPrivateKeyFormat::Seed), sk_raw);

               const Botan::Kyber_PrivateKey skr_both(skr->formatted_private_key_bits(MlPrivateKeyFormat::Both), mode);
               result.test_enum_eq(
                  "both encoding decodes as Both", skr_both.private_key_format(), MlPrivateKeyFormat::Both);
               result.test_bin_eq("both encoding retains the seed", skr_both.raw_private_key_bits(), sk_raw);

               const auto skr_expanded = std::make_unique<Botan::Kyber_PrivateKey>(
                  skr->formatted_raw_private_key_bits(MlPrivateKeyFormat::Expanded), mode);
               result.test_enum_eq(
                  "expanded sk has format Expanded", skr_expanded->private_key_format(), MlPrivateKeyFormat::Expanded);
               result.test_bin_eq("sk's expanded encoding consistency",
                                  skr->formatted_raw_private_key_bits(MlPrivateKeyFormat::Expanded),
                                  skr_expanded->formatted_raw_private_key_bits(MlPrivateKeyFormat::Expanded));
               result.test_bin_eq("sk's expanded RFC 9935 encoding consistency",
                                  skr->formatted_private_key_bits(MlPrivateKeyFormat::Expanded),
                                  skr_expanded->private_key_bits());
               result.test_throws<Botan::Encoding_Error>("expect no seed in expanded sk", [&] {
                  skr_expanded->formatted_raw_private_key_bits(MlPrivateKeyFormat::Seed);
               });
               result.test_throws<Botan::Encoding_Error>("expect no seed in expanded sk (formatted)", [&] {
                  skr_expanded->formatted_private_key_bits(MlPrivateKeyFormat::Seed);
               });

               const auto encapsulation = Botan::PK_KEM_Encryptor(*pkr, "Raw").encrypt(rng());
               result.test_bin_eq(
                  "expanded sk decapsulation",
                  Botan::PK_KEM_Decryptor(*skr_expanded, rng(), "Raw").decrypt(encapsulation.encapsulated_shared_key()),
                  encapsulation.shared_key());

            } else {
               result.test_bin_eq("sk's expanded encoding of sk",
                                  skr->formatted_raw_private_key_bits(MlPrivateKeyFormat::Expanded),
                                  sk_raw);
               result.test_throws<Botan::Encoding_Error>("expanded-only keys do not support the seed format", [&] {
                  skr->formatted_raw_private_key_bits(MlPrivateKeyFormat::Seed);
               });
            }
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "kyber_encodings", Kyber_Encoding_Test);

/**
 * ML-KEM private key encodings (RFC 9935 CHOICE alternatives and the raw
 * legacy encodings) as content of the PKCS#8 privateKey field: valid vectors
 * must decode to the given format and raw key and re-encode as expected,
 * malformed vectors must be rejected with the given error.
 */
class ML_KEM_Privkey_Encoding_Test final : public Text_Based_Test {
   public:
      ML_KEM_Privkey_Encoding_Test() :
            Text_Based_Test("pubkey/ml_kem_privkey_encodings.vec", "PrivateKey", "Format,PrivateRaw,Encoded,Error") {}

      bool skip_this_test(const std::string& algo_name, const VarMap& /*vars*/) override {
         return !Botan::KyberMode(algo_name).is_available();
      }

      Test::Result run_one_test(const std::string& algo_name, const VarMap& vars) override {
         Test::Result result("ml_kem_privkey_encodings");

         const auto mode = Botan::KyberMode(algo_name);
         const auto sk = Botan::hex_decode_locked(vars.get_req_str("PrivateKey"));
         const auto error = vars.get_opt_str("Error", "");

         if(!error.empty()) {
            result.test_throws("malformed encoding rejected", error, [&] { Botan::Kyber_PrivateKey(sk, mode); });
            return result;
         }

         const auto expected_format = [&]() -> Botan::MlPrivateKeyFormat {
            const auto format = vars.get_req_str("Format");
            if(format == "Seed") {
               return Botan::MlPrivateKeyFormat::Seed;
            }
            if(format == "Expanded") {
               return Botan::MlPrivateKeyFormat::Expanded;
            }
            if(format == "Both") {
               return Botan::MlPrivateKeyFormat::Both;
            }
            throw Test_Error("unknown private key format in test vector: " + format);
         }();
         const auto expected_raw = vars.get_req_bin("PrivateRaw");
         // The raw legacy encodings are re-encoded as the corresponding RFC 9935
         // alternative (given in Encoded), all others re-encode identically.
         const auto expected_encoding = [&]() -> Botan::secure_vector<uint8_t> {
            const auto encoded = vars.get_opt_bin("Encoded");
            return encoded.empty() ? sk : Botan::secure_vector<uint8_t>(encoded.begin(), encoded.end());
         }();

         const Botan::Kyber_PrivateKey skr(sk, mode);
         result.test_enum_eq("detected private key format", skr.private_key_format(), expected_format);
         result.test_bin_eq("raw private key", skr.raw_private_key_bits(), expected_raw);
         result.test_bin_eq("re-encoding in the detected format", skr.private_key_bits(), expected_encoding);

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ml_kem_privkey_encodings", ML_KEM_Privkey_Encoding_Test);

/**
 * Tests the private key format handling (Module_Lattice_PrivateKey interface)
 * with freshly generated keys for all available modes.
 */
class Kyber_Privkey_Format_Tests final : public Test {
   public:
      static Test::Result run_ml_kem(const char* test_name, Botan::KyberMode mode) {
         Test::Result result(test_name);
         if(!mode.is_available()) {
            result.note_missing(mode.to_string());
            return result;
         }
         using Botan::MlPrivateKeyFormat;
         auto rng = Test::new_rng(test_name);

         const Botan::Kyber_PrivateKey priv_key(*rng, mode);
         result.test_enum_eq(
            "generated ML-KEM key has format Both", priv_key.private_key_format(), MlPrivateKeyFormat::Both);

         const auto seed = priv_key.formatted_raw_private_key_bits(MlPrivateKeyFormat::Seed);
         result.test_sz_eq("seed has 64 bytes", seed.size(), 64);
         result.test_bin_eq("raw_private_key_bits() of a Both key is the seed", priv_key.raw_private_key_bits(), seed);
         result.test_throws<Botan::Encoding_Error>(
            "no raw encoding of Both", [&] { priv_key.formatted_raw_private_key_bits(MlPrivateKeyFormat::Both); });

         const auto pkcs8 = Botan::PKCS8::BER_encode(priv_key);
         Botan::DataSource_Memory pkcs8_source(pkcs8);
         const auto reloaded = Botan::PKCS8::load_key(pkcs8_source);
         result.test_bin_eq("PKCS#8 round trip is byte-identical", Botan::PKCS8::BER_encode(*reloaded), pkcs8);
         const auto* reloaded_ml = dynamic_cast<const Botan::Module_Lattice_PrivateKey*>(reloaded.get());
         if(result.test_not_null("reloaded key is an ML private key", reloaded_ml)) {
            result.test_enum_eq(
               "reloaded key has format Both", reloaded_ml->private_key_format(), MlPrivateKeyFormat::Both);
         }

         for(const auto format : {MlPrivateKeyFormat::Seed, MlPrivateKeyFormat::Expanded, MlPrivateKeyFormat::Both}) {
            const auto encoded = priv_key.formatted_private_key_bits(format);
            const Botan::Kyber_PrivateKey decoded(encoded, mode);
            result.test_enum_eq("format is retained on decoding", decoded.private_key_format(), format);
            result.test_bin_eq("decoded key re-encodes identically", decoded.private_key_bits(), encoded);
            result.test_bin_eq(
               "decoded key has the same public key", decoded.raw_public_key_bits(), priv_key.raw_public_key_bits());
         }

         const auto raw_expanded = priv_key.formatted_raw_private_key_bits(MlPrivateKeyFormat::Expanded);
         const Botan::Kyber_PrivateKey from_raw_expanded(raw_expanded, mode);
         result.test_enum_eq("raw expanded key is decoded as Expanded",
                             from_raw_expanded.private_key_format(),
                             MlPrivateKeyFormat::Expanded);
         result.test_bin_eq(
            "raw_private_key_bits() of an Expanded key", from_raw_expanded.raw_private_key_bits(), raw_expanded);
         result.test_bin_eq("private_key_bits() of an Expanded key",
                            from_raw_expanded.private_key_bits(),
                            priv_key.formatted_private_key_bits(MlPrivateKeyFormat::Expanded));
         for(const auto format : {MlPrivateKeyFormat::Seed, MlPrivateKeyFormat::Both}) {
            result.test_throws<Botan::Encoding_Error>("expanded key cannot be encoded with seed (raw)", [&] {
               from_raw_expanded.formatted_raw_private_key_bits(format);
            });
            result.test_throws<Botan::Encoding_Error>("expanded key cannot be encoded with seed",
                                                      [&] { from_raw_expanded.formatted_private_key_bits(format); });
         }

         const Botan::Kyber_PrivateKey from_raw_seed(seed, mode);
         result.test_enum_eq(
            "raw seed is decoded as Seed", from_raw_seed.private_key_format(), MlPrivateKeyFormat::Seed);
         result.test_bin_eq("private_key_bits() of a Seed key",
                            from_raw_seed.private_key_bits(),
                            priv_key.formatted_private_key_bits(MlPrivateKeyFormat::Seed));

         const auto another = priv_key.generate_another(*rng);
         const auto* another_ml = dynamic_cast<const Botan::Module_Lattice_PrivateKey*>(another.get());
         if(result.test_not_null("generate_another() yields an ML private key", another_ml)) {
            result.test_enum_eq(
               "generate_another() yields format Both", another_ml->private_key_format(), MlPrivateKeyFormat::Both);
         }

         return result;
      }

      static Test::Result run_round3(const char* test_name, Botan::KyberMode mode) {
         Test::Result result(test_name);
         if(!mode.is_available()) {
            result.note_missing(mode.to_string());
            return result;
         }
         using Botan::MlPrivateKeyFormat;
         auto rng = Test::new_rng(test_name);

         const Botan::Kyber_PrivateKey priv_key(*rng, mode);
         result.test_enum_eq(
            "Kyber round 3 key has format Expanded", priv_key.private_key_format(), MlPrivateKeyFormat::Expanded);
         const auto expanded = priv_key.private_key_bits();
         result.test_bin_eq("raw_private_key_bits()", priv_key.raw_private_key_bits(), expanded);
         result.test_bin_eq("formatted_raw_private_key_bits(Expanded)",
                            priv_key.formatted_raw_private_key_bits(MlPrivateKeyFormat::Expanded),
                            expanded);
         result.test_bin_eq("formatted_private_key_bits(Expanded)",
                            priv_key.formatted_private_key_bits(MlPrivateKeyFormat::Expanded),
                            expanded);
         for(const auto format : {MlPrivateKeyFormat::Seed, MlPrivateKeyFormat::Both}) {
            result.test_throws<Botan::Encoding_Error>("round 3 key supports only Expanded (raw)",
                                                      [&] { priv_key.formatted_raw_private_key_bits(format); });
            result.test_throws<Botan::Encoding_Error>("round 3 key supports only Expanded",
                                                      [&] { priv_key.formatted_private_key_bits(format); });
         }
         const Botan::Kyber_PrivateKey decoded(expanded, mode);
         result.test_enum_eq(
            "decoded round 3 key has format Expanded", decoded.private_key_format(), MlPrivateKeyFormat::Expanded);
         result.test_bin_eq("decoded round 3 key re-encodes identically", decoded.private_key_bits(), expanded);

         return result;
      }

      std::vector<Test::Result> run() override {
         return {
            run_ml_kem("ML-KEM-512_formats", Botan::KyberMode::ML_KEM_512),
            run_ml_kem("ML-KEM-768_formats", Botan::KyberMode::ML_KEM_768),
            run_ml_kem("ML-KEM-1024_formats", Botan::KyberMode::ML_KEM_1024),
            run_round3("Kyber-512-r3_formats", Botan::KyberMode::Kyber512_R3),
            run_round3("Kyber-768-r3_formats", Botan::KyberMode::Kyber768_R3),
            run_round3("Kyber-1024-r3_formats", Botan::KyberMode::Kyber1024_R3),
            run_round3("Kyber-512-90s-r3_formats", Botan::KyberMode::Kyber512_90s),
            run_round3("Kyber-768-90s-r3_formats", Botan::KyberMode::Kyber768_90s),
            run_round3("Kyber-1024-90s-r3_formats", Botan::KyberMode::Kyber1024_90s),
         };
      }
};

BOTAN_REGISTER_TEST("pubkey", "kyber_private_key_formats", Kyber_Privkey_Format_Tests);

   #if defined(BOTAN_HAS_ML_KEM) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

class MLKEM_Privkey_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         using Botan::MlPrivateKeyFormat;

         // Verbatim private key examples from RFC 9935: Appendix C.1 holds
         // valid keys in all three CHOICE formats, all derived from the seed
         // 000102...3e3f; Appendix C.4 holds keys with inconsistent seed and
         // expanded representations that must be rejected.
         struct TestFile {
               std::string filename;
               std::string algo_name;
               bool valid;
               MlPrivateKeyFormat format;
         };

         const std::vector<TestFile> files{
            {"rfc9935_mlkem512_seed.pem", "ML-KEM-512", true, MlPrivateKeyFormat::Seed},
            {"rfc9935_mlkem512_expanded.pem", "ML-KEM-512", true, MlPrivateKeyFormat::Expanded},
            {"rfc9935_mlkem512_both.pem", "ML-KEM-512", true, MlPrivateKeyFormat::Both},
            {"rfc9935_mlkem768_seed.pem", "ML-KEM-768", true, MlPrivateKeyFormat::Seed},
            {"rfc9935_mlkem768_expanded.pem", "ML-KEM-768", true, MlPrivateKeyFormat::Expanded},
            {"rfc9935_mlkem768_both.pem", "ML-KEM-768", true, MlPrivateKeyFormat::Both},
            {"rfc9935_mlkem1024_seed.pem", "ML-KEM-1024", true, MlPrivateKeyFormat::Seed},
            {"rfc9935_mlkem1024_expanded.pem", "ML-KEM-1024", true, MlPrivateKeyFormat::Expanded},
            {"rfc9935_mlkem1024_both.pem", "ML-KEM-1024", true, MlPrivateKeyFormat::Both},
            // (1) both: seed and expanded key do not match
            {"rfc9935_mlkem512_inconsistent_1.pem", "ML-KEM-512", false, MlPrivateKeyFormat::Both},
            // (2) expanded: mutated s with a valid public key hash (pairwise consistency check)
            {"rfc9935_mlkem512_inconsistent_2.pem", "ML-KEM-512", false, MlPrivateKeyFormat::Expanded},
            // (3) expanded: mutated H(ek) (hash check)
            {"rfc9935_mlkem512_inconsistent_3.pem", "ML-KEM-512", false, MlPrivateKeyFormat::Expanded},
            // (4) both: seed and expanded key differ in z only
            {"rfc9935_mlkem512_inconsistent_4.pem", "ML-KEM-512", false, MlPrivateKeyFormat::Both},
         };
         /* the same seed is used for all valid test vectors in RFC 9935 */
         const auto rfc_seed = Botan::hex_decode(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");

         auto format_suffix = [](MlPrivateKeyFormat format) -> std::string {
            switch(format) {
               case MlPrivateKeyFormat::Seed:
                  return "seed";
               case MlPrivateKeyFormat::Expanded:
                  return "expanded";
               case MlPrivateKeyFormat::Both:
                  return "both";
            }
            throw Test_Error("unknown private key format");
         };

         // The PKCS#8 privateKey field content of the RFC 9935 example key of
         // the given parameter set in the given format.
         auto rfc_private_key_bits = [&](const std::string& algo_name, MlPrivateKeyFormat format) {
            const std::string param_set = algo_name.substr(7);  // e.g. "512"
            const std::string filename = "rfc9935_mlkem" + param_set + "_" + format_suffix(format) + ".pem";
            Botan::DataSource_Stream key_source(Test::data_file("pubkey", filename));
            return Botan::PKCS8::load_key(key_source)->private_key_bits();
         };

         std::vector<Test::Result> results;
         std::map<std::string, std::vector<uint8_t>> pubkey_by_mode;

         for(const auto& file : files) {
            Test::Result result("ML-KEM private key " + file.filename);

            std::unique_ptr<Botan::Private_Key> priv_key;
            try {
               Botan::DataSource_Stream key_source(Test::data_file("pubkey", file.filename));
               priv_key = Botan::PKCS8::load_key(key_source);
            } catch(const Botan::Decoding_Error& e) {
               result.test_is_true(std::string("inconsistent ML-KEM key rejected: ") + e.what(), !file.valid);
               results.push_back(result);
               continue;
            }
            result.test_is_true("only valid keys are decodable", file.valid);
            if(!file.valid) {
               results.push_back(result);
               continue;
            }

            result.test_str_eq("algorithm name", priv_key->algo_name(), "ML-KEM");
            result.test_str_eq(
               "parameter set", priv_key->algorithm_identifier().oid().to_formatted_string(), file.algo_name);

            const auto* ml_key = dynamic_cast<const Botan::Module_Lattice_PrivateKey*>(priv_key.get());
            if(!result.test_not_null("ML-KEM key is an ML private key", ml_key)) {
               results.push_back(result);
               continue;
            }
            result.test_enum_eq("detected private key format", ml_key->private_key_format(), file.format);

            // The re-encoded PKCS#8 structure must be byte-identical to the RFC example.
            const auto rfc_der =
               Botan::PEM_Code::decode_check_label(Test::read_data_file("pubkey/" + file.filename), "PRIVATE KEY");
            result.test_bin_eq(
               "PKCS#8 re-encoding is identical to the RFC 9935 example", Botan::PKCS8::BER_encode(*priv_key), rfc_der);

            const bool has_seed = file.format != MlPrivateKeyFormat::Expanded;
            if(has_seed) {
               result.test_bin_eq("seed matches the RFC 9935 example seed", priv_key->raw_private_key_bits(), rfc_seed);
               result.test_bin_eq("formatted_raw_private_key_bits(Seed)",
                                  ml_key->formatted_raw_private_key_bits(MlPrivateKeyFormat::Seed),
                                  rfc_seed);
            } else {
               result.test_throws<Botan::Encoding_Error>("no seed available for an expanded-only key", [&] {
                  ml_key->formatted_raw_private_key_bits(MlPrivateKeyFormat::Seed);
               });
               Botan::secure_vector<uint8_t> raw_expanded;
               Botan::BER_Decoder(priv_key->private_key_bits()).decode(raw_expanded, Botan::ASN1_Type::OctetString);
               result.test_bin_eq("raw_private_key_bits() of an expanded-only key is the FIPS 203 key",
                                  priv_key->raw_private_key_bits(),
                                  raw_expanded);
               result.test_bin_eq("formatted_raw_private_key_bits(Expanded)",
                                  ml_key->formatted_raw_private_key_bits(MlPrivateKeyFormat::Expanded),
                                  raw_expanded);
            }
            result.test_throws<Botan::Encoding_Error>(
               "no raw encoding of Both", [&] { ml_key->formatted_raw_private_key_bits(MlPrivateKeyFormat::Both); });

            for(const auto format :
                {MlPrivateKeyFormat::Seed, MlPrivateKeyFormat::Expanded, MlPrivateKeyFormat::Both}) {
               const std::string desc = "formatted_private_key_bits(" + format_suffix(format) + ")";
               if(has_seed || format == MlPrivateKeyFormat::Expanded) {
                  result.test_bin_eq(desc + " matches the RFC 9935 example",
                                     ml_key->formatted_private_key_bits(format),
                                     rfc_private_key_bits(file.algo_name, format));
               } else {
                  result.test_throws<Botan::Encoding_Error>(desc + " fails without seed",
                                                            [&] { ml_key->formatted_private_key_bits(format); });
               }
            }

            const auto pub_key = priv_key->public_key();
            const auto encapsulation = Botan::PK_KEM_Encryptor(*pub_key, "Raw").encrypt(this->rng());
            result.test_bin_eq(
               "decapsulation",
               Botan::PK_KEM_Decryptor(*priv_key, this->rng(), "Raw").decrypt(encapsulation.encapsulated_shared_key()),
               encapsulation.shared_key());
            result.test_is_true("check_key", priv_key->check_key(this->rng(), true));

            // All formats of one parameter set derive from the same seed and
            // must therefore agree on the public key.
            auto [it, inserted] = pubkey_by_mode.try_emplace(file.algo_name, priv_key->raw_public_key_bits());
            if(!inserted) {
               result.test_bin_eq("public key matches the other formats of " + file.algo_name,
                                  priv_key->raw_public_key_bits(),
                                  it->second);
            }

            results.push_back(result);
         }

         // Legacy raw encodings (not RFC 9935 conforming) must still be accepted
         // and are re-encoded in the corresponding RFC 9935 format.
         for(const auto& algo_name : {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}) {
            Test::Result result(std::string("ML-KEM legacy raw private key encodings ") + algo_name);
            const Botan::KyberMode mode(algo_name);

            const Botan::Kyber_PrivateKey from_raw_seed(rfc_seed, mode);
            result.test_enum_eq(
               "raw seed is decoded as Seed", from_raw_seed.private_key_format(), MlPrivateKeyFormat::Seed);
            result.test_bin_eq("raw seed re-encodes as RFC 9935 seed format",
                               from_raw_seed.private_key_bits(),
                               rfc_private_key_bits(algo_name, MlPrivateKeyFormat::Seed));

            const auto raw_expanded = from_raw_seed.formatted_raw_private_key_bits(MlPrivateKeyFormat::Expanded);
            const Botan::Kyber_PrivateKey from_raw_expanded(raw_expanded, mode);
            result.test_enum_eq("raw expanded key is decoded as Expanded",
                                from_raw_expanded.private_key_format(),
                                MlPrivateKeyFormat::Expanded);
            result.test_bin_eq("raw expanded key re-encodes as RFC 9935 expanded format",
                               from_raw_expanded.private_key_bits(),
                               rfc_private_key_bits(algo_name, MlPrivateKeyFormat::Expanded));
            result.test_bin_eq(
               "raw_private_key_bits() of an Expanded key", from_raw_expanded.raw_private_key_bits(), raw_expanded);

            results.push_back(result);
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("pubkey", "mlkem_private_key", MLKEM_Privkey_Tests);

   #endif

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

   // NOLINTNEXTLINE(*-redundant-expression)
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

}  // namespace

}  // namespace Botan_Tests
