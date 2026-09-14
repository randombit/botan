/*
 * Tests for Crystals Dilithium
 * - KAT tests using the KAT vectors from
 *   https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/Dilithium-Round3.zip
 *
 * (C) 2022,2023 Jack Lloyd
 * (C) 2022 Manuel Glaser, Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "test_rng.h"
#include "tests.h"

#include <map>
#include <memory>
#include <vector>

#if defined(BOTAN_HAS_DILITHIUM_COMMON)
   #include <botan/ber_dec.h>
   #include <botan/data_src.h>
   #include <botan/dilithium.h>
   #include <botan/hash.h>
   #include <botan/hex.h>
   #include <botan/module_lattice_keys.h>
   #include <botan/pem.h>
   #include <botan/pk_algs.h>
   #include <botan/pk_keys.h>
   #include <botan/pk_options.h>
   #include <botan/pkcs8.h>
   #include <botan/pubkey.h>

   #include "test_pubkey.h"
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_DILITHIUM_COMMON) && defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_SHA3)

template <typename DerivedT>
class Dilithium_KAT_Tests : public Text_Based_Test {
   public:
      // NOLINTNEXTLINE(*crtp-constructor-accessibility)
      Dilithium_KAT_Tests() : Text_Based_Test(DerivedT::test_vector, "Seed,Msg,HashPk,HashSk,HashSig", "Sig") {}

      Test::Result run_one_test(const std::string& name, const VarMap& vars) override {
         Test::Result result(name);

         // read input from test file
         const auto ref_seed = vars.get_req_bin("Seed");
         const auto ref_msg = vars.get_req_bin("Msg");
         const auto ref_pk_hash = vars.get_req_bin("HashPk");
         const auto ref_sk_hash = vars.get_req_bin("HashSk");
         const auto ref_sig_hash = vars.get_req_bin("HashSig");
         const auto ref_sig = vars.get_opt_bin("Sig");

         auto sha3_256 = Botan::HashFunction::create_or_throw("SHA-3(256)");

         auto dilithium_test_rng = std::make_unique<CTR_DRBG_AES256>(ref_seed);

         const Botan::Dilithium_PrivateKey priv_key(*dilithium_test_rng, DerivedT::mode);

         const auto sk_bytes = priv_key.is_mldsa() ? priv_key.raw_private_key_bits() : priv_key.private_key_bits();
         result.test_bin_eq("generated expected private key hash", sha3_256->process(sk_bytes), ref_sk_hash);

         result.test_bin_eq(
            "generated expected public key hash", sha3_256->process(priv_key.public_key_bits()), ref_pk_hash);

         auto signer = Botan::PK_Signer(priv_key, *dilithium_test_rng, DerivedT::sign_param);
         auto signature = signer.sign_message(ref_msg.data(), ref_msg.size(), *dilithium_test_rng);

         result.test_bin_eq("generated expected signature hash", sha3_256->process(signature), ref_sig_hash);
         if(!ref_sig.empty()) {
            result.test_bin_eq("generated expected signature", signature, ref_sig);
         }

         const Botan::Dilithium_PublicKey pub_key(priv_key.public_key_bits(), DerivedT::mode);
         auto verifier = Botan::PK_Verifier(pub_key, Botan::PK_Signature_Options());
         verifier.update(ref_msg.data(), ref_msg.size());
         result.test_is_true("signature verifies", verifier.check_signature(signature.data(), signature.size()));

         // test validating incorrect wrong signature
         auto mutated_signature = Test::mutate_vec(signature, this->rng());
         result.test_is_true("invalid signature rejected",
                             !verifier.check_signature(mutated_signature.data(), mutated_signature.size()));

         verifier.update(ref_msg.data(), ref_msg.size());
         result.test_is_true("signature verifies", verifier.check_signature(signature.data(), signature.size()));

         return result;
      }
};

   // NOLINTNEXTLINE(*-macro-usage)
   #define REGISTER_DILITHIUM_KAT_TEST(m, rand)                                          \
      class DILITHIUM##m##rand final : public Dilithium_KAT_Tests<DILITHIUM##m##rand> {  \
         public:                                                                         \
            constexpr static auto test_vector = "pubkey/dilithium_" #m "_" #rand ".vec"; \
            constexpr static auto mode = Botan::DilithiumMode::Dilithium##m;             \
            constexpr static auto sign_param = #rand;                                    \
      };                                                                                 \
      BOTAN_REGISTER_TEST("pubkey", "dilithium_kat_" #m "_" #rand, DILITHIUM##m##rand)

   // NOLINTNEXTLINE(*-macro-usage)
   #define REGISTER_ML_DSA_KAT_TEST(m, rand)                                          \
      class ML_DSA##m##rand final : public Dilithium_KAT_Tests<ML_DSA##m##rand> {     \
         public:                                                                      \
            constexpr static auto test_vector = "pubkey/ml-dsa-" #m "_" #rand ".vec"; \
            constexpr static auto mode = Botan::DilithiumMode::ML_DSA_##m;            \
            constexpr static auto sign_param = #rand;                                 \
      };                                                                              \
      BOTAN_REGISTER_TEST("pubkey", "ml-dsa_kat_" #m "_" #rand, ML_DSA##m##rand)

   #if defined(BOTAN_HAS_DILITHIUM)
REGISTER_DILITHIUM_KAT_TEST(4x4, Deterministic);
REGISTER_DILITHIUM_KAT_TEST(6x5, Deterministic);
REGISTER_DILITHIUM_KAT_TEST(8x7, Deterministic);
REGISTER_DILITHIUM_KAT_TEST(4x4, Randomized);
REGISTER_DILITHIUM_KAT_TEST(6x5, Randomized);
REGISTER_DILITHIUM_KAT_TEST(8x7, Randomized);
   #endif

   #if defined(BOTAN_HAS_DILITHIUM_AES)
REGISTER_DILITHIUM_KAT_TEST(4x4_AES, Deterministic);
REGISTER_DILITHIUM_KAT_TEST(6x5_AES, Deterministic);
REGISTER_DILITHIUM_KAT_TEST(8x7_AES, Deterministic);
REGISTER_DILITHIUM_KAT_TEST(4x4_AES, Randomized);
REGISTER_DILITHIUM_KAT_TEST(6x5_AES, Randomized);
REGISTER_DILITHIUM_KAT_TEST(8x7_AES, Randomized);
   #endif

   #if defined(BOTAN_HAS_ML_DSA)
REGISTER_ML_DSA_KAT_TEST(4x4, Deterministic);
REGISTER_ML_DSA_KAT_TEST(6x5, Deterministic);
REGISTER_ML_DSA_KAT_TEST(8x7, Deterministic);
REGISTER_ML_DSA_KAT_TEST(4x4, Randomized);
REGISTER_ML_DSA_KAT_TEST(6x5, Randomized);
REGISTER_ML_DSA_KAT_TEST(8x7, Randomized);
   #endif

class DilithiumRoundtripTests final : public Test {
   public:
      static Test::Result run_roundtrip(
         const char* test_name, Botan::DilithiumMode mode, bool randomized, size_t strength, size_t psid) {
         Test::Result result(test_name);
         if(!mode.is_available()) {
            result.note_missing(mode.to_string());
            return result;
         }

         auto rng = Test::new_rng(test_name);

         auto sign = [randomized, &rng](const auto& private_key, const auto& msg) {
            const std::string param = (randomized) ? "Randomized" : "Deterministic";
            auto signer = Botan::PK_Signer(private_key, *rng, param);
            return signer.sign_message(msg, *rng);
         };

         auto verify = [](const auto& public_key, const auto& msg, const auto& signature) {
            auto verifier = Botan::PK_Verifier(public_key, Botan::PK_Signature_Options());
            verifier.update(msg);
            return verifier.check_signature(signature);
         };

         const std::string msg = "The quick brown fox jumps over the lazy dog.";
         const std::vector<uint8_t> msgvec(msg.data(), msg.data() + msg.size());

         const Botan::Dilithium_PrivateKey priv_key(*rng, mode);
         const Botan::Dilithium_PublicKey& pub_key = priv_key;

         result.test_sz_eq("key strength", priv_key.estimated_strength(), strength);
         result.test_sz_eq("key length", priv_key.key_length(), psid);
         result.test_sz_eq("key strength", pub_key.estimated_strength(), strength);
         result.test_sz_eq("key length", pub_key.key_length(), psid);

         const auto sig_before_codec = sign(priv_key, msgvec);

         const auto priv_key_encoded = priv_key.private_key_bits();
         const auto pub_key_encoded = priv_key.public_key_bits();

         const Botan::Dilithium_PrivateKey priv_key_decoded(priv_key_encoded, mode);
         const Botan::Dilithium_PublicKey pub_key_decoded(pub_key_encoded, mode);

         const auto sig_after_codec = sign(priv_key_decoded, msgvec);

         result.test_is_true("Pubkey: before,   Sig: before", verify(pub_key, msgvec, sig_before_codec));
         result.test_is_true("Pubkey: before,   Sig: after", verify(pub_key, msgvec, sig_after_codec));
         result.test_is_true("Pubkey: after,    Sig: after", verify(pub_key_decoded, msgvec, sig_after_codec));
         result.test_is_true("Pubkey: after,    Sig: before", verify(pub_key_decoded, msgvec, sig_before_codec));
         result.test_is_true("Pubkey: recalc'ed Sig: before", verify(priv_key_decoded, msgvec, sig_before_codec));
         result.test_is_true("Pubkey: recalc'ed Sig: after", verify(priv_key_decoded, msgvec, sig_after_codec));

         auto tampered_msgvec = msgvec;
         tampered_msgvec.front() = 'X';
         result.test_is_true("Pubkey: before,   Broken Sig: before",
                             !verify(pub_key, tampered_msgvec, sig_before_codec));
         result.test_is_true("Pubkey: before,   Broken Sig: after", !verify(pub_key, tampered_msgvec, sig_after_codec));
         result.test_is_true("Pubkey: after,    Broken Sig: after",
                             !verify(pub_key_decoded, tampered_msgvec, sig_after_codec));
         result.test_is_true("Pubkey: after,    Broken Sig: before",
                             !verify(pub_key_decoded, tampered_msgvec, sig_before_codec));
         result.test_is_true("Pubkey: recalc'ed Sig: before",
                             !verify(priv_key_decoded, tampered_msgvec, sig_before_codec));
         result.test_is_true("Pubkey: recalc'ed Sig: after",
                             !verify(priv_key_decoded, tampered_msgvec, sig_after_codec));

         // decoding via generic pk_algs.h
         const auto generic_pubkey_decoded = Botan::load_public_key(pub_key.algorithm_identifier(), pub_key_encoded);
         const auto generic_privkey_decoded =
            Botan::load_private_key(priv_key.algorithm_identifier(), priv_key_encoded);

         result.test_not_null("generic pubkey", generic_pubkey_decoded);
         result.test_not_null("generic privkey", generic_privkey_decoded);

         const auto sig_after_generic_codec = sign(*generic_privkey_decoded, msgvec);

         result.test_is_true("verification with generic public key",
                             verify(*generic_pubkey_decoded, msgvec, sig_before_codec));
         result.test_is_true("verification of signature with generic private key",
                             verify(*generic_pubkey_decoded, msgvec, sig_after_generic_codec));
         result.test_is_true("verification with generic private key",
                             verify(*generic_privkey_decoded, msgvec, sig_before_codec));

         return result;
      }

      std::vector<Test::Result> run() override {
         return {
            run_roundtrip("Dilithium_4x4_Common", Botan::DilithiumMode::Dilithium4x4, false, 128, 44),
            run_roundtrip("Dilithium_6x5_Common", Botan::DilithiumMode::Dilithium6x5, false, 192, 65),
            run_roundtrip("Dilithium_8x7_Common", Botan::DilithiumMode::Dilithium8x7, false, 256, 87),
            run_roundtrip("Dilithium_4x4_Common_Randomized", Botan::DilithiumMode::Dilithium4x4, true, 128, 44),
            run_roundtrip("Dilithium_6x5_Common_Randomized", Botan::DilithiumMode::Dilithium6x5, true, 192, 65),
            run_roundtrip("Dilithium_8x7_Common_Randomized", Botan::DilithiumMode::Dilithium8x7, true, 256, 87),
            run_roundtrip("Dilithium_4x4_AES", Botan::DilithiumMode::Dilithium4x4_AES, false, 128, 44),
            run_roundtrip("Dilithium_6x5_AES", Botan::DilithiumMode::Dilithium6x5_AES, false, 192, 65),
            run_roundtrip("Dilithium_8x7_AES", Botan::DilithiumMode::Dilithium8x7_AES, false, 256, 87),
            run_roundtrip("Dilithium_4x4_AES_Randomized", Botan::DilithiumMode::Dilithium4x4_AES, true, 128, 44),
            run_roundtrip("Dilithium_6x5_AES_Randomized", Botan::DilithiumMode::Dilithium6x5_AES, true, 192, 65),
            run_roundtrip("Dilithium_8x7_AES_Randomized", Botan::DilithiumMode::Dilithium8x7_AES, true, 256, 87),
            run_roundtrip("ML-DSA_4x4", Botan::DilithiumMode::ML_DSA_4x4, false, 128, 44),
            run_roundtrip("ML-DSA_6x5", Botan::DilithiumMode::ML_DSA_6x5, false, 192, 65),
            run_roundtrip("ML-DSA_8x7", Botan::DilithiumMode::ML_DSA_8x7, false, 256, 87),
            run_roundtrip("ML-DSA_4x4_Randomized", Botan::DilithiumMode::ML_DSA_4x4, true, 128, 44),
            run_roundtrip("ML-DSA_6x5_Randomized", Botan::DilithiumMode::ML_DSA_6x5, true, 192, 65),
            run_roundtrip("ML-DSA_8x7_Randomized", Botan::DilithiumMode::ML_DSA_8x7, true, 256, 87),
         };
      }
};

BOTAN_REGISTER_TEST("pubkey", "dilithium_roundtrips", DilithiumRoundtripTests);

/*
* The "salt" option names the size of the randomness drawn during hedged
* signing, which differs between ML-DSA (32 byte rnd) and Dilithium round 3
* (the full 64 byte rho')
*/
class Dilithium_Salt_Size_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("Dilithium salt size option");

         auto check = [&](const std::string& algo, const std::string& mode, size_t expected_salt, size_t wrong_salt) {
            std::unique_ptr<Botan::Private_Key> key;
            try {
               key = Botan::create_private_key(algo, this->rng(), mode);
            } catch(const Botan::Lookup_Error&) {
               /*ignore*/
            } catch(const Botan::Not_Implemented&) {
               /*ignore*/
            }

            if(key == nullptr) {
               result.test_note("Skipping " + mode + " - not available");
               return;
            }

            const auto pub = key->public_key();
            const std::vector<uint8_t> msg = {0x61, 0x62, 0x63};

            result.test_no_throw(mode + " accepts its randomness size as salt", [&] {
               Botan::PK_Signer signer(*key, this->rng(), Botan::PK_Signature_Options().with_salt_size(expected_salt));
               Botan::PK_Verifier verifier(*pub, Botan::PK_Signature_Options().with_salt_size(expected_salt));
               result.test_is_true(mode + " sign/verify",
                                   verifier.verify_message(msg, signer.sign_message(msg, this->rng())));
            });

            result.test_throws(mode + " rejects another salt size", [&] {
               const Botan::PK_Signer signer(
                  *key, this->rng(), Botan::PK_Signature_Options().with_salt_size(wrong_salt));
            });

            result.test_throws(mode + " rejects a salt when deterministic", [&] {
               const Botan::PK_Signer signer(
                  *key,
                  this->rng(),
                  Botan::PK_Signature_Options().with_salt_size(expected_salt).with_deterministic_signature());
            });
         };

         check("ML-DSA", "ML-DSA-4x4", 32, 64);
         check("Dilithium", "Dilithium-4x4-r3", 64, 32);

         return {result};
      }
};

BOTAN_REGISTER_TEST("pubkey", "dilithium_salt_size", Dilithium_Salt_Size_Tests);

class Dilithium_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override {
         const std::vector<std::string> all_instances = {
            "Dilithium-4x4-AES-r3",
            "Dilithium-6x5-AES-r3",
            "Dilithium-8x7-AES-r3",
            "Dilithium-4x4-r3",
            "Dilithium-6x5-r3",
            "Dilithium-8x7-r3",
            "ML-DSA-4x4",
            "ML-DSA-6x5",
            "ML-DSA-8x7",
         };

         std::vector<std::string> available_instances;

         for(const auto& mode : all_instances) {
            if(Botan::DilithiumMode(mode).is_available()) {
               available_instances.push_back(mode);
            }
         }
         return available_instances;
      }

      std::string algo_name(std::string_view param) const override {
         if(param.starts_with("Dilithium-")) {
            return "Dilithium";
         } else {
            return "ML-DSA";
         }
      }

      std::string algo_name() const override { throw Test_Error("No default algo name set for Dilithium"); }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view keygen_params,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> raw_pk) const override {
         return std::make_unique<Botan::Dilithium_PublicKey>(raw_pk, Botan::DilithiumMode(keygen_params));
      }
};

BOTAN_REGISTER_TEST("pubkey", "dilithium_keygen", Dilithium_Keygen_Tests);

#endif

}  // namespace

#if defined(BOTAN_HAS_DILITHIUM_COMMON)

/**
 * Tests the private key format handling (Module_Lattice_PrivateKey interface)
 * with freshly generated keys for all available modes.
 */
class Dilithium_Privkey_Format_Tests final : public Test {
   public:
      static Test::Result run_ml_dsa(const char* test_name, Botan::DilithiumMode mode) {
         Test::Result result(test_name);
         if(!mode.is_available()) {
            result.note_missing(mode.to_string());
            return result;
         }
         using Botan::MlPrivateKeyFormat;
         auto rng = Test::new_rng(test_name);

         const Botan::Dilithium_PrivateKey priv_key(*rng, mode);
         const Botan::Private_Key* generic_key = &priv_key;
         result.test_not_null("ML-DSA key is an ML private key",
                              dynamic_cast<const Botan::Module_Lattice_PrivateKey*>(generic_key));
         result.test_enum_eq(
            "generated ML-DSA key has format Both", priv_key.private_key_format(), MlPrivateKeyFormat::Both);

         const auto seed = priv_key.formatted_raw_private_key_bits(MlPrivateKeyFormat::Seed);
         result.test_sz_eq("seed has 32 bytes", seed.size(), 32);
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
            const Botan::Dilithium_PrivateKey decoded(encoded, mode);
            result.test_enum_eq("format is retained on decoding", decoded.private_key_format(), format);
            result.test_bin_eq("decoded key re-encodes identically", decoded.private_key_bits(), encoded);
            result.test_bin_eq(
               "decoded key has the same public key", decoded.raw_public_key_bits(), priv_key.raw_public_key_bits());
         }

         const auto raw_expanded = priv_key.formatted_raw_private_key_bits(MlPrivateKeyFormat::Expanded);
         const Botan::Dilithium_PrivateKey from_raw_expanded(raw_expanded, mode);
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

         const Botan::Dilithium_PrivateKey from_raw_seed(seed, mode);
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

      static Test::Result run_round3(const char* test_name, Botan::DilithiumMode mode) {
         Test::Result result(test_name);
         if(!mode.is_available()) {
            result.note_missing(mode.to_string());
            return result;
         }
         using Botan::MlPrivateKeyFormat;
         auto rng = Test::new_rng(test_name);

         const Botan::Dilithium_PrivateKey priv_key(*rng, mode);
         result.test_enum_eq(
            "Dilithium round 3 key has format Expanded", priv_key.private_key_format(), MlPrivateKeyFormat::Expanded);
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
         const Botan::Dilithium_PrivateKey decoded(expanded, mode);
         result.test_enum_eq(
            "decoded round 3 key has format Expanded", decoded.private_key_format(), MlPrivateKeyFormat::Expanded);
         result.test_bin_eq("decoded round 3 key re-encodes identically", decoded.private_key_bits(), expanded);

         return result;
      }

      std::vector<Test::Result> run() override {
         return {
            run_ml_dsa("ML-DSA_4x4_formats", Botan::DilithiumMode::ML_DSA_4x4),
            run_ml_dsa("ML-DSA_6x5_formats", Botan::DilithiumMode::ML_DSA_6x5),
            run_ml_dsa("ML-DSA_8x7_formats", Botan::DilithiumMode::ML_DSA_8x7),
            run_round3("Dilithium_4x4_formats", Botan::DilithiumMode::Dilithium4x4),
            run_round3("Dilithium_6x5_formats", Botan::DilithiumMode::Dilithium6x5),
            run_round3("Dilithium_8x7_formats", Botan::DilithiumMode::Dilithium8x7),
            run_round3("Dilithium_4x4_AES_formats", Botan::DilithiumMode::Dilithium4x4_AES),
            run_round3("Dilithium_6x5_AES_formats", Botan::DilithiumMode::Dilithium6x5_AES),
            run_round3("Dilithium_8x7_AES_formats", Botan::DilithiumMode::Dilithium8x7_AES),
         };
      }
};

BOTAN_REGISTER_TEST("pubkey", "dilithium_private_key_formats", Dilithium_Privkey_Format_Tests);

#endif

#if defined(BOTAN_HAS_ML_DSA) && defined(BOTAN_HAS_AES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
class MLDSA_Privkey_Tests : public Test {
   public:
      std::vector<Test::Result> run() override {
         using Botan::MlPrivateKeyFormat;

         // Verbatim private key examples from RFC 9881: Appendix C.1 holds
         // valid keys in all three CHOICE formats, all derived from the seed
         // 000102...1e1f; Appendix C.4 holds keys with inconsistent seed
         // and expanded representations that must be rejected.
         struct TestFile {
               std::string filename;
               std::string algo_name;
               bool valid;
               MlPrivateKeyFormat format;
         };

         const std::vector<TestFile> files{
            {"rfc9881_mldsa44_seed.pem", "ML-DSA-4x4", true, MlPrivateKeyFormat::Seed},
            {"rfc9881_mldsa44_expanded.pem", "ML-DSA-4x4", true, MlPrivateKeyFormat::Expanded},
            {"rfc9881_mldsa44_both.pem", "ML-DSA-4x4", true, MlPrivateKeyFormat::Both},
            {"rfc9881_mldsa65_seed.pem", "ML-DSA-6x5", true, MlPrivateKeyFormat::Seed},
            {"rfc9881_mldsa65_expanded.pem", "ML-DSA-6x5", true, MlPrivateKeyFormat::Expanded},
            {"rfc9881_mldsa65_both.pem", "ML-DSA-6x5", true, MlPrivateKeyFormat::Both},
            {"rfc9881_mldsa87_seed.pem", "ML-DSA-8x7", true, MlPrivateKeyFormat::Seed},
            {"rfc9881_mldsa87_expanded.pem", "ML-DSA-8x7", true, MlPrivateKeyFormat::Expanded},
            {"rfc9881_mldsa87_both.pem", "ML-DSA-8x7", true, MlPrivateKeyFormat::Both},
            {"rfc9881_mldsa44_inconsistent_1.pem", "ML-DSA-4x4", false, MlPrivateKeyFormat::Both},
            {"rfc9881_mldsa44_inconsistent_2.pem", "ML-DSA-4x4", false, MlPrivateKeyFormat::Both},
            {"rfc9881_mldsa44_inconsistent_3.pem", "ML-DSA-4x4", false, MlPrivateKeyFormat::Both},
         };
         /* the same seed is used for all valid test vectors in RFC 9881 */
         const auto rfc_seed = Botan::hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

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

         // The PKCS#8 privateKey field content of the RFC 9881 example key of
         // the given parameter set in the given format.
         auto rfc_private_key_bits = [&](const std::string& algo_name, MlPrivateKeyFormat format) {
            const std::string param_set = algo_name.substr(7, 1) + algo_name.substr(9, 1);  // e.g. "44"
            const std::string filename = "rfc9881_mldsa" + param_set + "_" + format_suffix(format) + ".pem";
            Botan::DataSource_Stream key_source(Test::data_file("pubkey", filename));
            return Botan::PKCS8::load_key(key_source)->private_key_bits();
         };

         std::vector<Test::Result> results;
         std::map<std::string, std::vector<uint8_t>> pubkey_by_mode;

         for(const auto& file : files) {
            Test::Result result("ML-DSA private key " + file.filename);

            std::unique_ptr<Botan::Private_Key> priv_key;
            try {
               Botan::DataSource_Stream key_source(Test::data_file("pubkey", file.filename));
               priv_key = Botan::PKCS8::load_key(key_source);
            } catch(const Botan::Decoding_Error&) {
               result.test_is_true("inconsistent ML-DSA key rejected", !file.valid);
               results.push_back(result);
               continue;
            }
            result.test_is_true("only valid keys are decodable", file.valid);
            if(!file.valid) {
               results.push_back(result);
               continue;
            }

            result.test_str_eq("algorithm name", priv_key->algo_name(), "ML-DSA");
            result.test_str_eq(
               "parameter set", priv_key->algorithm_identifier().oid().to_formatted_string(), file.algo_name);

            const auto* ml_key = dynamic_cast<const Botan::Module_Lattice_PrivateKey*>(priv_key.get());
            if(!result.test_not_null("ML-DSA key is an ML private key", ml_key)) {
               results.push_back(result);
               continue;
            }
            result.test_enum_eq("detected private key format", ml_key->private_key_format(), file.format);

            // The re-encoded PKCS#8 structure must be byte-identical to the RFC example.
            const auto rfc_der =
               Botan::PEM_Code::decode_check_label(Test::read_data_file("pubkey/" + file.filename), "PRIVATE KEY");
            result.test_bin_eq(
               "PKCS#8 re-encoding is identical to the RFC 9881 example", Botan::PKCS8::BER_encode(*priv_key), rfc_der);

            const bool has_seed = file.format != MlPrivateKeyFormat::Expanded;
            if(has_seed) {
               result.test_bin_eq("seed matches the RFC 9881 example seed", priv_key->raw_private_key_bits(), rfc_seed);
               result.test_bin_eq("formatted_raw_private_key_bits(Seed)",
                                  ml_key->formatted_raw_private_key_bits(MlPrivateKeyFormat::Seed),
                                  rfc_seed);
            } else {
               result.test_throws<Botan::Encoding_Error>("no seed available for an expanded-only key", [&] {
                  ml_key->formatted_raw_private_key_bits(MlPrivateKeyFormat::Seed);
               });
               Botan::secure_vector<uint8_t> raw_expanded;
               Botan::BER_Decoder(priv_key->private_key_bits()).decode(raw_expanded, Botan::ASN1_Type::OctetString);
               result.test_bin_eq("raw_private_key_bits() of an expanded-only key is the FIPS 204 key",
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
                  result.test_bin_eq(desc + " matches the RFC 9881 example",
                                     ml_key->formatted_private_key_bits(format),
                                     rfc_private_key_bits(file.algo_name, format));
               } else {
                  result.test_throws<Botan::Encoding_Error>(desc + " fails without seed",
                                                            [&] { ml_key->formatted_private_key_bits(format); });
               }
            }

            std::vector<uint8_t> ref_msg = {0, 1, 2, 4};
            std::vector<uint8_t> rng_seed(48);
            Botan_Tests::CTR_DRBG_AES256 rng(rng_seed);
            auto signer = Botan::PK_Signer(*priv_key, rng, Botan::PK_Signature_Options());
            auto signature = signer.sign_message(ref_msg.data(), ref_msg.size(), rng);

            auto pub_key = priv_key->public_key();
            auto verifier = Botan::PK_Verifier(*pub_key, Botan::PK_Signature_Options());
            verifier.update(ref_msg.data(), ref_msg.size());
            result.test_is_true("signature verifies", verifier.check_signature(signature.data(), signature.size()));

            const auto reencoded_priv_key = Botan::PKCS8::BER_encode(*priv_key);
            Botan::DataSource_Memory reencoded_source(reencoded_priv_key);
            const auto redecoded_priv_key = Botan::PKCS8::load_key(reencoded_source);
            result.test_bin_eq("PKCS#8 encoding roundtrip for private ML-DSA key yields same public key",
                               priv_key->raw_public_key_bits(),
                               redecoded_priv_key->raw_public_key_bits());

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

         // Legacy raw encodings (not RFC 9881 conforming) must still be accepted
         // and are re-encoded in the corresponding RFC 9881 format.
         for(const auto& [algo_name, mode] : {std::pair{"ML-DSA-4x4", Botan::DilithiumMode::ML_DSA_4x4},
                                              std::pair{"ML-DSA-6x5", Botan::DilithiumMode::ML_DSA_6x5},
                                              std::pair{"ML-DSA-8x7", Botan::DilithiumMode::ML_DSA_8x7}}) {
            Test::Result result(std::string("ML-DSA legacy raw private key encodings ") + algo_name);

            const Botan::Dilithium_PrivateKey from_raw_seed(rfc_seed, mode);
            result.test_enum_eq(
               "raw seed is decoded as Seed", from_raw_seed.private_key_format(), MlPrivateKeyFormat::Seed);
            result.test_bin_eq("raw seed re-encodes as RFC 9881 seed format",
                               from_raw_seed.private_key_bits(),
                               rfc_private_key_bits(algo_name, MlPrivateKeyFormat::Seed));

            const auto raw_expanded = from_raw_seed.formatted_raw_private_key_bits(MlPrivateKeyFormat::Expanded);
            const Botan::Dilithium_PrivateKey from_raw_expanded(raw_expanded, mode);
            result.test_enum_eq("raw expanded key is decoded as Expanded",
                                from_raw_expanded.private_key_format(),
                                MlPrivateKeyFormat::Expanded);
            result.test_bin_eq("raw expanded key re-encodes as RFC 9881 expanded format",
                               from_raw_expanded.private_key_bits(),
                               rfc_private_key_bits(algo_name, MlPrivateKeyFormat::Expanded));
            result.test_bin_eq(
               "raw_private_key_bits() of an Expanded key", from_raw_expanded.raw_private_key_bits(), raw_expanded);

            results.push_back(result);
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("pubkey", "mldsa_private_key", MLDSA_Privkey_Tests);

#endif

}  // namespace Botan_Tests
