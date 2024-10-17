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

#if defined(BOTAN_HAS_DILITHIUM_COMMON)
   #include <botan/dilithium.h>
   #include <botan/hash.h>
   #include <botan/pk_algs.h>
   #include <botan/pubkey.h>
   #include <botan/internal/fmt.h>

   #include "test_pubkey.h"
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_DILITHIUM_COMMON) && defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_SHA3)

template <typename DerivedT>
class Dilithium_KAT_Tests : public Text_Based_Test {
   public:
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

         Botan::Dilithium_PrivateKey priv_key(*dilithium_test_rng, DerivedT::mode);

         result.test_eq(
            "generated expected private key hash", sha3_256->process(priv_key.private_key_bits()), ref_sk_hash);

         result.test_eq(
            "generated expected public key hash", sha3_256->process(priv_key.public_key_bits()), ref_pk_hash);

         auto signer = Botan::PK_Signer(priv_key, *dilithium_test_rng, DerivedT::sign_param);
         auto signature = signer.sign_message(ref_msg.data(), ref_msg.size(), *dilithium_test_rng);

         result.test_eq("generated expected signature hash", sha3_256->process(signature), ref_sig_hash);
         if(!ref_sig.empty()) {
            result.test_eq("generated expected signature", signature, ref_sig);
         }

         Botan::Dilithium_PublicKey pub_key(priv_key.public_key_bits(), DerivedT::mode);
         auto verifier = Botan::PK_Verifier(pub_key, "");
         verifier.update(ref_msg.data(), ref_msg.size());
         result.confirm("signature verifies", verifier.check_signature(signature.data(), signature.size()));

         // test validating incorrect wrong signature
         auto mutated_signature = Test::mutate_vec(signature, this->rng());
         result.confirm("invalid signature rejected",
                        !verifier.check_signature(mutated_signature.data(), mutated_signature.size()));

         verifier.update(ref_msg.data(), ref_msg.size());
         result.confirm("signature verifies", verifier.check_signature(signature.data(), signature.size()));

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
            auto verifier = Botan::PK_Verifier(public_key, "");
            verifier.update(msg);
            return verifier.check_signature(signature);
         };

         const std::string msg = "The quick brown fox jumps over the lazy dog.";
         const std::vector<uint8_t> msgvec(msg.data(), msg.data() + msg.size());

         Botan::Dilithium_PrivateKey priv_key(*rng, mode);
         const Botan::Dilithium_PublicKey& pub_key = priv_key;

         result.test_eq("key strength", priv_key.estimated_strength(), strength);
         result.test_eq("key length", priv_key.key_length(), psid);
         result.test_eq("key strength", pub_key.estimated_strength(), strength);
         result.test_eq("key length", pub_key.key_length(), psid);

         const auto sig_before_codec = sign(priv_key, msgvec);

         const auto priv_key_encoded = priv_key.private_key_bits();
         const auto pub_key_encoded = priv_key.public_key_bits();

         Botan::Dilithium_PrivateKey priv_key_decoded(priv_key_encoded, mode);
         Botan::Dilithium_PublicKey pub_key_decoded(pub_key_encoded, mode);

         const auto sig_after_codec = sign(priv_key_decoded, msgvec);

         result.confirm("Pubkey: before,   Sig: before", verify(pub_key, msgvec, sig_before_codec));
         result.confirm("Pubkey: before,   Sig: after", verify(pub_key, msgvec, sig_after_codec));
         result.confirm("Pubkey: after,    Sig: after", verify(pub_key_decoded, msgvec, sig_after_codec));
         result.confirm("Pubkey: after,    Sig: before", verify(pub_key_decoded, msgvec, sig_before_codec));
         result.confirm("Pubkey: recalc'ed Sig: before", verify(priv_key_decoded, msgvec, sig_before_codec));
         result.confirm("Pubkey: recalc'ed Sig: after", verify(priv_key_decoded, msgvec, sig_after_codec));

         auto tampered_msgvec = msgvec;
         tampered_msgvec.front() = 'X';
         result.confirm("Pubkey: before,   Broken Sig: before", !verify(pub_key, tampered_msgvec, sig_before_codec));
         result.confirm("Pubkey: before,   Broken Sig: after", !verify(pub_key, tampered_msgvec, sig_after_codec));
         result.confirm("Pubkey: after,    Broken Sig: after",
                        !verify(pub_key_decoded, tampered_msgvec, sig_after_codec));
         result.confirm("Pubkey: after,    Broken Sig: before",
                        !verify(pub_key_decoded, tampered_msgvec, sig_before_codec));
         result.confirm("Pubkey: recalc'ed Sig: before", !verify(priv_key_decoded, tampered_msgvec, sig_before_codec));
         result.confirm("Pubkey: recalc'ed Sig: after", !verify(priv_key_decoded, tampered_msgvec, sig_after_codec));

         // decoding via generic pk_algs.h
         const auto generic_pubkey_decoded = Botan::load_public_key(pub_key.algorithm_identifier(), pub_key_encoded);
         const auto generic_privkey_decoded =
            Botan::load_private_key(priv_key.algorithm_identifier(), priv_key_encoded);

         result.test_not_null("generic pubkey", generic_pubkey_decoded);
         result.test_not_null("generic privkey", generic_privkey_decoded);

         const auto sig_after_generic_codec = sign(*generic_privkey_decoded, msgvec);

         result.confirm("verification with generic public key",
                        verify(*generic_pubkey_decoded, msgvec, sig_before_codec));
         result.confirm("verification of signature with generic private key",
                        verify(*generic_pubkey_decoded, msgvec, sig_after_generic_codec));
         result.confirm("verification with generic private key",
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

class Dilithium_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override {
         std::vector<std::string> all_instances = {
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
         std::copy_if(all_instances.begin(),
                      all_instances.end(),
                      std::back_inserter(available_instances),
                      [](const std::string& instance) { return Botan::DilithiumMode(instance).is_available(); });
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

}  // namespace Botan_Tests
