/*
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, Philippe Lieser - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_pubkey.h"
#include "tests.h"

#if defined(BOTAN_HAS_HSS_LMS)

   #include <botan/hss_lms.h>
   #include <botan/pk_algs.h>
   #include <botan/internal/fmt.h>
   #include <botan/internal/hss.h>
   #include <botan/internal/loadstor.h>

namespace Botan_Tests {

namespace {

/**
 * @brief Test the correct parsing of HSS-LMS parameters
 */
std::vector<Test::Result> test_hss_lms_params_parsing() {
   return {
      CHECK("HSS Parameter Parsing",
            [&](Test::Result& result) {
               result.test_no_throw("no throw", [&] {
                  Botan::HSS_LMS_Params hss_params("SHA-256,HW(5,1),HW(25,8)");

                  result.test_is_eq("hss levels", hss_params.L(), Botan::HSS_Level(2));
                  auto& top_lms_params = hss_params.params_at_level(Botan::HSS_Level(0));
                  result.test_is_eq("hash name", top_lms_params.lms_params().hash_name(), std::string("SHA-256"));
                  result.test_is_eq("top level - lms type",
                                    top_lms_params.lms_params().algorithm_type(),
                                    Botan::LMS_Algorithm_Type::SHA256_M32_H5);
                  result.test_is_eq("top level - ots type",
                                    top_lms_params.lmots_params().algorithm_type(),
                                    Botan::LMOTS_Algorithm_Type::SHA256_N32_W1);

                  auto& second_lms_params = hss_params.params_at_level(Botan::HSS_Level(1));
                  result.test_is_eq("2nd level - lms type",
                                    second_lms_params.lms_params().algorithm_type(),
                                    Botan::LMS_Algorithm_Type::SHA256_M32_H25);
                  result.test_is_eq("2nd level - ots type",
                                    second_lms_params.lmots_params().algorithm_type(),
                                    Botan::LMOTS_Algorithm_Type::SHA256_N32_W8);
               });
            }),

   };
}

/**
 * @brief Test signature generation using the raw private key bytes
 */
class HSS_LMS_Signature_Generation_Test final : public PK_Signature_Generation_Test {
   public:
      HSS_LMS_Signature_Generation_Test() :
            PK_Signature_Generation_Test("HSS-LMS", "pubkey/hss_lms_sig.vec", "Msg,PrivateKey,Signature") {}

      std::string default_padding(const VarMap&) const final { return ""; }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) final {
         const auto sk_bytes = Botan::lock(vars.get_req_bin("PrivateKey"));
         return std::make_unique<Botan::HSS_LMS_PrivateKey>(sk_bytes);
      }
};

/**
 * @brief Test signature verification using the raw public key bytes
 */
class HSS_LMS_Signature_Verify_Tests final : public PK_Signature_Verification_Test {
   public:
      HSS_LMS_Signature_Verify_Tests() :
            PK_Signature_Verification_Test("HSS-LMS", "pubkey/hss_lms_verify.vec", "Msg,PublicKey,Signature") {}

      std::string default_padding(const VarMap&) const final { return ""; }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override {
         const std::vector<uint8_t> pk_bytes = vars.get_req_bin("PublicKey");
         return std::make_unique<Botan::HSS_LMS_PublicKey>(pk_bytes);
      }
};

/**
 * @brief Test the correct revocation of invalid signatures
 */
class HSS_LMS_Signature_Verify_Invalid_Tests final : public PK_Signature_NonVerification_Test {
   public:
      HSS_LMS_Signature_Verify_Invalid_Tests() :
            PK_Signature_NonVerification_Test(
               "HSS_LMS", "pubkey/hss_lms_invalid.vec", "Msg,PublicKey,InvalidSignature") {}

      std::string default_padding(const VarMap&) const override { return ""; }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override {
         const std::vector<uint8_t> raw_key = vars.get_req_bin("PublicKey");
         return std::make_unique<Botan::HSS_LMS_PublicKey>(raw_key);
      }
};

/**
 * @brief Test HSS-LMS public key creation
 */
class HSS_LMS_Key_Generation_Test final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const final { return {"SHA-256,HW(10,4),HW(5,8)"}; }

      std::string algo_name() const final { return "HSS-LMS"; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view /* keygen_params */,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> raw_pk) const override {
         return std::make_unique<Botan::HSS_LMS_PublicKey>(raw_pk);
      }
};

/**
 * @brief Test that for manipulated signatures and too short signatures, private keys, and public keys a DecodeError occurs.
 */
class HSS_LMS_Negative_Tests final : public Test {
      Test::Result test_flipped_signature_bits() {
         Test::Result result("HSS-LMS - flipped signature bits");

         auto sk = Botan::create_private_key("HSS-LMS", Test::rng(), "Truncated(SHA-256,192),HW(5,8)");

         Botan::PK_Signer signer(*sk, Test::rng());
         Botan::PK_Verifier verifier(*sk);

         std::vector<uint8_t> mes = {0xde, 0xad, 0xbe, 0xef};

         signer.update(mes);
         auto valid_sig = signer.signature(Test::rng());
         verifier.update(mes);
         result.confirm("Entire signature is valid", verifier.check_signature(valid_sig.data(), valid_sig.size()));
         for(size_t idx = 0; idx < valid_sig.size(); ++idx) {
            auto bad_sig = valid_sig;
            bad_sig.at(idx) ^= 0x80;
            result.test_no_throw(Botan::fmt("Verification does not throw (byte idx {})", idx), [&]() {
               verifier.update(mes);
               bool valid = verifier.check_signature(bad_sig);
               result.confirm(Botan::fmt("Manipulated signature is invalid (byte idx {})", idx), !valid);
            });
         }

         return result;
      }

      Test::Result test_too_short_signature() {
         Test::Result result("HSS-LMS");

         auto sk = Botan::create_private_key("HSS-LMS", Test::rng(), "Truncated(SHA-256,192),HW(5,8)");

         Botan::PK_Signer signer(*sk, Test::rng());
         Botan::PK_Verifier verifier(*sk);

         std::vector<uint8_t> mes = {0xde, 0xad, 0xbe, 0xef};

         signer.update(mes);
         auto valid_sig = signer.signature(Test::rng());
         verifier.update(mes);
         result.confirm("Entire signature is valid", verifier.check_signature(valid_sig.data(), valid_sig.size()));
         for(size_t n = 0; n < valid_sig.size(); ++n) {
            result.test_no_throw("Verification does not throw", [&]() {
               verifier.update(mes);
               bool valid = verifier.check_signature(valid_sig.data(), n);
               result.confirm("Too short signature is invalid", !valid);
            });
         }

         return result;
      }

      Test::Result test_too_short_private_key() {
         Test::Result result("HSS-LMS");

         // HSS_LMS_PublicKey::key_length()
         auto sk = Botan::create_private_key("HSS-LMS", Test::rng(), "Truncated(SHA-256,192),HW(5,8)");

         auto sk_bytes = sk->private_key_bits();
         result.test_no_throw("Entire private key valid", [&]() {
            Botan::HSS_LMS_PrivateKey key(sk_bytes);
            BOTAN_UNUSED(key);
         });
         for(size_t n = 0; n < sk_bytes.size(); ++n) {
            result.test_throws<Botan::Decoding_Error>("Partial private key invalid", [&]() {
               std::span<const uint8_t> partial_key = {sk_bytes.data(), n};
               Botan::HSS_LMS_PrivateKey key(partial_key);
               BOTAN_UNUSED(key);
            });
         }
         return result;
      }

      Test::Result test_too_short_public_key() {
         Test::Result result("HSS-LMS");

         // HSS_LMS_PublicKey::key_length()
         auto sk = Botan::create_private_key("HSS-LMS", Test::rng(), "Truncated(SHA-256,192),HW(5,8)");

         auto sk_bytes = sk->public_key_bits();
         result.test_no_throw("Entire public key valid", [&]() {
            Botan::HSS_LMS_PublicKey key(sk_bytes);
            BOTAN_UNUSED(key);
         });
         for(size_t n = 0; n < sk_bytes.size(); ++n) {
            result.test_throws<Botan::Decoding_Error>("Partial public key invalid", [&]() {
               std::span<const uint8_t> partial_key = {sk_bytes.data(), n};
               Botan::HSS_LMS_PublicKey key(partial_key);
               BOTAN_UNUSED(key);
            });
         }
         return result;
      }

      std::vector<Test::Result> run() final {
         return {test_flipped_signature_bits(),
                 test_too_short_signature(),
                 test_too_short_private_key(),
                 test_too_short_public_key()};
      }
};

/**
 * @brief Test the correct handling of the HSS-LMS private key's state.
 */
class HSS_LMS_Statefulness_Test final : public Test {
      Botan::HSS_LMS_PrivateKey create_private_key_with_idx(uint64_t idx) {
         auto sk = Botan::HSS_LMS_PrivateKey(Test::rng(), "Truncated(SHA-256,192),HW(5,8)");
         auto bytes = sk.private_key_bits();
         // The index is store after the level (uint32_t)
         Botan::store_be(idx, bytes.data() + sizeof(uint32_t));
         return Botan::HSS_LMS_PrivateKey(bytes);
      }

      Test::Result test_sig_changes_state() {
         Test::Result result("HSS-LMS");

         auto sk = Botan::HSS_LMS_PrivateKey(Test::rng(), "Truncated(SHA-256,192),HW(5,8),HW(5,8)");
         Botan::PK_Signer signer(sk, Test::rng());
         std::vector<uint8_t> mes = {0xde, 0xad, 0xbe, 0xef};
         auto sk_bytes_begin = sk.private_key_bits();

         // Tree hights: 5,5 => 2^(5+5) = 1024 signatures available
         const uint64_t expected_total = 1024;
         result.confirm("Fresh key starts with total number of remaining signatures.",
                        sk.remaining_operations() == expected_total);

         // Creating a signature should update the private key's state
         auto sig_0 = signer.sign_message(mes, Test::rng());
         result.confirm(
            "First signature uses index 0.",
            Botan::HSS_Signature::from_bytes_or_throw(sig_0).bottom_sig().q() == Botan::LMS_Tree_Node_Idx(0));

         auto sk_bytes_after_sig = sk.private_key_bits();

         result.confirm("Signature decreases number of remaining signatures.",
                        sk.remaining_operations() == expected_total - 1);
         result.test_ne("Signature updates private key.", sk_bytes_after_sig, sk_bytes_begin);

         auto sig_1 = signer.sign_message(mes, Test::rng());
         result.confirm(
            "Next signature uses the new index.",
            Botan::HSS_Signature::from_bytes_or_throw(sig_1).bottom_sig().q() == Botan::LMS_Tree_Node_Idx(1));

         return result;
      }

      Test::Result test_max_sig_count() {
         Test::Result result("HSS-LMS");

         uint64_t total_sig_count = 32;
         auto sk = create_private_key_with_idx(total_sig_count - 1);

         Botan::PK_Signer signer(sk, Test::rng());
         std::vector<uint8_t> mes = {0xde, 0xad, 0xbe, 0xef};
         auto sk_bytes_begin = sk.private_key_bits();

         result.confirm("One remaining signature.", sk.remaining_operations() == uint64_t(1));
         result.test_no_throw("Use last signature index.", [&]() { signer.sign_message(mes, Test::rng()); });
         result.confirm("No remaining signatures.", sk.remaining_operations() == uint64_t(0));
         result.test_throws("Cannot sign with exhausted key.", [&]() { signer.sign_message(mes, Test::rng()); });
         result.confirm("Still zero remaining signatures.", sk.remaining_operations() == uint64_t(0));

         return result;
      }

      std::vector<Test::Result> run() final { return {test_sig_changes_state(), test_max_sig_count()}; }
};

/**
 * @brief Test APIs not covered by other tests.
 */
class HSS_LMS_Missing_API_Test final : public Test {
      std::vector<Test::Result> run() final {
         Test::Result result("HSS-LMS");

         // HSS_LMS_PublicKey::key_length()
         auto sk = Botan::create_private_key("HSS-LMS", Test::rng(), "SHA-256,HW(10,4)");
         sk->key_length();
         result.test_gt("Public key length must be greater than the simply type information plus I",
                        sk->key_length(),
                        3 * sizeof(uint32_t) + Botan::LMS_IDENTIFIER_LEN);

         // HSS_LMS_Verification_Operation::hash_function()
         Botan::PK_Verifier verifier(*sk);
         result.test_eq("PK_Verifier should report the hash of the key", verifier.hash_function(), "SHA-256");

         // HSS_LMS_PrivateKey::raw_private_key_bits()
         result.test_eq("Our BER and raw encoding is the same", sk->raw_private_key_bits(), sk->private_key_bits());

         // HSS_LMS_Signature_Operation::algorithm_identifier()
         Botan::PK_Signer signer(*sk, Test::rng());
         result.test_is_eq(signer.algorithm_identifier(), sk->algorithm_identifier());

         // HSS_LMS_Signature_Operation::hash_function()
         result.test_eq("PK_Signer should report the hash of the key", signer.hash_function(), "SHA-256");

         return {result};
      }
};

BOTAN_REGISTER_TEST_FN("pubkey", "hss_lms_params_parsing", test_hss_lms_params_parsing);
BOTAN_REGISTER_TEST("pubkey", "hss_lms_sign", HSS_LMS_Signature_Generation_Test);
BOTAN_REGISTER_TEST("pubkey", "hss_lms_verify", HSS_LMS_Signature_Verify_Tests);
BOTAN_REGISTER_TEST("pubkey", "hss_lms_verify_invalid", HSS_LMS_Signature_Verify_Invalid_Tests);
BOTAN_REGISTER_TEST("pubkey", "hss_lms_keygen", HSS_LMS_Key_Generation_Test);
BOTAN_REGISTER_TEST("pubkey", "hss_lms_negative", HSS_LMS_Negative_Tests);
BOTAN_REGISTER_TEST("pubkey", "hss_lms_state", HSS_LMS_Statefulness_Test);
BOTAN_REGISTER_TEST("pubkey", "hss_lms_api", HSS_LMS_Missing_API_Test);

}  // namespace

}  // namespace Botan_Tests

#endif  // BOTAN_HAS_HSS_LMS
