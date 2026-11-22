/*
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, Philippe Lieser - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_HSS_LMS)
   #include "test_arb_eq.h"
   #include "test_pubkey.h"
   #include <botan/asn1_obj.h>
   #include <botan/der_enc.h>
   #include <botan/exceptn.h>
   #include <botan/hss_lms.h>
   #include <botan/pk_algs.h>
   #include <botan/pk_options.h>
   #include <botan/pkcs8.h>
   #include <botan/pubkey.h>
   #include <botan/rng.h>
   #include <botan/internal/buffer_slicer.h>
   #include <botan/internal/concat_util.h>
   #include <botan/internal/fmt.h>
   #include <botan/internal/hss.h>
   #include <botan/internal/loadstor.h>
   #include <botan/internal/target_info.h>
   #include <limits>
   #include <set>

   #if defined(BOTAN_TARGET_OS_HAS_THREADS)
      #include <future>
   #endif

   #if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
      #include <botan/x509cert.h>
   #endif

   #if defined(BOTAN_TARGET_OS_HAS_POSIX1)
      #include <sys/wait.h>
      #include <unistd.h>
   #endif

namespace Botan_Tests {

namespace {

// Offset of the signature index in the private key encoding, after L
constexpr size_t sk_index_offset = sizeof(uint32_t);

Botan::AlgorithmIdentifier hss_lms_sk_alg_id(std::string_view oid_name) {
   return Botan::AlgorithmIdentifier(Botan::OID::from_string(oid_name), Botan::AlgorithmIdentifier::USE_EMPTY_PARAM);
}

/**
 * @brief Test the correct parsing of HSS-LMS parameters
 */
std::vector<Test::Result> test_hss_lms_params_parsing() {
   return {
      CHECK("HSS Parameter Parsing",
            [&](Test::Result& result) {
               result.test_no_throw("no throw", [&] {
                  const Botan::HSS_LMS_Params hss_params("SHA-256,HW(5,1),HW(25,8)");

                  test_arb_eq(result, "hss levels", hss_params.L(), Botan::HSS_Level(2));
                  const auto& top_lms_params = hss_params.params_at_level(Botan::HSS_Level(0));
                  result.test_str_eq("hash name", top_lms_params.lms_params().hash_name(), "SHA-256");
                  result.test_enum_eq("top level - lms type",
                                      top_lms_params.lms_params().algorithm_type(),
                                      Botan::LMS_Algorithm_Type::SHA256_M32_H5);
                  result.test_enum_eq("top level - ots type",
                                      top_lms_params.lmots_params().algorithm_type(),
                                      Botan::LMOTS_Algorithm_Type::SHA256_N32_W1);

                  const auto& second_lms_params = hss_params.params_at_level(Botan::HSS_Level(1));
                  result.test_enum_eq("2nd level - lms type",
                                      second_lms_params.lms_params().algorithm_type(),
                                      Botan::LMS_Algorithm_Type::SHA256_M32_H25);
                  result.test_enum_eq("2nd level - ots type",
                                      second_lms_params.lmots_params().algorithm_type(),
                                      Botan::LMOTS_Algorithm_Type::SHA256_N32_W8);
               });
            }),

      CHECK("HSS Parameters with inconsistent hash functions",
            [&](Test::Result& result) {
               using Params_Pair = Botan::HSS_LMS_Params::LMS_LMOTS_Params_Pair;

               const Botan::HSS_LMS_Params sha256("SHA-256,HW(5,4)");
               const Botan::HSS_LMS_Params sha192("Truncated(SHA-256,192),HW(5,4)");

               const auto& sha256_lms = sha256.params_at_level(Botan::HSS_Level(0)).lms_params();
               const auto& sha256_lmots = sha256.params_at_level(Botan::HSS_Level(0)).lmots_params();
               const auto& sha192_lms = sha192.params_at_level(Botan::HSS_Level(0)).lms_params();
               const auto& sha192_lmots = sha192.params_at_level(Botan::HSS_Level(0)).lmots_params();

               result.test_no_throw("consistent hash functions are accepted", [&] {
                  const Botan::HSS_LMS_Params params(
                     std::vector<Params_Pair>{{sha256_lms, sha256_lmots}, {sha256_lms, sha256_lmots}});
               });

               result.test_throws<Botan::Invalid_Argument>("different hash functions within a level are rejected", [&] {
                  const Botan::HSS_LMS_Params params(std::vector<Params_Pair>{{sha256_lms, sha192_lmots}});
               });

               result.test_throws<Botan::Invalid_Argument>("different hash functions between levels are rejected", [&] {
                  const Botan::HSS_LMS_Params params(
                     std::vector<Params_Pair>{{sha256_lms, sha256_lmots}, {sha192_lms, sha192_lmots}});
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

      std::string default_padding(const VarMap& /*vars*/) const final { return ""; }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) final {
         const auto sk_bytes = vars.get_req_bin("PrivateKey");
         return std::make_unique<Botan::HSS_LMS_PrivateKey>(Botan::AlgorithmIdentifier(), sk_bytes);
      }
};

/**
 * @brief Test signature verification using the raw public key bytes
 */
class HSS_LMS_Signature_Verify_Tests final : public PK_Signature_Verification_Test {
   public:
      HSS_LMS_Signature_Verify_Tests() :
            PK_Signature_Verification_Test("HSS-LMS", "pubkey/hss_lms_verify.vec", "Msg,PublicKey,Signature") {}

      std::string default_padding(const VarMap& /*vars*/) const final { return ""; }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override {
         const std::vector<uint8_t> pk_bytes = vars.get_req_bin("PublicKey");
         return std::make_unique<Botan::HSS_LMS_PublicKey>(Botan::AlgorithmIdentifier(), pk_bytes);
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

      std::string default_padding(const VarMap& /*vars*/) const override { return ""; }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override {
         const std::vector<uint8_t> raw_key = vars.get_req_bin("PublicKey");
         return std::make_unique<Botan::HSS_LMS_PublicKey>(Botan::AlgorithmIdentifier(), raw_key);
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
         return std::make_unique<Botan::HSS_LMS_PublicKey>(Botan::AlgorithmIdentifier(), raw_pk);
      }
};

/**
 * @brief Test that for manipulated signatures and too short signatures, private keys, and public keys a DecodeError occurs.
 */
class HSS_LMS_Negative_Tests final : public Test {
      Test::Result test_flipped_signature_bits() {
         Test::Result result("HSS-LMS - flipped signature bits");

         const auto sk = Botan::create_private_key("HSS-LMS", Test::rng(), "Truncated(SHA-256,192),HW(5,8)");

         Botan::PK_Signer signer(*sk, Test::rng(), Botan::PK_Signature_Options());
         Botan::PK_Verifier verifier(*sk, Botan::PK_Signature_Options());

         std::vector<uint8_t> mes = {0xde, 0xad, 0xbe, 0xef};

         signer.update(mes);
         auto valid_sig = signer.signature(Test::rng());
         verifier.update(mes);
         result.test_is_true("Entire signature is valid", verifier.check_signature(valid_sig));
         for(size_t idx = 0; idx < valid_sig.size(); ++idx) {
            auto bad_sig = valid_sig;
            bad_sig.at(idx) ^= 0x80;
            result.test_no_throw(Botan::fmt("Verification does not throw (byte idx {})", idx), [&]() {
               verifier.update(mes);
               const bool valid = verifier.check_signature(bad_sig);
               result.test_is_true(Botan::fmt("Manipulated signature is invalid (byte idx {})", idx), !valid);
            });
         }

         return result;
      }

      Test::Result test_too_short_signature() {
         Test::Result result("HSS-LMS");

         const auto sk = Botan::create_private_key("HSS-LMS", Test::rng(), "Truncated(SHA-256,192),HW(5,8)");

         Botan::PK_Signer signer(*sk, Test::rng(), Botan::PK_Signature_Options());
         Botan::PK_Verifier verifier(*sk, Botan::PK_Signature_Options());

         std::vector<uint8_t> mes = {0xde, 0xad, 0xbe, 0xef};

         signer.update(mes);
         auto valid_sig = signer.signature(Test::rng());
         verifier.update(mes);
         result.test_is_true("Entire signature is valid", verifier.check_signature(valid_sig));
         for(size_t n = 0; n < valid_sig.size(); ++n) {
            result.test_no_throw("Verification does not throw", [&]() {
               verifier.update(mes);
               const bool valid = verifier.check_signature(valid_sig.data(), n);
               result.test_is_true("Too short signature is invalid", !valid);
            });
         }

         return result;
      }

      Test::Result test_too_short_private_key() {
         Test::Result result("HSS-LMS");

         // HSS_LMS_PublicKey::key_length()
         auto sk = Botan::create_private_key("HSS-LMS", Test::rng(), "Truncated(SHA-256,192),HW(5,8)");

         // Raw bytes without an OID would accept the legacy format, which is a prefix
         const auto alg_id = sk->pkcs8_algorithm_identifier();
         auto sk_bytes = sk->private_key_bits();
         result.test_no_throw("Entire private key valid", [&]() {
            const Botan::HSS_LMS_PrivateKey key(alg_id, sk_bytes);
            BOTAN_UNUSED(key);
         });
         for(size_t n = 0; n < sk_bytes.size(); ++n) {
            result.test_throws<Botan::Decoding_Error>("Partial private key invalid", [&]() {
               const std::span<const uint8_t> partial_key = {sk_bytes.data(), n};
               const Botan::HSS_LMS_PrivateKey key(alg_id, partial_key);
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
            const Botan::HSS_LMS_PublicKey key(sk_bytes);
            BOTAN_UNUSED(key);
         });
         for(size_t n = 0; n < sk_bytes.size(); ++n) {
            result.test_throws<Botan::Decoding_Error>("Partial public key invalid", [&]() {
               const std::span<const uint8_t> partial_key = {sk_bytes.data(), n};
               const Botan::HSS_LMS_PublicKey key(partial_key);
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
         const auto sk = Botan::HSS_LMS_PrivateKey(Test::rng(), "Truncated(SHA-256,192),HW(5,8)");
         auto bytes = sk.private_key_bits();
         Botan::store_be(idx, bytes.data() + sk_index_offset);
         return Botan::HSS_LMS_PrivateKey(Botan::AlgorithmIdentifier(), bytes);
      }

      Test::Result test_sig_changes_state() {
         Test::Result result("HSS-LMS");

         const auto sk = Botan::HSS_LMS_PrivateKey(Test::rng(), "Truncated(SHA-256,192),HW(5,8),HW(5,8)");
         Botan::PK_Signer signer(sk, Test::rng(), Botan::PK_Signature_Options());
         std::vector<uint8_t> mes = {0xde, 0xad, 0xbe, 0xef};
         auto sk_bytes_begin = sk.private_key_bits();

         // Tree heights: 5,5 => 2^(5+5) = 1024 signatures available
         const uint64_t expected_total = 1024;
         result.test_opt_u64_eq(
            "Fresh key starts with total number of remaining signatures.", sk.remaining_operations(), expected_total);

         // Creating a signature should update the private key's state
         auto sig_0 = signer.sign_message(mes, Test::rng());
         result.test_is_true(
            "First signature uses index 0.",
            Botan::HSS_Signature::from_bytes_or_throw(sig_0).bottom_sig().q() == Botan::LMS_Tree_Node_Idx(0));

         auto sk_bytes_after_sig = sk.private_key_bits();

         result.test_opt_u64_eq(
            "Signature decreases number of remaining signatures.", sk.remaining_operations(), expected_total - 1);
         result.test_bin_ne("Signature updates private key.", sk_bytes_after_sig, sk_bytes_begin);

         auto sig_1 = signer.sign_message(mes, Test::rng());
         result.test_is_true(
            "Next signature uses the new index.",
            Botan::HSS_Signature::from_bytes_or_throw(sig_1).bottom_sig().q() == Botan::LMS_Tree_Node_Idx(1));

         return result;
      }

      Test::Result test_max_sig_count() {
         Test::Result result("HSS-LMS");

         const uint64_t total_sig_count = 32;
         const auto sk = create_private_key_with_idx(total_sig_count - 1);

         Botan::PK_Signer signer(sk, Test::rng(), Botan::PK_Signature_Options());
         std::vector<uint8_t> mes = {0xde, 0xad, 0xbe, 0xef};
         const auto sk_bytes_begin = sk.private_key_bits();

         result.test_opt_u64_eq("One remaining signature.", sk.remaining_operations(), 1);
         result.test_no_throw("Use last signature index.", [&]() { signer.sign_message(mes, Test::rng()); });
         result.test_opt_u64_eq("No remaining signatures.", sk.remaining_operations(), 0);
         result.test_throws("Cannot sign with exhausted key.", [&]() { signer.sign_message(mes, Test::rng()); });
         result.test_opt_u64_eq("Still zero remaining signatures.", sk.remaining_operations(), 0);

         return result;
      }

      Test::Result test_idx_bound_checked_on_load() {
         Test::Result result("HSS-LMS");

         // create_private_key_with_idx uses a single HW(5,8) layer, so the
         // maximum signature count is 32
         result.test_no_throw("Index == max_sig_count is accepted on load", [&]() {
            const auto sk = create_private_key_with_idx(32);
            result.test_opt_u64_eq("Exhausted key loads with no remaining signatures", sk.remaining_operations(), 0);
            Botan::PK_Signer signer(sk, Test::rng(), "");
            const std::vector<uint8_t> mes = {0xde, 0xad, 0xbe, 0xef};
            result.test_throws("Cannot sign with exhausted key", [&]() { signer.sign_message(mes, Test::rng()); });
         });

         result.test_throws<Botan::Decoding_Error>("Index > max_sig_count is rejected on load",
                                                   [&]() { create_private_key_with_idx(33); });

         result.test_throws<Botan::Decoding_Error>("Huge index is rejected on load", [&]() {
            create_private_key_with_idx(std::numeric_limits<uint64_t>::max());
         });

         return result;
      }

      Test::Result test_exhausted_key_stays_exhausted() {
         Test::Result result("HSS-LMS");

         // With a total tree height >= 64 the maximum signature count is
         // clamped to 2^64 - 1, so an index of 2^64 - 1 is accepted on load
         const auto sk =
            Botan::HSS_LMS_PrivateKey(Test::rng(), "Truncated(SHA-256,192),HW(5,8),HW(25,8),HW(25,8),HW(25,8)");
         auto bytes = sk.private_key_bits();
         Botan::store_be(std::numeric_limits<uint64_t>::max(), bytes.data() + sk_index_offset);

         const auto exhausted_sk = Botan::HSS_LMS_PrivateKey(Botan::AlgorithmIdentifier(), bytes);
         result.test_opt_u64_eq("Exhausted key has no remaining signatures", exhausted_sk.remaining_operations(), 0);

         Botan::PK_Signer signer(exhausted_sk, Test::rng(), "");
         const std::vector<uint8_t> mes = {0xde, 0xad, 0xbe, 0xef};

         // A failed signing attempt must not wrap the index back to zero
         result.test_throws("Cannot sign with exhausted key", [&]() { signer.sign_message(mes, Test::rng()); });
         result.test_opt_u64_eq("Failed signing does not reset the state", exhausted_sk.remaining_operations(), 0);
         result.test_throws("Exhausted key stays exhausted", [&]() { signer.sign_message(mes, Test::rng()); });

         return result;
      }

      Test::Result test_params_are_part_of_key_identity() {
         Test::Result result("HSS-LMS");

         const auto sk = Botan::HSS_LMS_PrivateKey(Test::rng(), "Truncated(SHA-256,192),HW(5,8)");
         auto bytes = sk.private_key_bits();

         // Patch the LMOTS algorithm type from SHA256_N24_W8 (0x08) to
         // SHA256_N24_W4 (0x07), pretending the same seed and identifier
         // belong to a key with a different Winternitz parameter
         const size_t lmots_type_lsb = sk_index_offset + sizeof(uint64_t) + 2 * sizeof(uint32_t) - 1;
         result.require("LMOTS type byte has expected value", bytes[lmots_type_lsb] == 0x08);
         bytes[lmots_type_lsb] = 0x07;

         // The index registry tracks the same key material under different
         // parameter sets independently. Nothing can prevent such (insecurely)
         // related keys from issuing overlapping one time signatures.
         const Botan::HSS_LMS_PrivateKey patched(Botan::AlgorithmIdentifier(), bytes);

         Botan::PK_Signer signer(sk, Test::rng(), "");
         const std::vector<uint8_t> mes = {0xde, 0xad, 0xbe, 0xef};
         signer.sign_message(mes, Test::rng());

         result.test_opt_u64_eq("Original key consumed an index", sk.remaining_operations(), 31);
         result.test_opt_u64_eq(
            "Key with the same material but other params is unaffected", patched.remaining_operations(), 32);

         return result;
      }

      Test::Result test_separately_loaded_copies_share_state() {
         Test::Result result("HSS-LMS");

         const auto sk = Botan::HSS_LMS_PrivateKey(Test::rng(), "Truncated(SHA-256,192),HW(5,8)");
         const auto sk_bytes = sk.private_key_bits();

         const Botan::HSS_LMS_PrivateKey copy1(Botan::AlgorithmIdentifier(), sk_bytes);
         const Botan::HSS_LMS_PrivateKey copy2(Botan::AlgorithmIdentifier(), sk_bytes);

         const std::vector<uint8_t> mes = {0xde, 0xad, 0xbe, 0xef};

         Botan::PK_Signer signer1(copy1, Test::rng(), "");
         const auto sig_0 = signer1.sign_message(mes, Test::rng());

         result.test_opt_u64_eq("Signing with one copy is seen by the other", copy2.remaining_operations(), 31);

         Botan::PK_Signer signer2(copy2, Test::rng(), "");
         const auto sig_1 = signer2.sign_message(mes, Test::rng());

         result.test_is_true(
            "First signature uses index 0",
            Botan::HSS_Signature::from_bytes_or_throw(sig_0).bottom_sig().q() == Botan::LMS_Tree_Node_Idx(0));
         result.test_is_true(
            "Second signature uses index 1",
            Botan::HSS_Signature::from_bytes_or_throw(sig_1).bottom_sig().q() == Botan::LMS_Tree_Node_Idx(1));

         return result;
      }

      Test::Result test_unsupported_output_format_rejected() {
         Test::Result result("HSS-LMS DER output format");

         const Botan::HSS_LMS_PrivateKey sk(Test::rng(), "Truncated(SHA-256,192),HW(5,8)");
         Botan::PK_Signer signer(sk, Test::rng(), Botan::PK_Signature_Options());

         result.test_throws<Botan::Invalid_Argument>(
            "DER output format is rejected", [&] { signer.set_output_format(Botan::Signature_Format::DerSequence); });

         const std::vector<uint8_t> mes = {0xde, 0xad, 0xbe, 0xef};
         const auto sig = signer.sign_message(mes, Test::rng());
         result.test_opt_u64_eq("only one index was used", sk.remaining_operations(), 31);

         Botan::PK_Verifier verifier(sk, Botan::PK_Signature_Options());
         result.test_is_true("signature is valid", verifier.verify_message(mes, sig));

         return result;
      }

   #if defined(BOTAN_TARGET_OS_HAS_POSIX1)
      Test::Result test_forked_key_cannot_sign() {
         Test::Result result("HSS-LMS fork safety");

         const Botan::HSS_LMS_PrivateKey sk(Test::rng(), "Truncated(SHA-256,192),HW(5,8)");
         const std::vector<uint8_t> mes = {0xde, 0xad, 0xbe, 0xef};
         constexpr uint8_t child_signed = 1;
         constexpr uint8_t child_refused = 2;
         constexpr uint8_t child_other_exception = 3;

         int fd[2];
         if(::pipe(fd) != 0) {
            result.test_failure("failed to create pipe");
            return result;
         }

         const pid_t pid = ::fork();
         if(pid == -1) {
            ::close(fd[0]);
            ::close(fd[1]);

      #if defined(BOTAN_TARGET_OS_IS_EMSCRIPTEN)
            result.test_note("failed to fork process");
      #else
            result.test_failure("failed to fork process");
      #endif

            return result;
         } else if(pid == 0) {
            ::close(fd[0]);

            // Signing may wait on worker threads which do not exist in the child
            ::alarm(30);

            uint8_t child_status = child_signed;

            try {
               Botan::PK_Signer signer(sk, Test::rng(), "");
               signer.sign_message(mes, Test::rng());
            } catch(const Botan::Invalid_State&) {
               child_status = child_refused;
            } catch(const std::exception&) {
               child_status = child_other_exception;
            }

            [[maybe_unused]] const ssize_t written = ::write(fd[1], &child_status, sizeof(child_status));
            ::close(fd[1]);

            ::execl("/bin/true", "true", NULL);  // NOLINT(*-vararg)
            ::_exit(0);
         }

         ::close(fd[1]);

         uint8_t child_status = 0;
         const ssize_t got = ::read(fd[0], &child_status, sizeof(child_status));
         if(got > 0) {
            result.test_sz_eq("expected status byte from child", static_cast<size_t>(got), sizeof(child_status));
            result.test_u8_eq("forked child refused to emit an index", child_status, child_refused);
         } else {
            result.test_failure("failed to read child status");
         }
         ::close(fd[0]);

         int status = 0;
         if(::waitpid(pid, &status, 0) == pid) {
            result.test_is_true("child exited successfully", WIFEXITED(status) && WEXITSTATUS(status) == 0);
         } else {
            result.test_failure("failed to wait for child process");
         }

         Botan::PK_Signer signer(sk, Test::rng(), "");
         result.test_no_throw("parent can still sign", [&]() { signer.sign_message(mes, Test::rng()); });

         return result;
      }
   #endif

      std::vector<Test::Result> run() final {
         std::vector<Test::Result> results = {test_sig_changes_state(),
                                              test_max_sig_count(),
                                              test_idx_bound_checked_on_load(),
                                              test_exhausted_key_stays_exhausted(),
                                              test_params_are_part_of_key_identity(),
                                              test_separately_loaded_copies_share_state(),
                                              test_unsupported_output_format_rejected()};

   #if defined(BOTAN_TARGET_OS_HAS_POSIX1)
         if(Test::options().test_threads() == 1) {
            results.push_back(test_forked_key_cannot_sign());
         }
   #endif

         return results;
      }
};

/**
 * @brief Test APIs not covered by other tests.
 */
class HSS_LMS_Missing_API_Test final : public Test {
      std::vector<Test::Result> run() final {
         Test::Result result("HSS-LMS");

         // HSS_LMS_PublicKey::key_length()
         auto sk = Botan::create_private_key("HSS-LMS", Test::rng(), "SHA-256,HW(10,4)");
         result.test_sz_eq("Key length is the hash output length in bits", sk->key_length(), 256);

         // HSS_LMS_Verification_Operation::hash_function()
         const Botan::PK_Verifier verifier(*sk, Botan::PK_Signature_Options());
         result.test_str_eq("PK_Verifier should report the hash of the key", verifier.hash_function(), "SHA-256");

         // HSS_LMS_PrivateKey::raw_private_key_bits()
         result.test_bin_eq("Our BER and raw encoding is the same", sk->raw_private_key_bits(), sk->private_key_bits());

         // HSS_LMS_Signature_Operation::algorithm_identifier()
         const Botan::PK_Signer signer(*sk, Test::rng(), Botan::PK_Signature_Options());
         result.test_is_true("signature algorithm", signer.algorithm_identifier() == sk->algorithm_identifier());

         // HSS_LMS_Signature_Operation::hash_function()
         result.test_str_eq("PK_Signer should report the hash of the key", signer.hash_function(), "SHA-256");

         return {result};
      }
};

uint32_t u32_at(std::span<const uint8_t> bytes, size_t offset) {
   if(offset + sizeof(uint32_t) > bytes.size()) {
      throw Test_Error("HSS-LMS private key encoding is shorter than expected");
   }
   return Botan::load_be<uint32_t>(bytes.subspan(offset).first<sizeof(uint32_t)>());
}

/**
 * @brief Location of a section of an HSS-LMS private key in the current format
 */
struct HSS_LMS_SK_Section final {
      size_t offset;  // of the tag
      uint32_t tag;
      uint32_t length;
};

size_t section_body(const HSS_LMS_SK_Section& section) {
   return section.offset + 2 * sizeof(uint32_t);
}

// The nodes of an LMS tree section follow the level and tree number
size_t section_nodes(const HSS_LMS_SK_Section& section) {
   return section_body(section) + sizeof(uint32_t) + sizeof(uint64_t);
}

/**
 * @brief Offsets within an HSS-LMS private key in the current format
 */
struct HSS_LMS_SK_Layout final {
      size_t legacy_end;
      size_t seed;
      size_t root;
      size_t section_count;
      std::vector<HSS_LMS_SK_Section> sections;
};

HSS_LMS_SK_Layout hss_lms_sk_layout(std::span<const uint8_t> bytes, const Botan::HSS_LMS_Params& params) {
   const size_t L = params.L().get();
   const size_t m = params.params_at_level(Botan::HSS_Level(0)).lms_params().m();

   HSS_LMS_SK_Layout layout{};
   layout.seed = sk_index_offset + sizeof(uint64_t) + L * 2 * sizeof(uint32_t);
   layout.legacy_end = layout.seed + m + Botan::LMS_IDENTIFIER_LEN;
   layout.root = layout.legacy_end;
   layout.section_count = layout.root + m;

   size_t offset = layout.section_count + sizeof(uint32_t);
   const uint32_t count = u32_at(bytes, layout.section_count);
   for(uint32_t i = 0; i != count; ++i) {
      const uint32_t tag = u32_at(bytes, offset);
      const uint32_t length = u32_at(bytes, offset + sizeof(uint32_t));
      layout.sections.push_back({offset, tag, length});
      offset += 2 * sizeof(uint32_t) + length;
   }
   return layout;
}

/**
 * @brief The HSS index used for a signature, combined from the leaf used at each level
 */
uint64_t hss_signature_index(std::span<const uint8_t> sig, const Botan::HSS_LMS_Params& params) {
   const auto parsed = Botan::HSS_Signature::from_bytes_or_throw(sig);
   uint64_t idx = 0;
   for(Botan::HSS_Level level(0); level < params.L(); ++level) {
      const auto& lms_sig = (level + 1 < params.L()) ? parsed.signed_pub_key(level).signature() : parsed.bottom_sig();
      idx = (idx << params.params_at_level(level).lms_params().h()) | lms_sig.q().get();
   }
   return idx;
}

/**
 * @brief Tests of the private key encoding, and the tree data cached in the key.
 */
class HSS_LMS_Encoding_Test_Base : public Test {
   protected:
      static constexpr std::string_view TwoLevelParams = "Truncated(SHA-256,192),HW(5,1),HW(5,1)";

      std::vector<uint8_t> message() const { return {0xde, 0xad, 0xbe, 0xef}; }

      std::vector<uint8_t> sign(const Botan::Private_Key& sk) const {
         Botan::PK_Signer signer(sk, Test::rng(), "");
         return signer.sign_message(message(), Test::rng());
      }

      bool verify(const Botan::Public_Key& pk, std::span<const uint8_t> sig) const {
         Botan::PK_Verifier verifier(pk, "");
         return verifier.verify_message(message(), sig);
      }

      static Botan::HSS_LMS_PrivateKey load(std::span<const uint8_t> bytes) {
         return Botan::HSS_LMS_PrivateKey(hss_lms_sk_alg_id("HSS-LMS-Private-Key"), bytes);
      }

      static Botan::HSS_LMS_PrivateKey load_legacy(std::span<const uint8_t> bytes) {
         return Botan::HSS_LMS_PrivateKey(hss_lms_sk_alg_id("HSS-LMS-Private-Key-legacy"), bytes);
      }

      static std::vector<uint8_t> legacy_encoding(std::span<const uint8_t> bytes, const Botan::HSS_LMS_Params& params) {
         const auto layout = hss_lms_sk_layout(bytes, params);
         return std::vector<uint8_t>(bytes.begin(), bytes.begin() + layout.legacy_end);
      }

      Test::Result test_current_encoding() {
         Test::Result result("HSS-LMS private key encoding");

         const Botan::HSS_LMS_Params params(TwoLevelParams);
         const Botan::HSS_LMS_PrivateKey sk(Test::rng(), TwoLevelParams);
         const size_t m = params.params_at_level(Botan::HSS_Level(0)).lms_params().m();

         result.test_str_eq(
            "private key OID", sk.pkcs8_algorithm_identifier().oid().to_string(), "1.3.6.1.4.1.25258.1.19");

         const auto fresh = sk.private_key_bits();
         const auto fresh_layout = hss_lms_sk_layout(fresh, params);
         result.test_sz_eq("only the top tree is cached before signing", fresh_layout.sections.size(), 1);

         sign(sk);

         const auto bytes = sk.private_key_bits();
         const auto layout = hss_lms_sk_layout(bytes, params);
         result.test_sz_eq("both trees are cached after signing", layout.sections.size(), 2);
         result.test_sz_eq("encoding has no trailing data",
                           section_body(layout.sections.back()) + layout.sections.back().length,
                           bytes.size());

         const auto pk_bits = sk.public_key_bits();
         result.test_bin_eq(
            "encoding contains the root", std::span(bytes).subspan(layout.root, m), std::span(pk_bits).last(m));

         const auto loaded = load(bytes);
         result.test_bin_eq("loaded key has the same public key", loaded.public_key_bits(), pk_bits);
         result.test_bin_eq("encoding round trips", loaded.private_key_bits(), bytes);

         const auto sig = sign(loaded);
         result.test_u64_eq("loaded key continues at the next index", hss_signature_index(sig, params), 1);
         result.test_is_true("signature of loaded key is valid", verify(sk, sig));

         return result;
      }

      Test::Result test_legacy_encoding() {
         Test::Result result("HSS-LMS legacy private key encoding");

         const Botan::HSS_LMS_Params params(TwoLevelParams);
         const Botan::HSS_LMS_PrivateKey sk(Test::rng(), TwoLevelParams);
         sign(sk);

         const auto legacy = legacy_encoding(sk.private_key_bits(), params);

         const auto loaded = load_legacy(legacy);
         result.test_bin_eq("legacy key has the same public key", loaded.public_key_bits(), sk.public_key_bits());

         const auto sig = sign(loaded);
         result.test_u64_eq("legacy key continues at the next index", hss_signature_index(sig, params), 1);
         result.test_is_true("signature of legacy key is valid", verify(sk, sig));

         const auto reencoded = loaded.private_key_bits();
         result.test_sz_eq(
            "re-encoded legacy key caches both trees", hss_lms_sk_layout(reencoded, params).sections.size(), 2);
         result.test_bin_eq("re-encoded legacy key starts with the legacy fields",
                            std::span(reencoded).first(legacy.size()),
                            legacy_encoding(sk.private_key_bits(), params));

         // A PKCS #8 structure as written by older versions
         const auto pkcs8 = Botan::DER_Encoder()
                               .start_sequence()
                               .encode(size_t(0))
                               .encode(hss_lms_sk_alg_id("HSS-LMS-Private-Key-legacy"))
                               .encode(legacy, Botan::ASN1_Type::OctetString)
                               .end_cons()
                               .get_contents_unlocked();
         const auto from_pkcs8 = Botan::PKCS8::load_key(pkcs8);
         result.test_bin_eq(
            "legacy PKCS #8 key has the same public key", from_pkcs8->public_key_bits(), sk.public_key_bits());
         result.test_is_true("signature of legacy PKCS #8 key is valid", verify(sk, sign(*from_pkcs8)));

         return result;
      }

      Test::Result test_algorithm_identifiers() {
         Test::Result result("HSS-LMS private key algorithm identifiers");

         const Botan::HSS_LMS_Params params(TwoLevelParams);
         const Botan::HSS_LMS_PrivateKey sk(Test::rng(), TwoLevelParams);
         const auto current = sk.private_key_bits();
         const auto legacy = legacy_encoding(current, params);

         const auto from_pkcs8 = Botan::PKCS8::load_key(sk.private_key_info());
         result.test_bin_eq("PKCS #8 round trip", from_pkcs8->private_key_bits(), current);

         result.test_no_throw("raw bytes in the current format", [&] {
            const Botan::HSS_LMS_PrivateKey key(Botan::AlgorithmIdentifier(), current);
            result.test_bin_eq("same public key", key.public_key_bits(), sk.public_key_bits());
         });
         result.test_no_throw("raw bytes in the legacy format", [&] {
            const Botan::HSS_LMS_PrivateKey key(Botan::AlgorithmIdentifier(), legacy);
            result.test_bin_eq("same public key", key.public_key_bits(), sk.public_key_bits());
         });

         result.test_throws<Botan::Decoding_Error>("legacy OID with the current format", [&] { load_legacy(current); });
         result.test_throws<Botan::Decoding_Error>("current OID with the legacy format", [&] { load(legacy); });
         result.test_throws<Botan::Decoding_Error>(
            "public key OID", [&] { Botan::HSS_LMS_PrivateKey(sk.algorithm_identifier(), current); });

         return result;
      }

      Test::Result test_root_is_taken_from_encoding() {
         Test::Result result("HSS-LMS root is not recomputed on load");

         const Botan::HSS_LMS_Params params(TwoLevelParams);
         const Botan::HSS_LMS_PrivateKey sk(Test::rng(), TwoLevelParams);

         auto bytes = sk.private_key_bits();
         const auto layout = hss_lms_sk_layout(bytes, params);
         bytes.at(layout.seed) ^= 0x01;

         const auto corrupted = load(bytes);
         result.test_bin_eq(
            "public key is taken from the stored root", corrupted.public_key_bits(), sk.public_key_bits());

         result.test_is_true("strong key check of a valid key passes", sk.check_key(Test::rng(), true));
         result.test_is_true("weak key check does not compute the tree", corrupted.check_key(Test::rng(), false));
         result.test_is_true("strong key check detects a seed not matching the root",
                             !corrupted.check_key(Test::rng(), true));

         result.test_throws<Botan::Internal_Error>("a signature not matching the root is not released",
                                                   [&] { sign(corrupted); });
         result.test_throws<Botan::Invalid_State>("a seed not matching the root is detected once recomputed",
                                                  [&] { sign(corrupted); });

         return result;
      }

      Test::Result test_corrupt_cache_is_discarded() {
         Test::Result result("HSS-LMS corrupted cache data");

         const Botan::HSS_LMS_Params params(TwoLevelParams);
         const Botan::HSS_LMS_PrivateKey sk(Test::rng(), TwoLevelParams);
         sign(sk);

         const auto bytes = sk.private_key_bits();
         const auto layout = hss_lms_sk_layout(bytes, params);
         result.require("both trees are cached", layout.sections.size() == 2);

         const auto& top = layout.sections[0];
         const auto& bottom = layout.sections[1];
         const size_t bottom_row_size =
            Botan::LMS_Treetop::row_size(params.params_at_level(Botan::HSS_Level(1)).lms_params());

         const auto signs_validly_after_flipping = [&](std::string_view what, size_t offset) {
            auto corrupted = bytes;
            corrupted.at(offset) ^= 0x01;
            const auto loaded = load(corrupted);
            const auto sig = sign(loaded);
            result.test_is_true(Botan::fmt("{}: signature is valid", what), verify(sk, sig));
         };

         signs_validly_after_flipping("top tree nodes", section_nodes(top));
         signs_validly_after_flipping("bottom tree number", section_nodes(bottom) - 1);
         signs_validly_after_flipping("bottom tree nodes", section_nodes(bottom) + bottom_row_size - 1);
         signs_validly_after_flipping("signature over bottom tree", section_nodes(bottom) + bottom_row_size + 40);
         signs_validly_after_flipping("bottom tree public key", section_body(bottom) + bottom.length - 1);

         auto corrupted_root = bytes;
         corrupted_root.at(layout.root) ^= 0x01;
         const auto loaded = load(corrupted_root);
         result.test_throws<Botan::Invalid_State>("signing with a corrupted root fails", [&] { sign(loaded); });

         return result;
      }

      Test::Result test_stale_cache_is_discarded() {
         Test::Result result("HSS-LMS stale cache data");

         const Botan::HSS_LMS_Params params(TwoLevelParams);
         const Botan::HSS_LMS_PrivateKey sk(Test::rng(), TwoLevelParams);
         sign(sk);

         // Skip ahead to the second bottom tree, which makes the cached one stale
         auto bytes = sk.private_key_bits();
         Botan::store_be(uint64_t(32), bytes.data() + sk_index_offset);

         const auto loaded = load(bytes);
         const auto sig = sign(loaded);
         result.test_u64_eq("signature uses the patched index", hss_signature_index(sig, params), 32);
         result.test_is_true("signature is valid", verify(sk, sig));

         const auto reencoded = loaded.private_key_bits();
         const auto layout = hss_lms_sk_layout(reencoded, params);
         result.require("both trees are cached", layout.sections.size() == 2);
         result.test_u64_eq(
            "the new bottom tree is cached",
            Botan::load_be<uint64_t>(
               std::span(reencoded).subspan(section_body(layout.sections[1]) + sizeof(uint32_t)).first<8>()),
            1);

         return result;
      }

      Test::Result test_unknown_sections_are_ignored() {
         Test::Result result("HSS-LMS unknown private key sections");

         const Botan::HSS_LMS_Params params(TwoLevelParams);
         const Botan::HSS_LMS_PrivateKey sk(Test::rng(), TwoLevelParams);

         auto bytes = sk.private_key_bits();
         const auto layout = hss_lms_sk_layout(bytes, params);
         Botan::store_be(u32_at(bytes, layout.section_count) + 1, bytes.data() + layout.section_count);
         const auto unknown = Botan::concat<Botan::secure_vector<uint8_t>>(
            Botan::store_be(uint32_t(0x7fffffff)), Botan::store_be(uint32_t(3)), std::array<uint8_t, 3>{1, 2, 3});
         bytes.insert(bytes.end(), unknown.begin(), unknown.end());

         const auto loaded = load(bytes);
         result.test_is_true("key with an unknown section signs validly", verify(sk, sign(loaded)));

         return result;
      }

      Test::Result test_malformed_encodings_are_rejected() {
         Test::Result result("HSS-LMS malformed private key encodings");

         const Botan::HSS_LMS_Params params(TwoLevelParams);
         const Botan::HSS_LMS_PrivateKey sk(Test::rng(), TwoLevelParams);
         sign(sk);

         const auto bytes = sk.private_key_bits();
         const auto layout = hss_lms_sk_layout(bytes, params);
         result.require("both trees are cached", layout.sections.size() == 2);

         const auto rejects = [&](std::string_view what, const auto& patch) {
            auto patched = bytes;
            patch(patched);
            result.test_throws<Botan::Decoding_Error>(what, [&] { load(patched); });
         };

         rejects("trailing data", [](auto& b) { b.push_back(0); });
         rejects("missing section", [&](auto& b) { Botan::store_be(uint32_t(3), b.data() + layout.section_count); });
         rejects("wrong tree section length", [&](auto& b) {
            Botan::store_be(layout.sections[0].length - 1, b.data() + layout.sections[0].offset + sizeof(uint32_t));
         });
         rejects("tree sections out of order",
                 [&](auto& b) { Botan::store_be(uint32_t(0), b.data() + section_body(layout.sections[1])); });
         rejects("tree section for a level that does not exist",
                 [&](auto& b) { Botan::store_be(uint32_t(2), b.data() + section_body(layout.sections[1])); });

         return result;
      }

      Test::Result test_subtrees() {
         Test::Result result("HSS-LMS trees with subtrees");

         // Trees higher than 10 store their nodes down to height h - 10 and
         // recompute the subtrees below as needed
         const std::string_view hss_params_str = "Truncated(SHA-256,192),HW(15,1)";
         const Botan::HSS_LMS_Params params(hss_params_str);
         const auto& lms_params = params.params_at_level(Botan::HSS_Level(0)).lms_params();
         const auto& lmots_params = params.params_at_level(Botan::HSS_Level(0)).lmots_params();
         result.test_u32_eq("subtree height", Botan::LMS_Treetop::subtree_height(lms_params), 5);

         const Botan::HSS_LMS_PrivateKey sk(Test::rng(), hss_params_str);
         const auto layout = hss_lms_sk_layout(sk.private_key_bits(), params);
         result.require("top tree is cached", layout.sections.size() == 1);
         result.test_sz_eq("cached top tree has 2^10 nodes",
                           layout.sections[0].length,
                           sizeof(uint32_t) + sizeof(uint64_t) + 1024 * lms_params.m());

         // Index 33 is in the second subtree
         for(uint64_t i = 0; i != 33; ++i) {
            sign(sk);
         }
         const auto loaded = load(sk.private_key_bits());
         const auto sig = sign(loaded);
         result.test_u64_eq("signature index", hss_signature_index(sig, params), 33);
         result.test_is_true("signature using a recomputed subtree is valid", verify(sk, sig));

         // The same on the level of a single LMS tree
         const Botan::LMS_Identifier identifier(
            Test::rng().random_vec<std::vector<uint8_t>>(Botan::LMS_IDENTIFIER_LEN));
         const Botan::LMS_PrivateKey lms_sk(
            lms_params, lmots_params, identifier, Test::rng().random_vec<Botan::LMS_Seed>(lms_params.m()));
         const Botan::LMS_PrivateKey other_lms_sk(
            lms_params, lmots_params, identifier, Test::rng().random_vec<Botan::LMS_Seed>(lms_params.m()));

         const Botan::LMS_Tree_Node_Idx q(40);
         const auto [treetop, subtree] = lms_sk.build_tree(q);
         result.test_u32_eq("leaf 40 is in subtree 1", subtree.index(), 1);
         result.test_bin_eq(
            "subtree root is part of the treetop", subtree.node(1), treetop.node((uint32_t(1) << 10) + 1));
         result.test_bin_eq("treetop from its row",
                            Botan::LMS_Treetop::from_row(lms_params, identifier, treetop.row()).root(),
                            treetop.root());

         const auto rebuilt = lms_sk.build_subtree(treetop, q);
         result.test_is_true("subtree is recomputed", rebuilt.has_value());
         if(rebuilt.has_value()) {
            result.test_bin_eq("recomputed subtree matches", rebuilt->node(2), subtree.node(2));
         }
         result.test_is_true("subtree of another key does not match the treetop",
                             !other_lms_sk.build_subtree(treetop, q).has_value());

         Botan::LMS_Signature_Bytes lms_sig(Botan::LMS_Signature::size(lms_params, lmots_params));
         const Botan::LMS_Message msg(message());
         lms_sk.sign_with_nodes(lms_sig, q, msg, treetop, &subtree);
         const Botan::LMS_PublicKey lms_pk(lms_params, lmots_params, identifier, Botan::LMS_Tree_Node(treetop.root()));
         Botan::BufferSlicer slicer(lms_sig);
         result.test_is_true("LMS signature using stored nodes is valid",
                             lms_pk.verify_signature(msg, Botan::LMS_Signature::from_bytes_or_throw(slicer)));

         return result;
      }

   #if defined(BOTAN_TARGET_OS_HAS_THREADS)
      Test::Result test_concurrent_signing() {
         Test::Result result("HSS-LMS concurrent signing with separately loaded keys");

         const Botan::HSS_LMS_Params params(TwoLevelParams);
         const Botan::HSS_LMS_PrivateKey sk(Test::rng(), TwoLevelParams);

         const auto bytes = sk.private_key_bits();
         const auto legacy = legacy_encoding(bytes, params);

         // More threads than key objects, so some objects are shared between
         // threads. Half of the objects are loaded from the legacy encoding.
         constexpr size_t key_objects = 4;
         constexpr size_t threads = 8;
         // The bottom trees have 32 leaves, so this crosses several of them
         constexpr size_t sigs_per_thread = 20;
         constexpr size_t total_sigs = threads * sigs_per_thread;

         std::vector<std::unique_ptr<Botan::HSS_LMS_PrivateKey>> keys;
         for(size_t i = 0; i != key_objects; ++i) {
            keys.push_back(
               std::make_unique<Botan::HSS_LMS_PrivateKey>((i % 2 == 0) ? load(bytes) : load_legacy(legacy)));
         }

         const auto thread_message = [](size_t t, size_t i) {
            return std::vector<uint8_t>{static_cast<uint8_t>(t), static_cast<uint8_t>(i)};
         };

         std::vector<std::future<std::vector<std::vector<uint8_t>>>> futures;
         futures.reserve(threads);
         for(size_t t = 0; t != threads; ++t) {
            futures.push_back(std::async(std::launch::async, [&, t]() {
               auto thread_rng = Test::new_rng(Botan::fmt("{} thread {}", result.who(), t));
               Botan::PK_Signer signer(*keys[t % key_objects], *thread_rng, "");
               std::vector<std::vector<uint8_t>> sigs;
               for(size_t i = 0; i != sigs_per_thread; ++i) {
                  sigs.push_back(signer.sign_message(thread_message(t, i), *thread_rng));
               }
               return sigs;
            }));
         }

         Botan::PK_Verifier verifier(sk, "");
         std::set<uint64_t> indices;
         for(size_t t = 0; t != threads; ++t) {
            try {
               const auto sigs = futures[t].get();
               for(size_t i = 0; i != sigs.size(); ++i) {
                  if(!verifier.verify_message(thread_message(t, i), sigs[i])) {
                     result.test_failure(Botan::fmt("signature {} of thread {} is invalid", i, t));
                  }
                  if(!indices.insert(hss_signature_index(sigs[i], params)).second) {
                     result.test_failure(Botan::fmt("signature {} of thread {} reuses an index", i, t));
                  }
               }
            } catch(const std::exception& e) {
               result.test_failure(Botan::fmt("thread {} failed", t), e.what());
            }
         }

         result.test_sz_eq("each signature used its own index", indices.size(), total_sigs);
         result.test_is_true("indices are consecutive", !indices.empty() && *indices.rbegin() == total_sigs - 1);
         result.test_opt_u64_eq("all copies share the state", keys[1]->remaining_operations(), 1024 - total_sigs);

         const auto reloaded = load(keys[1]->private_key_bits());
         const auto sig = sign(reloaded);
         result.test_u64_eq("reloaded key continues after all threads", hss_signature_index(sig, params), total_sigs);
         result.test_is_true("signature of reloaded key is valid", verify(sk, sig));

         return result;
      }
   #endif
};

class HSS_LMS_Encoding_Test final : public HSS_LMS_Encoding_Test_Base {
   public:
      std::vector<Test::Result> run() final {
         std::vector<Test::Result> results = {test_current_encoding(),
                                              test_legacy_encoding(),
                                              test_algorithm_identifiers(),
                                              test_root_is_taken_from_encoding(),
                                              test_corrupt_cache_is_discarded(),
                                              test_stale_cache_is_discarded(),
                                              test_unknown_sections_are_ignored(),
                                              test_malformed_encodings_are_rejected()};

   #if defined(BOTAN_TARGET_OS_HAS_THREADS)
         results.push_back(test_concurrent_signing());
   #endif

         return results;
      }
};

/**
 * @brief Separate from HSS_LMS_Encoding_Test, since computing trees of height 15 is slow under valgrind.
 */
class HSS_LMS_Subtree_Test final : public HSS_LMS_Encoding_Test_Base {
   public:
      std::vector<Test::Result> run() final { return {test_subtrees()}; }
};

   #if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
/**
 * @brief Test with the example certificate from RFC 9802 Appendix A.
 */
class HSS_LMS_X509_Test final : public Test {
      std::vector<Test::Result> run() final {
         Test::Result result("HSS-LMS X.509");

         const Botan::X509_Certificate cert(Test::data_file("x509/hss-lms/hss-lms-rfc-9802-cert.pem"));
         const auto ver_res = cert.verify_signature(*cert.subject_public_key());
         result.test_is_true("signature of certificate verifies", ver_res.first == Botan::Certificate_Status_Code::OK);

         return {result};
      }
};
   #endif

BOTAN_REGISTER_TEST_FN("pubkey", "hss_lms_params_parsing", test_hss_lms_params_parsing);
BOTAN_REGISTER_TEST("pubkey", "hss_lms_sign", HSS_LMS_Signature_Generation_Test);
BOTAN_REGISTER_TEST("pubkey", "hss_lms_verify", HSS_LMS_Signature_Verify_Tests);
BOTAN_REGISTER_TEST("pubkey", "hss_lms_verify_invalid", HSS_LMS_Signature_Verify_Invalid_Tests);
BOTAN_REGISTER_TEST("pubkey", "hss_lms_keygen", HSS_LMS_Key_Generation_Test);
BOTAN_REGISTER_TEST("pubkey", "hss_lms_negative", HSS_LMS_Negative_Tests);
BOTAN_REGISTER_TEST("pubkey", "hss_lms_state", HSS_LMS_Statefulness_Test);
BOTAN_REGISTER_TEST("pubkey", "hss_lms_api", HSS_LMS_Missing_API_Test);
BOTAN_REGISTER_TEST("pubkey", "hss_lms_encoding", HSS_LMS_Encoding_Test);
BOTAN_REGISTER_TEST("pubkey", "hss_lms_subtrees", HSS_LMS_Subtree_Test);

   #if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
BOTAN_REGISTER_TEST("pubkey", "hss_lms_x509", HSS_LMS_X509_Test);
   #endif

}  // namespace

}  // namespace Botan_Tests

#endif  // BOTAN_HAS_HSS_LMS
