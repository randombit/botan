/*
* Extended Hash-Based Signatures Tests
*
* (C) 2014,2015 Jack Lloyd
* (C) 2016,2018 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#include "tests.h"

#if defined(BOTAN_HAS_XMSSMT_RFC8391)
   #include "test_pubkey.h"
   #include "test_rng.h"
   #include <botan/hash.h>
   #include <botan/hex.h>
   #include <botan/pubkey.h>
   #include <botan/xmssmt.h>
   #include <botan/internal/buffer_slicer.h>
   #include <botan/internal/loadstor.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_XMSSMT_RFC8391)

class XMSSMT_Signature_Tests final : public PK_Signature_Generation_Test {
   public:
      XMSSMT_Signature_Tests() :
            PK_Signature_Generation_Test("XMSSMT", "pubkey/xmssmt_sig.vec", "Params,Msg,PrivateKey,Signature") {}

      bool skip_this_test(const std::string& /*header*/, const VarMap& vars) override {
         if(Test::run_long_tests() == false) {
            const std::string params = vars.get_req_str("Params");

            if(params.find("60/3") != std::string::npos || params.find("40/2") != std::string::npos) {
               return true;
            }

            return false;
         }

         return false;
      }

      std::string default_padding(const VarMap& vars) const override { return vars.get_req_str("Params"); }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override {
         const std::vector<uint8_t> raw_key = vars.get_req_bin("PrivateKey");
         const Botan::secure_vector<uint8_t> sec_key(raw_key.begin(), raw_key.end());

         return std::make_unique<Botan::XMSSMT_PrivateKey>(sec_key);
      }
};

class XMSSMT_Signature_Verify_Tests final : public PK_Signature_Verification_Test {
   public:
      XMSSMT_Signature_Verify_Tests() :
            PK_Signature_Verification_Test("XMSS^MT", "pubkey/xmssmt_verify.vec", "Params,Msg,PublicKey,Signature") {}

      std::string default_padding(const VarMap& vars) const override { return vars.get_req_str("Params"); }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override {
         const std::vector<uint8_t> raw_key = vars.get_req_bin("PublicKey");
         return std::make_unique<Botan::XMSSMT_PublicKey>(raw_key);
      }

      // bool test_random_invalid_sigs() const override { return false; }
};

class XMSSMT_Signature_Verify_Invalid_Tests final : public PK_Signature_NonVerification_Test {
   public:
      XMSSMT_Signature_Verify_Invalid_Tests() :
            PK_Signature_NonVerification_Test(
               "XMSSMT", "pubkey/xmssmt_invalid.vec", "Params,Msg,PublicKey,InvalidSignature") {}

      std::string default_padding(const VarMap& vars) const override { return vars.get_req_str("Params"); }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override {
         const std::vector<uint8_t> raw_key = vars.get_req_bin("PublicKey");
         return std::make_unique<Botan::XMSSMT_PublicKey>(raw_key);
      }
};

class XMSSMT_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      /* all 20/4 parameter sets (fast) so we test all hash variations,
         to test different heights the remaining SHA2_*_256 parameter sets excluding 60/3 and 40/2 are included
         60/3 and 40/2 is too slow  */
      std::vector<std::string> keygen_params() const override {
         return {"XMSSMT-SHA2_20/4_192",
                 "XMSSMT-SHAKE256_20/4_192",
                 "XMSSMT-SHA2_20/4_256",
                 "XMSSMT-SHAKE_20/4_256",
                 "XMSSMT-SHAKE256_20/4_256",
                 "XMSSMT-SHA2_20/4_512",
                 "XMSSMT-SHAKE_20/4_512",
                 "XMSSMT-SHA2_20/2_256",
                 "XMSSMT-SHA2_40/4_256",
                 "XMSSMT-SHA2_40/8_256",
                 "XMSSMT-SHA2_60/6_256",
                 "XMSSMT-SHA2_60/12_256"};
      }

      std::string algo_name() const override { return "XMSSMT"; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view /* keygen_params */,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> raw_pk) const override {
         Botan::BufferSlicer s(raw_pk);
         const auto oid = Botan::XMSSMT_Parameters::xmssmt_algorithm_t(Botan::load_be(s.take<4>()));
         const auto p = Botan::XMSSMT_Parameters(oid);
         auto root = s.copy_as_secure_vector(p.element_size());
         auto public_seed = s.copy_as_secure_vector(p.element_size());

         return std::make_unique<Botan::XMSSMT_PublicKey>(oid, std::move(root), std::move(public_seed));
      }
};

/**
 * Tests that the key generation is compatible with the reference implementation
 *   based on: https://github.com/XMSS/xmss-reference/tree/171ccbd
 */
class XMSSMT_Keygen_Reference_Test final : public Text_Based_Test {
   public:
      XMSSMT_Keygen_Reference_Test() :
            Text_Based_Test("pubkey/xmssmt_keygen.vec", "Params,SecretSeed,PublicSeed,SecretPrf,PublicKey,PrivateKey") {
      }

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) final {
         Test::Result result(vars.get_req_str("Params"));

         Fixed_Output_RNG fixed_rng;
         auto add_entropy = [&](auto v) { fixed_rng.add_entropy(v.data(), v.size()); };

         // The order of the RNG values is dependent on the order they are pulled
         // from the RNG in the production implementation.
         add_entropy(vars.get_req_bin("PublicSeed"));  // XMSSMT_PublicKey constructor's initializer list
         add_entropy(
            vars.get_req_bin("SecretPrf"));  // XMSSMT_PrivateKey constructor's call to ..._Internal constructor
         add_entropy(
            vars.get_req_bin("SecretSeed"));  // XMSSMT_PrivateKey constructor's call to ..._Internal constructor

         const auto xmssmt_algo = Botan::XMSSMT_Parameters::xmssmt_id_from_string(vars.get_req_str("Params"));
         const Botan::XMSSMT_PrivateKey keypair(xmssmt_algo, fixed_rng);

         result.test_bin_eq("Generated private key matches", keypair.raw_private_key(), vars.get_req_bin("PrivateKey"));
         result.test_bin_eq(
            "Generated public key matches", keypair.raw_public_key_bits(), vars.get_req_bin("PublicKey"));

         return result;
      }

      bool skip_this_test(const std::string& /*header*/, const VarMap& vars) override {
         const std::string param_str = vars.get_req_str("Params");
         const auto params = Botan::XMSSMT_Parameters(param_str);
         const bool hash_available = Botan::HashFunction::create(params.hash_function_name()) != nullptr;

         /* generating keys with layer height of 5 is very fast */
         const bool fast_params = param_str.find("20/4") != std::string::npos ||
                                  param_str.find("40/8") != std::string::npos ||
                                  param_str.find("60/12") != std::string::npos;
         return !(hash_available && (fast_params || Test::run_long_tests()));
      }
};

std::vector<Test::Result> xmssmt_statefulness() {
   auto rng = Test::new_rng(__func__);

   auto sign_something = [&rng](auto& sk) {
      auto msg = Botan::hex_decode("deadbeef");

      Botan::PK_Signer signer(sk, *rng, "SHA2_20/4_256");
      signer.sign_message(msg, *rng);
   };

   return {CHECK("signing alters state",
                 [&](auto& result) {
                    Botan::XMSSMT_PrivateKey sk(Botan::XMSSMT_Parameters::XMSSMT_SHA2_20_4_256, *rng);
                    result.test_opt_u64_eq("allows 2^20 signatures", sk.remaining_operations(), 1048576);

                    sign_something(sk);

                    result.test_opt_u64_eq("allows 2^20-1 signatures", sk.remaining_operations(), 1048575);
                 }),

           CHECK("state can become exhausted", [&](auto& result) {
              const auto skbytes = Botan::hex_decode(
                 "00000002"
                 "1ffb7a0511d1f733f52918e21960f1c6c0386e79c65aeaad8e6883382cf56ec7"
                 "9bcd386b92deae42b7aee30bc28ed5a9acd1cd23d0d2ad761f654b82176f7def"
                 "0fffff"  // 2^20-1
                 "69a2ad2eed76ca2dc4969d91dbd6e63bdbe23cc6032575b0a7158eca8b36be0d"
                 "89781cdf4762d69c796ed711efdc10371405be818ffb69f2c76dc094df4f46a6");
              Botan::XMSSMT_PrivateKey sk(skbytes);
              result.test_opt_u64_eq("allow one last signature", sk.remaining_operations(), 1);

              sign_something(sk);

              result.test_opt_u64_eq("allow no more signatures", sk.remaining_operations(), 0);
              result.test_throws("no more signing", [&] { sign_something(sk); });
           })};
}

BOTAN_REGISTER_TEST("pubkey", "xmssmt_sign", XMSSMT_Signature_Tests);
BOTAN_REGISTER_TEST("pubkey", "xmssmt_verify", XMSSMT_Signature_Verify_Tests);
BOTAN_REGISTER_TEST("pubkey", "xmssmt_verify_invalid", XMSSMT_Signature_Verify_Invalid_Tests);
BOTAN_REGISTER_TEST("pubkey", "xmssmt_keygen", XMSSMT_Keygen_Tests);
BOTAN_REGISTER_TEST("pubkey", "xmssmt_keygen_reference", XMSSMT_Keygen_Reference_Test);
BOTAN_REGISTER_TEST_FN("pubkey", "xmssmt_unit_tests", xmssmt_statefulness);

#endif

}  // namespace

}  // namespace Botan_Tests
