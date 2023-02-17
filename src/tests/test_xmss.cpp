/*
* Extended Hash-Based Signatures Tests
*
* (C) 2014,2015 Jack Lloyd
* (C) 2016,2018 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#include "tests.h"

#if defined(BOTAN_HAS_XMSS_RFC8391)
   #include <botan/xmss.h>
   #include "test_rng.h"
   #include "test_pubkey.h"
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_XMSS_RFC8391)

class XMSS_Signature_Tests final : public PK_Signature_Generation_Test
   {
   public:
      XMSS_Signature_Tests()
         : PK_Signature_Generation_Test(
              "XMSS",
              "pubkey/xmss_sig.vec",
              "Params,Msg,PrivateKey,Signature") {}

      bool skip_this_test(const std::string& /*header*/,
                          const VarMap& vars) override
         {
         if(Test::run_long_tests() == false)
            {
            const std::string params = vars.get_req_str("Params");

            if(params == "SHAKE_10_256" || params == "SHA2_10_192")
               {
               return false;
               }

            return true;
            }

         return false;
         }

      std::string default_padding(const VarMap& vars) const override
         {
         return vars.get_req_str("Params");
         }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const std::vector<uint8_t> raw_key = vars.get_req_bin("PrivateKey");
         const Botan::secure_vector<uint8_t> sec_key(raw_key.begin(), raw_key.end());

         return std::make_unique<Botan::XMSS_PrivateKey>(sec_key);
         }
   };

class XMSS_Signature_Verify_Tests final : public PK_Signature_Verification_Test
   {
   public:
      XMSS_Signature_Verify_Tests()
         : PK_Signature_Verification_Test(
              "XMSS",
              "pubkey/xmss_verify.vec",
              "Params,Msg,PublicKey,Signature") {}

      std::string default_padding(const VarMap& vars) const override
         {
         return vars.get_req_str("Params");
         }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override
         {
         const std::vector<uint8_t> raw_key = vars.get_req_bin("PublicKey");
         return std::make_unique<Botan::XMSS_PublicKey>(raw_key);
         }
   };

class XMSS_Signature_Verify_Invalid_Tests final : public PK_Signature_NonVerification_Test
   {
   public:
       XMSS_Signature_Verify_Invalid_Tests()
          : PK_Signature_NonVerification_Test(
               "XMSS",
               "pubkey/xmss_invalid.vec",
               "Params,Msg,PublicKey,InvalidSignature") {}

       std::string default_padding(const VarMap& vars) const override
          {
          return vars.get_req_str("Params");
          }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override
         {
         const std::vector<uint8_t> raw_key = vars.get_req_bin("PublicKey");
         return std::make_unique<Botan::XMSS_PublicKey>(raw_key);
         }
   };

class XMSS_Keygen_Tests final : public PK_Key_Generation_Test
   {
   public:
      std::vector<std::string> keygen_params() const override
         {
         return { "XMSS-SHA2_10_256", "XMSS-SHA2_10_192" };
         }
      std::string algo_name() const override
         {
         return "XMSS";
         }
   };

/**
 * Tests that the key generation is compatible with the reference implementation
 *   based on: https://github.com/XMSS/xmss-reference/tree/171ccbd
 */
class XMSS_Keygen_Reference_Test final : public Text_Based_Test
   {
   public:
      XMSS_Keygen_Reference_Test()
         : Text_Based_Test("pubkey/xmss_keygen_reference.vec", "Params,SecretSeed,PublicSeed,SecretPrf,PublicKey,PrivateKey")
      {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) final
         {
         Test::Result result(vars.get_req_str("Params"));

         Fixed_Output_RNG fixed_rng;
         auto add_entropy = [&](auto v)
            { fixed_rng.add_entropy(v.data(), v.size()); };

         // The order of the RNG values is dependent on the order they are pulled
         // from the RNG in the production implementation.
         add_entropy(vars.get_req_bin("PublicSeed")); // XMSS_PublicKey constructor's initializer list
         add_entropy(vars.get_req_bin("SecretPrf"));  // XMSS_PrivateKey constructor's call to ..._Internal constructor
         add_entropy(vars.get_req_bin("SecretSeed")); // XMSS_PrivateKey constructor's call to ..._Internal constructor

         const auto xmss_algo = Botan::XMSS_Parameters::xmss_id_from_string(vars.get_req_str("Params"));
         Botan::XMSS_PrivateKey keypair(xmss_algo, fixed_rng);

         result.test_eq("Generated private key matches", keypair.raw_private_key(), vars.get_req_bin("PrivateKey"));
         result.test_eq("Generated public key matches", keypair.raw_public_key(), vars.get_req_bin("PublicKey"));

         return result;
         }

      bool skip_this_test(const std::string& /*header*/,
                          const VarMap& vars) override
         {
         if(Test::run_long_tests())
            { return false; }

         else if(vars.get_req_str("Params") == "XMSS-SHA2_10_256")
            { return false; }

         else
            { return true; }
         }
   };

std::vector<Test::Result> xmss_statefulness()
   {
   auto sign_something = [](auto& sk)
      {
      auto msg = Botan::hex_decode("deadbeef");

      Botan::PK_Signer signer(sk, Test::rng(), "SHA2_10_256");
      signer.sign_message(msg, Test::rng());
      };

   return
      {
      CHECK("signing alters state", [&](auto& result)
         {
         Botan::XMSS_PrivateKey sk(Botan::XMSS_Parameters::XMSS_SHA2_10_256, Test::rng());
         result.require("allows 1024 signatures", sk.remaining_signatures() == 1024);

         sign_something(sk);

         result.require("allows 1023 signatures", sk.remaining_signatures() == 1023);
         }),

      CHECK("state can become exhausted", [&](auto& result)
         {
         const auto skbytes = Botan::hex_decode(
            "000000011BBB81273E8057724A2A894593A1A688B3271410B3BEAB9F5587337BCDCBBF5C4E43AB"
            "0AB2F88258E5AC54BB252E39335AE9B0D4AF0C0347EA45B8AA0AA3804C000003FFAC0C29C1ACD3"
            //                                                         ~~1023~~
            "19DA96E9C8EE4E28C2078441A76B6BB8BAFD358F67FBCBFC559B55C37C01FFADBB118099759EEB"
            "A3B07643F73BCB4AAC546E244B57782D6BEABC"
         );
         Botan::XMSS_PrivateKey sk(skbytes);
         result.require("allow one last signature", sk.remaining_signatures() == 1);

         sign_something(sk);

         result.require("allow no more signatures", sk.remaining_signatures() == 0);
         result.test_throws("no more signing", [&] { sign_something(sk); });
         })
      };
   }

BOTAN_REGISTER_TEST("pubkey", "xmss_sign", XMSS_Signature_Tests);
BOTAN_REGISTER_TEST("pubkey", "xmss_verify", XMSS_Signature_Verify_Tests);
BOTAN_REGISTER_TEST("pubkey", "xmss_verify_invalid", XMSS_Signature_Verify_Invalid_Tests);
BOTAN_REGISTER_TEST("pubkey", "xmss_keygen", XMSS_Keygen_Tests);
BOTAN_REGISTER_TEST("pubkey", "xmss_keygen_reference", XMSS_Keygen_Reference_Test);
BOTAN_REGISTER_TEST_FN("pubkey", "xmss_statefulness", xmss_statefulness);

#endif

}

}
