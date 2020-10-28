/*
 * Extended Hash-Based Signatures Tests
 *
 * (C) 2014,2015 Jack Lloyd
 * (C) 2016,2018 Matthias Gierlings
 **/

#include "tests.h"

#if defined(BOTAN_HAS_XMSS_RFC8391)
   #include <botan/xmss.h>
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

      bool skip_this_test(const std::string&,
                          const VarMap& vars) override
         {
         if(Test::run_long_tests() == false)
            {
            const std::string params = vars.get_req_str("Params");

            if(params == "SHAKE_10_256")
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

         std::unique_ptr<Botan::Private_Key> key(new Botan::XMSS_PrivateKey(sec_key));
         return key;
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
         std::unique_ptr<Botan::Public_Key> key(new Botan::XMSS_PublicKey(raw_key));
         return key;
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
         std::unique_ptr<Botan::Public_Key> key(new Botan::XMSS_PublicKey(raw_key));
         return key;
         }
   };

class XMSS_Keygen_Tests final : public PK_Key_Generation_Test
   {
   public:
      std::vector<std::string> keygen_params() const override
         {
         return { "XMSS-SHA2_10_256" };
         }
      std::string algo_name() const override
         {
         return "XMSS";
         }
   };

BOTAN_REGISTER_TEST("pubkey", "xmss_sign", XMSS_Signature_Tests);
BOTAN_REGISTER_TEST("pubkey", "xmss_verify", XMSS_Signature_Verify_Tests);
BOTAN_REGISTER_TEST("pubkey", "xmss_verify_invalid", XMSS_Signature_Verify_Invalid_Tests);
BOTAN_REGISTER_TEST("pubkey", "xmss_keygen", XMSS_Keygen_Tests);

#endif

}

}
