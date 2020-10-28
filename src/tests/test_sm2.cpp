/*
* (C) 2017 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include "test_rng.h"

#if defined(BOTAN_HAS_SM2)
   #include <botan/sm2.h>
   #include "test_pubkey.h"
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_SM2)

namespace {

std::unique_ptr<Botan::Private_Key> load_sm2_private_key(const VarMap& vars)
   {
   // group params
   const BigInt p = vars.get_req_bn("P");
   const BigInt a = vars.get_req_bn("A");
   const BigInt b = vars.get_req_bn("B");
   const BigInt xG = vars.get_req_bn("xG");
   const BigInt yG = vars.get_req_bn("yG");
   const BigInt order = vars.get_req_bn("Order");
   const BigInt cofactor = vars.get_req_bn("Cofactor");
   const BigInt x = vars.get_req_bn("x");

   Botan::EC_Group domain(p, a, b, xG, yG, order, cofactor);

   Botan::Null_RNG null_rng;
   return std::unique_ptr<Botan::Private_Key>(new Botan::SM2_PrivateKey(null_rng, domain, x));
   }

class SM2_Signature_KAT_Tests final : public PK_Signature_Generation_Test
   {
   public:
      SM2_Signature_KAT_Tests()
         : PK_Signature_Generation_Test(
            "SM2",
            "pubkey/sm2_sig.vec",
            "P,A,B,xG,yG,Order,Cofactor,Ident,Msg,x,Nonce,Signature",
            "Hash") {}

      bool clear_between_callbacks() const override { return false; }

      std::string default_padding(const VarMap& vars) const override
         {
         return vars.get_req_str("Ident") + "," + vars.get_opt_str("Hash", "SM3");
         }

      Botan::RandomNumberGenerator* test_rng(const std::vector<uint8_t>& nonce) const override
         {
         return new Fixed_Output_Position_RNG(nonce, 1);
         }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         return load_sm2_private_key(vars);
         }
   };

BOTAN_REGISTER_TEST("pubkey", "sm2_sig", SM2_Signature_KAT_Tests);

class SM2_Encryption_KAT_Tests final : public PK_Encryption_Decryption_Test
   {
   public:
      SM2_Encryption_KAT_Tests()
         : PK_Encryption_Decryption_Test(
            "SM2",
            "pubkey/sm2_enc.vec",
            "P,A,B,xG,yG,Order,Cofactor,Msg,x,Nonce,Ciphertext",
            "Hash") {}

      std::string default_padding(const VarMap& vars) const override
         {
         return vars.get_opt_str("Hash", "SM3");
         }

      bool clear_between_callbacks() const override { return false; }

      Botan::RandomNumberGenerator* test_rng(const std::vector<uint8_t>& nonce) const override
         {
         return new Fixed_Output_Position_RNG(nonce, 1);
         }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         return load_sm2_private_key(vars);
         }
   };

}

BOTAN_REGISTER_TEST("pubkey", "sm2_enc", SM2_Encryption_KAT_Tests);

class SM2_Keygen_Tests final : public PK_Key_Generation_Test
   {
   public:
      std::vector<std::string> keygen_params() const override
         {
         return { "secp256r1", "sm2p256v1" };
         }

      std::string algo_name() const override
         {
         return "SM2";
         }
   };

BOTAN_REGISTER_TEST("pubkey", "sm2_keygen", SM2_Keygen_Tests);


#endif

}
