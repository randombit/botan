/*
* (C) 2017 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include "test_rng.h"

#if defined(BOTAN_HAS_SM2)
   #include <botan/sm2.h>
   #include <botan/sm2_enc.h>
   #include "test_pubkey.h"
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_SM2)

namespace {

template<typename T>
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
   return std::unique_ptr<Botan::Private_Key>(new T(null_rng, domain, x));
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
         return load_sm2_private_key<Botan::SM2_Signature_PrivateKey>(vars);
         }
   };

BOTAN_REGISTER_TEST("sm2_sig", SM2_Signature_KAT_Tests);

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
         return load_sm2_private_key<Botan::SM2_Encryption_PrivateKey>(vars);
         }
   };

}

BOTAN_REGISTER_TEST("sm2_enc", SM2_Encryption_KAT_Tests);


#endif

}
