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
         return get_req_str(vars, "Ident") + "," + get_opt_str(vars, "Hash", "SM3");
         }

      Botan::RandomNumberGenerator* test_rng(const std::vector<uint8_t>& nonce) const override
         {
         return new Fixed_Output_Position_RNG(nonce, 1);
         }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         // group params
         const BigInt p = get_req_bn(vars, "P");
         const BigInt a = get_req_bn(vars, "A");
         const BigInt b = get_req_bn(vars, "B");
         const BigInt xG = get_req_bn(vars, "xG");
         const BigInt yG = get_req_bn(vars, "yG");
         const BigInt order = get_req_bn(vars, "Order");
         const BigInt cofactor = get_req_bn(vars, "Cofactor");
         const BigInt x = get_req_bn(vars, "x");

         Botan::CurveGFp curve(p, a, b);
         Botan::PointGFp base_point(curve, xG, yG);
         Botan::EC_Group domain(curve, base_point, order, cofactor);

         Botan::Null_RNG null_rng;
         std::unique_ptr<Botan::Private_Key> key(new Botan::SM2_Signature_PrivateKey(null_rng, domain, x));
         return key;
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
         return get_opt_str(vars, "Hash", "SM3");
         }

      bool clear_between_callbacks() const override { return false; }

      Botan::RandomNumberGenerator* test_rng(const std::vector<uint8_t>& nonce) const override
         {
         return new Fixed_Output_Position_RNG(nonce, 1);
         }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         // group params
         const BigInt p = get_req_bn(vars, "P");
         const BigInt a = get_req_bn(vars, "A");
         const BigInt b = get_req_bn(vars, "B");
         const BigInt xG = get_req_bn(vars, "xG");
         const BigInt yG = get_req_bn(vars, "yG");
         const BigInt order = get_req_bn(vars, "Order");
         const BigInt cofactor = get_req_bn(vars, "Cofactor");
         const BigInt x = get_req_bn(vars, "x");

         Botan::CurveGFp curve(p, a, b);
         Botan::PointGFp base_point(curve, xG, yG);
         Botan::EC_Group domain(curve, base_point, order, cofactor);

         Botan::Null_RNG null_rng;
         std::unique_ptr<Botan::Private_Key> key(new Botan::SM2_Encryption_PrivateKey(null_rng, domain, x));
         return key;
         }
   };

}

BOTAN_REGISTER_TEST("sm2_enc", SM2_Encryption_KAT_Tests);


#endif

}
