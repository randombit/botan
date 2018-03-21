/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_GOST_34_10_2001)
   #include <botan/gost_3410.h>
   #include <botan/oids.h>
   #include "test_pubkey.h"
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_GOST_34_10_2001)

class GOST_3410_2001_Verification_Tests final : public PK_Signature_Verification_Test
   {
   public:
      GOST_3410_2001_Verification_Tests() : PK_Signature_Verification_Test(
            "GOST 34.10-2001",
            "pubkey/gost_3410_verify.vec",
            "P,A,B,Gx,Gy,Order,Cofactor,Px,Py,Hash,Msg,Signature") {}

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override
         {
         const BigInt p = get_req_bn(vars, "P");
         const BigInt a = get_req_bn(vars, "A");
         const BigInt b = get_req_bn(vars, "B");
         const BigInt Gx = get_req_bn(vars, "Gx");
         const BigInt Gy = get_req_bn(vars, "Gy");
         const BigInt order = get_req_bn(vars, "Order");
         const BigInt cofactor = get_req_bn(vars, "Cofactor");

         const BigInt Px = get_req_bn(vars, "Px");
         const BigInt Py = get_req_bn(vars, "Py");

         Botan::EC_Group group(p, a, b, Gx, Gy, order, cofactor);

         const Botan::PointGFp public_point = group.point(Px, Py);

         std::unique_ptr<Botan::Public_Key> key(new Botan::GOST_3410_PublicKey(group, public_point));
         return key;
         }

      std::string default_padding(const VarMap& vars) const override
         {
         const std::string hash = get_req_str(vars, "Hash");
         if(hash == "Raw")
            return hash;
         return "EMSA1(" + hash + ")";
         }
   };

class GOST_3410_2001_Signature_Tests final : public PK_Signature_Generation_Test
   {
   public:
      GOST_3410_2001_Signature_Tests() : PK_Signature_Generation_Test(
            "GOST 34.10-2001",
            "pubkey/gost_3410_sign.vec",
            "P,A,B,Gx,Gy,Order,X,Cofactor,Hash,Nonce,Msg,Signature") {}

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const BigInt p = get_req_bn(vars, "P");
         const BigInt a = get_req_bn(vars, "A");
         const BigInt b = get_req_bn(vars, "B");
         const BigInt Gx = get_req_bn(vars, "Gx");
         const BigInt Gy = get_req_bn(vars, "Gy");
         const BigInt order = get_req_bn(vars, "Order");
         const BigInt cofactor = get_req_bn(vars, "Cofactor");

         const BigInt x = get_req_bn(vars, "X");

         const Botan::OID oid("1.3.6.1.4.1.25258.2");

         Botan::EC_Group group(p, a, b, Gx, Gy, order, cofactor, oid);

         std::unique_ptr<Botan::Private_Key> key(new Botan::GOST_3410_PrivateKey(Test::rng(), group, x));
         return key;
         }

      std::string default_padding(const VarMap& vars) const override
         {
         const std::string hash = get_req_str(vars, "Hash");
         if(hash == "Raw")
            return hash;
         return "EMSA1(" + hash + ")";
         }

      Botan::RandomNumberGenerator* test_rng(const std::vector<uint8_t>& nonce) const override
         {
         return new Fixed_Output_Position_RNG(nonce, 1);
         }
   };

class GOST_3410_2001_Keygen_Tests final : public PK_Key_Generation_Test
   {
   public:
      std::vector<std::string> keygen_params() const override
         {
         return { "gost_256A", "secp256r1" };
         }
      std::string algo_name() const override
         {
         return "GOST-34.10";
         }
   };

BOTAN_REGISTER_TEST("gost_3410_verify", GOST_3410_2001_Verification_Tests);
BOTAN_REGISTER_TEST("gost_3410_sign", GOST_3410_2001_Signature_Tests);
BOTAN_REGISTER_TEST("gost_3410_keygen", GOST_3410_2001_Keygen_Tests);

#endif

}

}
