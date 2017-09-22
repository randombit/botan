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
            "Group,Pubkey,Hash,Msg,Signature") {}

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override
         {
         const std::string group_id = get_req_str(vars, "Group");
         Botan::EC_Group group(Botan::OIDS::lookup(group_id));
         const Botan::PointGFp public_point = Botan::OS2ECP(get_req_bin(vars, "Pubkey"), group.get_curve());

         std::unique_ptr<Botan::Public_Key> key(new Botan::GOST_3410_PublicKey(group, public_point));
         return key;
         }

      std::string default_padding(const VarMap& vars) const override
         {
         return "EMSA1(" + get_req_str(vars, "Hash") + ")";
         }
   };

class GOST_3410_2001_Signature_Tests final : public PK_Signature_Generation_Test
   {
   public:
      GOST_3410_2001_Signature_Tests() : PK_Signature_Generation_Test(
            "GOST 34.10-2001",
            "pubkey/gost_3410_sign.vec",
            "Group,Privkey,Hash,Nonce,Msg,Signature") {}

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const std::string group_id = get_req_str(vars, "Group");
         const BigInt x = get_req_bn(vars, "Privkey");
         Botan::EC_Group group(Botan::OIDS::lookup(group_id));

         std::unique_ptr<Botan::Private_Key> key(new Botan::GOST_3410_PrivateKey(Test::rng(), group, x));
         return key;
         }

      std::string default_padding(const VarMap& vars) const override
         {
         return "EMSA1(" + get_req_str(vars, "Hash") + ")";
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
