/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_GOST_34_10_2001)
   #include "test_pubkey.h"
   #include <botan/gost_3410.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_GOST_34_10_2001)

class GOST_3410_2001_Verification_Tests final : public PK_Signature_Verification_Test {
   public:
      GOST_3410_2001_Verification_Tests() :
            PK_Signature_Verification_Test(
               "GOST 34.10-2001", "pubkey/gost_3410_verify.vec", "P,A,B,Gx,Gy,Oid,Order,Px,Py,Hash,Msg,Signature") {}

      bool skip_this_test(const std::string&, const VarMap&) override {
         return !Botan::EC_Group::supports_application_specific_group();
      }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override {
         const BigInt p = vars.get_req_bn("P");
         const BigInt a = vars.get_req_bn("A");
         const BigInt b = vars.get_req_bn("B");
         const BigInt Gx = vars.get_req_bn("Gx");
         const BigInt Gy = vars.get_req_bn("Gy");
         const BigInt order = vars.get_req_bn("Order");
         const Botan::OID oid(vars.get_req_str("Oid"));

         Botan::EC_Group group(p, a, b, Gx, Gy, order, BigInt::one(), oid);

         const BigInt Px = vars.get_req_bn("Px");
         const BigInt Py = vars.get_req_bn("Py");

         const auto public_point = Botan::EC_AffinePoint::from_bigint_xy(group, Px, Py).value();

         return std::make_unique<Botan::GOST_3410_PublicKey>(group, public_point);
      }

      std::string default_padding(const VarMap& vars) const override { return vars.get_req_str("Hash"); }
};

class GOST_3410_2001_Signature_Tests final : public PK_Signature_Generation_Test {
   public:
      GOST_3410_2001_Signature_Tests() :
            PK_Signature_Generation_Test(
               "GOST 34.10-2001", "pubkey/gost_3410_sign.vec", "P,A,B,Gx,Gy,Oid,Order,X,Hash,Nonce,Msg,Signature") {}

      bool skip_this_test(const std::string&, const VarMap&) override {
         return !Botan::EC_Group::supports_application_specific_group();
      }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override {
         const BigInt p = vars.get_req_bn("P");
         const BigInt a = vars.get_req_bn("A");
         const BigInt b = vars.get_req_bn("B");
         const BigInt Gx = vars.get_req_bn("Gx");
         const BigInt Gy = vars.get_req_bn("Gy");
         const BigInt order = vars.get_req_bn("Order");
         const Botan::OID oid(vars.get_req_str("Oid"));

         Botan::EC_Group group(p, a, b, Gx, Gy, order, BigInt::one(), oid);

         const BigInt x = vars.get_req_bn("X");

         return std::make_unique<Botan::GOST_3410_PrivateKey>(this->rng(), group, x);
      }

      std::string default_padding(const VarMap& vars) const override { return vars.get_req_str("Hash"); }

      std::unique_ptr<Botan::RandomNumberGenerator> test_rng(const std::vector<uint8_t>& nonce) const override {
         return std::make_unique<Fixed_Output_Position_RNG>(nonce, 1, this->rng());
      }
};

class GOST_3410_2001_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override {
         std::vector<std::string> params;
         for(const auto& curve : {"gost_256A", "secp256r1"}) {
            if(Botan::EC_Group::supports_named_group(curve)) {
               params.push_back(curve);
            }
         }
         return params;
      }

      std::string algo_name() const override { return "GOST-34.10"; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view keygen_params,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> raw_pk) const override {
         const auto group = Botan::EC_Group(keygen_params);
         const auto public_key = Botan::EC_AffinePoint(group, raw_pk);
         return std::make_unique<Botan::GOST_3410_PublicKey>(group, public_key);
      }
};

BOTAN_REGISTER_TEST("pubkey", "gost_3410_verify", GOST_3410_2001_Verification_Tests);
BOTAN_REGISTER_TEST("pubkey", "gost_3410_sign", GOST_3410_2001_Signature_Tests);
BOTAN_REGISTER_TEST("pubkey", "gost_3410_keygen", GOST_3410_2001_Keygen_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
