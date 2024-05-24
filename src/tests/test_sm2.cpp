/*
* (C) 2017 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_rng.h"
#include "tests.h"

#if defined(BOTAN_HAS_SM2)
   #include "test_pubkey.h"
   #include <botan/sm2.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_SM2)

namespace {

std::unique_ptr<Botan::Private_Key> load_sm2_private_key(const VarMap& vars) {
   // group params
   const BigInt p = vars.get_req_bn("P");
   const BigInt a = vars.get_req_bn("A");
   const BigInt b = vars.get_req_bn("B");
   const BigInt xG = vars.get_req_bn("xG");
   const BigInt yG = vars.get_req_bn("yG");
   const BigInt order = vars.get_req_bn("Order");
   const BigInt x = vars.get_req_bn("x");
   const Botan::OID oid = Botan::OID(vars.get_req_str("Oid"));

   Botan::EC_Group domain(oid, p, a, b, xG, yG, order);

   Botan::Null_RNG null_rng;
   return std::make_unique<Botan::SM2_PrivateKey>(null_rng, domain, x);
}

class SM2_Signature_KAT_Tests final : public PK_Signature_Generation_Test {
   public:
      SM2_Signature_KAT_Tests() :
            PK_Signature_Generation_Test(
               "SM2", "pubkey/sm2_sig.vec", "P,A,B,xG,yG,Order,Oid,Ident,Msg,x,Nonce,Signature", "Hash") {}

      bool clear_between_callbacks() const override { return false; }

      std::string default_padding(const VarMap& vars) const override {
         return vars.get_req_str("Ident") + "," + vars.get_opt_str("Hash", "SM3");
      }

      std::unique_ptr<Botan::RandomNumberGenerator> test_rng(const std::vector<uint8_t>& nonce) const override {
         return std::make_unique<Fixed_Output_Position_RNG>(nonce, 1, this->rng());
      }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override {
         return load_sm2_private_key(vars);
      }
};

BOTAN_REGISTER_TEST("pubkey", "sm2_sig", SM2_Signature_KAT_Tests);

class SM2_Encryption_KAT_Tests final : public PK_Encryption_Decryption_Test {
   public:
      SM2_Encryption_KAT_Tests() :
            PK_Encryption_Decryption_Test(
               "SM2", "pubkey/sm2_enc.vec", "P,A,B,xG,yG,Order,Oid,Msg,x,Nonce,Ciphertext", "Hash") {}

      std::string default_padding(const VarMap& vars) const override { return vars.get_opt_str("Hash", "SM3"); }

      bool clear_between_callbacks() const override { return false; }

      std::unique_ptr<Botan::RandomNumberGenerator> test_rng(const std::vector<uint8_t>& nonce) const override {
         return std::make_unique<Fixed_Output_Position_RNG>(nonce, 1, this->rng());
      }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override {
         return load_sm2_private_key(vars);
      }
};

}  // namespace

BOTAN_REGISTER_TEST("pubkey", "sm2_enc", SM2_Encryption_KAT_Tests);

class SM2_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override { return {"secp256r1", "sm2p256v1"}; }

      std::string algo_name() const override { return "SM2"; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view keygen_params,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> raw_pk) const override {
         const auto group = Botan::EC_Group(keygen_params);
         const auto public_point = group.OS2ECP(raw_pk);
         return std::make_unique<Botan::SM2_PublicKey>(group, public_point);
      }
};

BOTAN_REGISTER_TEST("pubkey", "sm2_keygen", SM2_Keygen_Tests);

#endif

}  // namespace Botan_Tests
