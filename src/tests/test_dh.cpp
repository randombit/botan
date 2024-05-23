/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   #include "test_pubkey.h"
   #include <botan/dh.h>
   #include <botan/dl_group.h>
   #include <botan/pubkey.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)

class Diffie_Hellman_KAT_Tests final : public PK_Key_Agreement_Test {
   public:
      Diffie_Hellman_KAT_Tests() :
            PK_Key_Agreement_Test("Diffie-Hellman", "pubkey/dh.vec", "P,G,X,Y,K", "Q,KDF,OutLen") {}

      std::string default_kdf(const VarMap& /*unused*/) const override { return "Raw"; }

      std::unique_ptr<Botan::Private_Key> load_our_key(const std::string& /*header*/, const VarMap& vars) override {
         const Botan::BigInt p = vars.get_req_bn("P");
         const Botan::BigInt q = vars.get_opt_bn("Q", 0);
         const Botan::BigInt g = vars.get_req_bn("G");
         const Botan::BigInt x = vars.get_req_bn("X");

         Botan::DL_Group group;
         if(q == 0) {
            group = Botan::DL_Group(p, g);
         } else {
            group = Botan::DL_Group(p, q, g);
         }

         return std::make_unique<Botan::DH_PrivateKey>(group, x);
      }

      std::vector<uint8_t> load_their_key(const std::string& /*header*/, const VarMap& vars) override {
         const Botan::BigInt p = vars.get_req_bn("P");
         const Botan::BigInt q = vars.get_opt_bn("Q", 0);
         const Botan::BigInt g = vars.get_req_bn("G");
         const Botan::BigInt y = vars.get_req_bn("Y");

         Botan::DL_Group group;
         if(q == 0) {
            group = Botan::DL_Group(p, g);
         } else {
            group = Botan::DL_Group(p, q, g);
         }

         Botan::DH_PublicKey key(group, y);
         return key.public_value();
      }

      std::vector<Test::Result> run_final_tests() override {
         Test::Result result("DH negative tests");

         const BigInt g("2");
         const BigInt p("58458002095536094658683755258523362961421200751439456159756164191494576279467");
         const Botan::DL_Group group(p, g);

         const Botan::BigInt x("46205663093589612668746163860870963912226379131190812163519349848291472898748");
         auto privkey = std::make_unique<Botan::DH_PrivateKey>(group, x);

         auto kas = std::make_unique<Botan::PK_Key_Agreement>(*privkey, this->rng(), "Raw");

         result.test_throws("agreement input too big", "DH agreement - invalid key provided", [&kas]() {
            const BigInt too_big("584580020955360946586837552585233629614212007514394561597561641914945762794672");
            kas->derive_key(16, BigInt::encode(too_big));
         });

         result.test_throws("agreement input too small", "DH agreement - invalid key provided", [&kas]() {
            const BigInt too_small("1");
            kas->derive_key(16, BigInt::encode(too_small));
         });

         return {result};
      }
};

class DH_Invalid_Key_Tests final : public Text_Based_Test {
   public:
      DH_Invalid_Key_Tests() : Text_Based_Test("pubkey/dh_invalid.vec", "P,Q,G,InvalidKey") {}

      bool clear_between_callbacks() const override { return false; }

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("DH invalid keys");

         const Botan::BigInt p = vars.get_req_bn("P");
         const Botan::BigInt q = vars.get_req_bn("Q");
         const Botan::BigInt g = vars.get_req_bn("G");
         const Botan::BigInt pubkey = vars.get_req_bn("InvalidKey");

         Botan::DL_Group group(p, q, g);

         auto key = std::make_unique<Botan::DH_PublicKey>(group, pubkey);
         result.test_eq("public key fails check", key->check_key(this->rng(), false), false);
         return result;
      }
};

class Diffie_Hellman_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override { return {"modp/ietf/1024"}; }

      std::string algo_name() const override { return "DH"; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view keygen_params,
                                                             std::string_view /*provider*/,
                                                             std::span<const uint8_t> raw_key_bits) const override {
         return std::make_unique<Botan::DH_PublicKey>(Botan::DL_Group(keygen_params), Botan::BigInt(raw_key_bits));
      }
};

BOTAN_REGISTER_TEST("pubkey", "dh_kat", Diffie_Hellman_KAT_Tests);
BOTAN_REGISTER_TEST("pubkey", "dh_invalid", DH_Invalid_Key_Tests);

BOTAN_REGISTER_TEST("pubkey", "dh_keygen", Diffie_Hellman_Keygen_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
