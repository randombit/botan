/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   #include "test_pubkey.h"
   #include <botan/pubkey.h>
   #include <botan/dh.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)

class Diffie_Hellman_KAT_Tests final : public PK_Key_Agreement_Test
   {
   public:
      Diffie_Hellman_KAT_Tests()
         : PK_Key_Agreement_Test(
              "Diffie-Hellman",
              "pubkey/dh.vec",
              "P,G,X,Y,Msg,OutLen,K",
              "Q,KDF") {}

      std::string default_kdf(const VarMap&) const override
         {
         return "Raw";
         }

      std::unique_ptr<Botan::Private_Key> load_our_key(const std::string&, const VarMap& vars) override
         {
         const Botan::BigInt p = vars.get_req_bn("P");
         const Botan::BigInt q = vars.get_opt_bn("Q", 0);
         const Botan::BigInt g = vars.get_req_bn("G");
         const Botan::BigInt x = vars.get_req_bn("X");

         Botan::DL_Group grp;
         if(q == 0)
            {
            grp = Botan::DL_Group(p, g);
            }
         else
            {
            grp = Botan::DL_Group(p, q, g);
            }

         std::unique_ptr<Botan::Private_Key> key(new Botan::DH_PrivateKey(Test::rng(), grp, x));
         return key;
         }

      std::vector<uint8_t> load_their_key(const std::string&, const VarMap& vars) override
         {
         const Botan::BigInt p = vars.get_req_bn("P");
         const Botan::BigInt q = vars.get_opt_bn("Q", 0);
         const Botan::BigInt g = vars.get_req_bn("G");
         const Botan::BigInt y = vars.get_req_bn("Y");

         Botan::DL_Group grp;
         if(q == 0)
            {
            grp = Botan::DL_Group(p, g);
            }
         else
            {
            grp = Botan::DL_Group(p, q, g);
            }

         Botan::DH_PublicKey key(grp, y);
         return key.public_value();
         }

      std::vector<Test::Result> run_final_tests() override
         {
         Test::Result result("DH negative tests");

         const BigInt g("2");
         const BigInt p("58458002095536094658683755258523362961421200751439456159756164191494576279467");
         const Botan::DL_Group grp(p, g);

         const Botan::BigInt x("46205663093589612668746163860870963912226379131190812163519349848291472898748");
         std::unique_ptr<Botan::Private_Key> privkey(new Botan::DH_PrivateKey(Test::rng(), grp, x));

         std::unique_ptr<Botan::PK_Key_Agreement> kas(new Botan::PK_Key_Agreement(*privkey, rng(), "Raw"));

         result.test_throws("agreement input too big",
                            "DH agreement - invalid key provided",
                            [&kas]()
            {
            const BigInt too_big("584580020955360946586837552585233629614212007514394561597561641914945762794672");
            kas->derive_key(16, BigInt::encode(too_big));
            });

         result.test_throws("agreement input too small",
                            "DH agreement - invalid key provided",
                            [&kas]()
            {
            const BigInt too_small("1");
            kas->derive_key(16, BigInt::encode(too_small));
            });

         return{result};
         }

   };

class DH_Invalid_Key_Tests final : public Text_Based_Test
   {
   public:
      DH_Invalid_Key_Tests() :
         Text_Based_Test("pubkey/dh_invalid.vec", "P,Q,G,InvalidKey") {}

      bool clear_between_callbacks() const override
         {
         return false;
         }

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("DH invalid keys");

         const Botan::BigInt p = vars.get_req_bn("P");
         const Botan::BigInt q = vars.get_req_bn("Q");
         const Botan::BigInt g = vars.get_req_bn("G");
         const Botan::BigInt pubkey = vars.get_req_bn("InvalidKey");

         Botan::DL_Group grp(p, q, g);
         std::unique_ptr<Botan::Public_Key> key(new Botan::DH_PublicKey(grp, pubkey));
         result.test_eq("public key fails check", key->check_key(Test::rng(), false), false);
         return result;
         }
   };

class Diffie_Hellman_Keygen_Tests final : public PK_Key_Generation_Test
   {
   public:
      std::vector<std::string> keygen_params() const override
         {
         return { "modp/ietf/1024" };
         }
      std::string algo_name() const override
         {
         return "DH";
         }
   };

BOTAN_REGISTER_TEST("pubkey", "dh_kat", Diffie_Hellman_KAT_Tests);
BOTAN_REGISTER_TEST("pubkey", "dh_invalid", DH_Invalid_Key_Tests);

BOTAN_REGISTER_TEST("pubkey", "dh_keygen", Diffie_Hellman_Keygen_Tests);

#endif

}

}
