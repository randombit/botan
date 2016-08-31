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

class Diffie_Hellman_KAT_Tests : public PK_Key_Agreement_Test
   {
   public:
      Diffie_Hellman_KAT_Tests() : PK_Key_Agreement_Test(
         "Diffie-Hellman",
         "pubkey/dh.vec",
         {"P", "G", "X", "Y", "Msg", "OutLen", "K"},
         {"KDF"})
         {}

      std::string default_kdf(const VarMap&) const override { return "Raw"; }

      std::unique_ptr<Botan::Private_Key> load_our_key(const std::string&, const VarMap& vars) override
         {
         const Botan::BigInt p = get_req_bn(vars, "P");
         const Botan::BigInt g = get_req_bn(vars, "G");
         const Botan::BigInt x = get_req_bn(vars, "X");

         const Botan::DL_Group grp(p, g);

         std::unique_ptr<Botan::Private_Key> key(new Botan::DH_PrivateKey(Test::rng(), grp, x));
         return key;
         }

      std::vector<uint8_t> load_their_key(const std::string&, const VarMap& vars) override
         {
         const Botan::BigInt p = get_req_bn(vars, "P");
         const Botan::BigInt g = get_req_bn(vars, "G");
         const Botan::BigInt y = get_req_bn(vars, "Y");
         const Botan::DL_Group grp(p, g);

         Botan::DH_PublicKey key(grp, y);
         return key.public_value();
         }

      std::vector<Test::Result> run_final_tests() override
         {
         using namespace Botan;

         Test::Result result("DH negative tests");

         const BigInt g("2");
         const BigInt p("58458002095536094658683755258523362961421200751439456159756164191494576279467");
         const DL_Group grp(p, g);

         const Botan::BigInt x("46205663093589612668746163860870963912226379131190812163519349848291472898748");
         std::unique_ptr<Private_Key> privkey(new DH_PrivateKey(Test::rng(), grp, x));

         std::unique_ptr<PK_Key_Agreement> kas(new PK_Key_Agreement(*privkey, "Raw"));

         result.test_throws("agreement input too big", [&kas]()
            {
            const BigInt too_big("584580020955360946586837552585233629614212007514394561597561641914945762794672");
            kas->derive_key(16, BigInt::encode(too_big));
            });

         result.test_throws("agreement input too small", [&kas]()
            {
            const BigInt too_small("1");
            kas->derive_key(16, BigInt::encode(too_small));
            });

         return{result};
         }

   };

BOTAN_REGISTER_TEST("dh_kat", Diffie_Hellman_KAT_Tests);

class Diffie_Hellman_Keygen_Tests : public PK_Key_Generation_Test
   {
   public:
      std::vector<std::string> keygen_params() const override { return { "modp/ietf/1024", "modp/ietf/2048" }; }

      std::unique_ptr<Botan::Private_Key> make_key(Botan::RandomNumberGenerator& rng,
                                                   const std::string& param) const override
         {
         Botan::DL_Group group(param);
         std::unique_ptr<Botan::Private_Key> key(new Botan::DH_PrivateKey(rng, group));
         return key;
         }
   };


BOTAN_REGISTER_TEST("dh_keygen", Diffie_Hellman_Keygen_Tests);

#endif

}

}
