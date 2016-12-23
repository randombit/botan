/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DL_GROUP)
  #include <botan/dl_group.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_DL_GROUP)

namespace {

class DL_Group_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         Botan::RandomNumberGenerator& rng = Test::rng();

         results.push_back(test_dl_encoding());
         results.push_back(test_dl_named(rng));
         //results.push_back(test_dl_generate(rng));

         return results;
         }

   private:
      Test::Result test_dl_encoding()
         {
         Test::Result result("DL_Group encoding");

         const Botan::DL_Group orig("modp/ietf/1024");

         const std::string pem1 = orig.PEM_encode(Botan::DL_Group::ANSI_X9_42);
         const std::string pem2 = orig.PEM_encode(Botan::DL_Group::ANSI_X9_57);
         const std::string pem3 = orig.PEM_encode(Botan::DL_Group::PKCS_3);

         Botan::DL_Group group;

         group.PEM_decode(pem1);

         result.test_eq("Same p in X9.42 decoding", group.get_p(), orig.get_p());
         result.test_eq("Same q in X9.42 decoding", group.get_q(), orig.get_q());
         result.test_eq("Same g in X9.42 decoding", group.get_g(), orig.get_g());

         group.PEM_decode(pem2);

         result.test_eq("Same p in X9.57 decoding", group.get_p(), orig.get_p());
         result.test_eq("Same q in X9.57 decoding", group.get_q(), orig.get_q());
         result.test_eq("Same g in X9.57 decoding", group.get_g(), orig.get_g());

         group.PEM_decode(pem3);

         result.test_eq("Same p in X9.57 decoding", group.get_p(), orig.get_p());
         // no q in PKCS #3 format
         result.test_eq("Same g in X9.57 decoding", group.get_g(), orig.get_g());

         return result;
         }

      Test::Result test_dl_generate(Botan::RandomNumberGenerator& rng)
         {
         Test::Result result("DL_Group generate");

         Botan::DL_Group dsa1024(rng, Botan::DL_Group::DSA_Kosherizer, 1024);

         result.test_eq("DSA p size", dsa1024.get_p().bits(), 1024);
         result.test_eq("DSA q size", dsa1024.get_q().bits(), 160);
         result.test_eq("DSA g size", dsa1024.get_g().bits(), 1024);
         result.test_eq("DSA group verifies", dsa1024.verify_group(rng, true), true);

         Botan::DL_Group dh1050(rng, Botan::DL_Group::Prime_Subgroup, 1050, 175);
         result.test_eq("DH p size", dh1050.get_p().bits(), 1050);
         result.test_eq("DH q size", dh1050.get_q().bits(), 175);
         result.test_eq("DH g size", dh1050.get_g().bits(), 2);
         result.test_eq("DH group verifies", dh1050.verify_group(rng, true), true);

         return result;
         }

      Test::Result test_dl_named(Botan::RandomNumberGenerator& rng)
         {
         const std::vector<std::string> dl_named = {
            "modp/ietf/1024",
            "modp/ietf/1536",
            "modp/ietf/2048",
            "modp/ietf/3072",
            "modp/ietf/4096",
            "modp/ietf/6144",
            "modp/ietf/8192",

            "modp/srp/1024",
            "modp/srp/1536",
            "modp/srp/2048",
            "modp/srp/3072",
            "modp/srp/4096",
            "modp/srp/6144",
            "modp/srp/8192",

            "dsa/jce/1024",
            "dsa/botan/2048",
            "dsa/botan/3072",
         };

         Test::Result result("DL_Group named");
         result.start_timer();

         for(std::string name : dl_named)
            {
            Botan::DL_Group group(name);

            // These two groups fail verification because pow(g,q,p) != 1
            if(name != "modp/srp/1024" && name != "modp/srp/1536")
               {
               result.test_eq(name + " verifies", group.verify_group(rng, false), true);
               }

            if(name.find("/srp/") == std::string::npos)
               {
               try
                  {
                  group.get_q(); // confirm all our non-SRP groups have q
                  }
               catch(Botan::Invalid_State&)
                  {
                  result.test_failure("Group " + name + " has no q");
                  }
               }
            }
         result.end_timer();

         return result;
         }
   };

BOTAN_REGISTER_TEST("dl_group", DL_Group_Tests);

}

#endif

}
