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
         results.push_back(test_dl_generate(rng));

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

         result.start_timer();

         Botan::DL_Group dh1050(rng, Botan::DL_Group::Prime_Subgroup, 1050, 175);
         result.test_eq("DH p size", dh1050.get_p().bits(), 1050);
         result.test_eq("DH q size", dh1050.get_q().bits(), 175);
         result.test_lte("DH g size", dh1050.get_g().bits(), 1050);
         result.test_eq("DH group verifies", dh1050.verify_group(rng, true), true);

#if defined(BOTAN_HAS_SHA1)
         Botan::DL_Group dsa1024(rng, Botan::DL_Group::DSA_Kosherizer, 1024);
         result.test_eq("DSA p size", dsa1024.get_p().bits(), 1024);
         result.test_eq("DSA q size", dsa1024.get_q().bits(), 160);
         result.test_lte("DSA g size", dsa1024.get_g().bits(), 1024);
         result.test_eq("DSA group verifies", dsa1024.verify_group(rng, true), true);
#endif

#if defined(BOTAN_HAS_SHA1)
         // From FIPS 186-3 test data
         const std::vector<uint8_t> seed = Botan::hex_decode("1F5DA0AF598EEADEE6E6665BF880E63D8B609BA2");

         result.test_throws("invalid params", [&] { Botan::DL_Group invalid(rng, seed, 1024, 224); });
         result.test_throws("invalid params", [&] { Botan::DL_Group invalid(rng, seed, 3072, 224); });
         result.test_throws("invalid params", [&] { Botan::DL_Group invalid(rng, seed, 2048, 256); });

         Botan::DL_Group dsa_from_seed(rng, seed, 1024, 160);

         result.test_eq("DSA q from seed", dsa_from_seed.get_q(),
                        Botan::BigInt("0xAB1A788BCE3C557A965A5BFA6908FAA665FDEB7D"));

         // Modulo just to avoid embedding entire 1024-bit P in src file
         result.test_eq("DSA p from seed", static_cast<size_t>(dsa_from_seed.get_p() % 4294967291), size_t(2513712339));

         result.test_eq("DSA group from seed verifies", dsa_from_seed.verify_group(rng, true), true);
#endif

         result.end_timer();

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
            // Confirm we can load every group we expect
            Botan::DL_Group group(name);

            result.test_ne("DL_Group p is set", group.get_p(), 0);
            result.test_ne("DL_Group g is set", group.get_g(), 0);

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

            if(group.get_p().bits() < 2048 || Test::run_long_tests())
               {
               // These two groups fail verification because pow(g,q,p) != 1
               if(name != "modp/srp/1024" && name != "modp/srp/2048")
                  {
                  result.test_eq(name + " verifies", group.verify_group(rng, false), true);
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
