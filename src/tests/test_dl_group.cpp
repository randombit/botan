/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#define BOTAN_NO_DEPRECATED_WARNINGS

#include "tests.h"

#if defined(BOTAN_HAS_DL_GROUP)
   #include <botan/dl_group.h>
   #include <botan/workfactor.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_DL_GROUP)

namespace {

class DL_Group_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(test_dl_encoding());
         results.push_back(test_dl_errors());

         return results;
         }

   private:
      Test::Result test_dl_errors()
         {
         Test::Result result("DL_Group errors");
         result.test_throws("Uninitialized",
                            "DL_Group uninitialized",
                            []() { Botan::DL_Group dl; dl.get_p(); });

#if !defined(BOTAN_HAS_SANITIZER_UNDEFINED)
         result.test_throws("Bad generator param",
                            "DL_Group unknown PrimeType",
                            []() {
                            auto invalid_type = static_cast<Botan::DL_Group::PrimeType>(9);
                            Botan::DL_Group dl(Test::rng(), invalid_type, 1024);
             });
#endif

         return result;
         }

      Test::Result test_dl_encoding()
         {
         Test::Result result("DL_Group encoding");

         const Botan::DL_Group orig("modp/ietf/1024");

         const std::string pem1 = orig.PEM_encode(Botan::DL_Group::ANSI_X9_42);
         const std::string pem2 = orig.PEM_encode(Botan::DL_Group::ANSI_X9_57);
         const std::string pem3 = orig.PEM_encode(Botan::DL_Group::PKCS_3);

         Botan::DL_Group group1(pem1);

         result.test_eq("Same p in X9.42 decoding", group1.get_p(), orig.get_p());
         result.test_eq("Same q in X9.42 decoding", group1.get_q(), orig.get_q());
         result.test_eq("Same g in X9.42 decoding", group1.get_g(), orig.get_g());

         result.test_eq("PEM encodings match",
                        group1.PEM_encode(Botan::DL_Group::ANSI_X9_42),
                        Botan::DL_Group::PEM_for_named_group("modp/ietf/1024"));

         Botan::DL_Group group2(pem2);

         result.test_eq("Same p in X9.57 decoding", group2.get_p(), orig.get_p());
         result.test_eq("Same q in X9.57 decoding", group2.get_q(), orig.get_q());
         result.test_eq("Same g in X9.57 decoding", group2.get_g(), orig.get_g());

         Botan::DL_Group group3(pem3);

         result.test_eq("Same p in X9.57 decoding", group3.get_p(), orig.get_p());
         // no q in PKCS #3 format
         result.test_eq("Same g in X9.57 decoding", group3.get_g(), orig.get_g());

         return result;
         }
   };

BOTAN_REGISTER_TEST("pubkey", "dl_group", DL_Group_Tests);

class DL_Generate_Group_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         Test::Result result("DL_Group generate");

         result.start_timer();

         auto& rng = Test::rng();

         Botan::DL_Group dh1050(rng, Botan::DL_Group::Prime_Subgroup, 1050, 175);
         result.test_eq("DH p size", dh1050.get_p().bits(), 1050);
         result.test_eq("DH q size", dh1050.get_q().bits(), 175);
         result.test_lte("DH g size", dh1050.get_g().bits(), 1050);
         result.test_eq("DH group verifies", dh1050.verify_group(rng, true), true);

         Botan::DL_Group dh_implicit_q(rng, Botan::DL_Group::Prime_Subgroup, 1040);
         result.test_eq("DH p size", dh_implicit_q.get_p().bits(), 1040);
         result.test_eq("DH q size", dh_implicit_q.get_q().bits(), Botan::dl_exponent_size(1040));
         result.test_eq("DH group verifies", dh_implicit_q.verify_group(rng, true), true);

         if(Test::run_long_tests())
            {
            Botan::DL_Group dh_strong(rng, Botan::DL_Group::Strong, 1025);
            result.test_eq("DH p size", dh_strong.get_p().bits(), 1025);
            result.test_eq("DH q size", dh_strong.get_q().bits(), 1024);
            result.test_eq("DH group verifies", dh_strong.verify_group(rng, true), true);
            }

#if defined(BOTAN_HAS_SHA1)
         Botan::DL_Group dsa1024(rng, Botan::DL_Group::DSA_Kosherizer, 1024);
         result.test_eq("DSA p size", dsa1024.get_p().bits(), 1024);
         result.test_eq("DSA q size", dsa1024.get_q().bits(), 160);
         result.test_lte("DSA g size", dsa1024.get_g().bits(), 1024);
         result.test_eq("DSA group verifies", dsa1024.verify_group(rng, true), true);

         const std::vector<uint8_t> short_seed(16);
         const std::vector<uint8_t> invalid_seed(20);
         const std::vector<uint8_t> working_seed = Botan::hex_decode("0000000000000000000000000000000000000021");

         result.test_throws("DSA seed does not generate group",
                            "DL_Group: The seed given does not generate a DSA group",
                            [&rng,&invalid_seed]() { Botan::DL_Group dsa(rng, invalid_seed, 1024, 160); });

         result.test_throws("DSA seed is too short",
                            "Generating a DSA parameter set with a 160 bit long q requires a seed at least as many bits long",
                            [&rng,&short_seed]() { Botan::DL_Group dsa(rng, short_seed, 1024, 160); });

         // From FIPS 186-3 test data
         const std::vector<uint8_t> seed = Botan::hex_decode("1F5DA0AF598EEADEE6E6665BF880E63D8B609BA2");

         result.test_throws("invalid params", [&]() { Botan::DL_Group invalid(rng, seed, 1024, 224); });
         result.test_throws("invalid params", [&]() { Botan::DL_Group invalid(rng, seed, 3072, 224); });
         result.test_throws("invalid params", [&]() { Botan::DL_Group invalid(rng, seed, 2048, 256); });

         Botan::DL_Group dsa_from_seed(rng, seed, 1024, 160);

         result.test_eq("DSA q from seed", dsa_from_seed.get_q(),
                        Botan::BigInt("0xAB1A788BCE3C557A965A5BFA6908FAA665FDEB7D"));

         // Modulo just to avoid embedding entire 1024-bit P in src file
         result.test_eq("DSA p from seed", static_cast<size_t>(dsa_from_seed.get_p() % 4294967291), size_t(2513712339));

         result.test_eq("DSA group from seed verifies", dsa_from_seed.verify_group(rng, true), true);
#endif

         result.end_timer();

         return {result};
         }
   };

BOTAN_REGISTER_TEST("pubkey", "dl_group_gen", DL_Generate_Group_Tests);

class DL_Named_Group_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         const std::vector<std::string> dl_named =
            {
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

            "ffdhe/ietf/2048",
            "ffdhe/ietf/3072",
            "ffdhe/ietf/4096",
            "ffdhe/ietf/6144",
            "ffdhe/ietf/8192",
            };

         Test::Result result("DL_Group named");
         result.start_timer();

         for(std::string name : dl_named)
            {
            // Confirm we can load every group we expect
            Botan::DL_Group group(name);

            result.test_ne("DL_Group p is set", group.get_p(), 0);
            result.test_ne("DL_Group g is set", group.get_g(), 0);

            const size_t strength = group.estimated_strength();

            // 8192 bit ~~ 2**202 strength
            result.confirm("Plausible strength", strength >= 80 && strength < 210);

            result.confirm("Expected source", group.source() == Botan::DL_Group_Source::Builtin);

            if(name.find("modp/srp/") == std::string::npos)
               {
               result.test_ne("DL_Group q is set", group.get_q(), 0);
               }
            else
               {
               result.test_eq("DL_Group q is not set for SRP groups", group.get_q(), 0);
               }

            if(group.p_bits() <= 1536 || Test::run_long_tests())
               {
               result.test_eq(name + " strong verifies", group.verify_group(Test::rng(), true), true);
               }

            }
         result.end_timer();

         return {result};
         }
   };

BOTAN_REGISTER_TEST("pubkey", "dl_group_named", DL_Named_Group_Tests);

}

#endif

}
