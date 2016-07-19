/*
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_OID_LOOKUP)
   #include <botan/oids.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_OID_LOOKUP)

Test::Result test_add_have_OID()
   {
   Test::Result result("OID add");

   result.test_eq("there is no OID 'botan-test-oid1'", Botan::OIDS::have_oid("botan-test-oid1"), false);

   Botan::OIDS::add_oid(Botan::OID("1.2.345.6.666"), "botan-test-oid1");

   result.test_eq("OID 'botan-test-oid1' added successfully", Botan::OIDS::have_oid("botan-test-oid1"), true);

   result.test_eq("name of OID '1.2.345.6.666' is 'botan-test-oid1'", Botan::OIDS::name_of(Botan::OID("1.2.345.6.666"),
                  "botan-test-oid1"), true);

   return result;
   }

Test::Result test_add_have_OID_str()
   {
   Test::Result result("OID add string");

   result.test_eq("there is no OID 'botan-test-oid2'", Botan::OIDS::have_oid("botan-test-oid2"), false);

   Botan::OIDS::add_oidstr("1.2.345.6.777", "botan-test-oid2");

   result.test_eq("OID 'botan-test-oid2' added successfully", Botan::OIDS::have_oid("botan-test-oid2"), true);

   result.test_eq("name of OID '1.2.345.6.777' is 'botan-test-oid2'", Botan::OIDS::name_of(Botan::OID("1.2.345.6.777"),
                  "botan-test-oid2"), true);
   return result;
   }

Test::Result test_add_and_lookup()
   {
   Test::Result result("OID add and lookup");

   result.test_eq("OIDS::lookup returns empty string for non-existent OID object",
                  Botan::OIDS::lookup(Botan::OID("1.2.345.6.888")), std::string());

   result.test_throws("OIDS::lookup thows for non-existent OID name", []()
      {
      Botan::OIDS::lookup("botan-test-oid3");
      });

   // add oid -> string mapping
   Botan::OIDS::add_oid2str(Botan::OID("1.2.345.6.888"), "botan-test-oid3");
   result.test_eq("", Botan::OIDS::lookup(Botan::OID("1.2.345.6.888")), "botan-test-oid3");

   // still throws
   result.test_throws("OIDS::lookup still throws without adding name mapping", []()
      {
      Botan::OIDS::lookup("botan-test-oid3");
      });

   // add string -> oid mapping
   Botan::OIDS::add_str2oid(Botan::OID("1.2.345.6.888"), "botan-test-oid3");
   Botan::OIDS::lookup("botan-test-oid3");

   return result;
   }

class OID_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         std::vector<std::function<Test::Result()>> fns =
            {
            test_add_have_OID,
            test_add_have_OID_str,
            test_add_and_lookup,
            };

         for(size_t i = 0; i != fns.size(); ++i)
            {
            try
               {
               results.push_back(fns[ i ]());
               }
            catch(std::exception& e)
               {
               results.push_back(Test::Result::Failure("OID tests " + std::to_string(i), e.what()));
               }
            }

         return results;
         }
   };

BOTAN_REGISTER_TEST("oid", OID_Tests);

#endif

}

}
