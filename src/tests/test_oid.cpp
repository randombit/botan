/*
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ASN1)
   #include <botan/oids.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ASN1)

Test::Result test_OID_to_string()
   {
   /*
   See #2730 and #2237

   Certain locales format integers with thousands seperators.  This
   caused a subtle bug which caused OID comparisons to fail because
   OID::to_string(), which used ostringstream, introduced a thousands
   seperator when the OID component had a value >= 1000. But this
   only failed in certain locales (pt_BR was reported).

   Nominally C++ requires std::to_string to also be locale-respecting.
   But, libc++, libstdc++, and MSVC's STL library all implement
   std::to_string in a way that ignores locales, because adding locale
   support means std::to_string will be both slow and a serialization
   point. So as a stopgap we assume this behavior from std::to_string.

   Here we test the original issue of #2237 to verify it works. If
   the compiler implements std::to_string in a way that respects locale,
   *and* this test is run in a locale that uses thousands seperators,
   then it will fail. Which is much better than a very subtle failure.
   However if it ever does fail then we must replace nearly every
   call to std::to_string with something else that ignores locale.
   */

   Botan::OID oid{1,2,1000,1001,1002000};

   Test::Result result("OID::to_string");

   result.test_eq("OID::to_string behaves as we expect",
                  oid.to_string(), "1.2.1000.1001.1002000");

   return result;
   }

Test::Result test_add_have_OID()
   {
   Test::Result result("OID add");

   result.test_eq("there is no OID 'botan-test-oid1'", Botan::OIDS::str2oid_or_empty("botan-test-oid1").has_value(), false);

   Botan::OIDS::add_oid(Botan::OID("1.2.345.6.666"), "botan-test-oid1");

   result.test_eq("OID 'botan-test-oid1' added successfully", Botan::OIDS::str2oid_or_empty("botan-test-oid1").has_value(), true);

   result.test_eq("name of OID '1.2.345.6.666' is 'botan-test-oid1'",
                  Botan::OIDS::oid2str_or_throw(Botan::OID("1.2.345.6.666")), "botan-test-oid1");

   return result;
   }

Test::Result test_add_have_OID_str()
   {
   Test::Result result("OID add string");

   result.test_eq("there is no OID 'botan-test-oid2'", Botan::OIDS::str2oid_or_empty("botan-test-oid2").has_value(), false);

   Botan::OIDS::add_oidstr("1.2.345.6.777", "botan-test-oid2");

   result.test_eq("OID 'botan-test-oid2' added successfully", Botan::OIDS::str2oid_or_empty("botan-test-oid2").has_value(), true);

   result.test_eq("name of OID '1.2.345.6.777' is 'botan-test-oid2'",
                  Botan::OIDS::oid2str_or_throw(Botan::OID("1.2.345.6.777")), "botan-test-oid2");
   return result;
   }

Test::Result test_add_and_lookup()
   {
   Test::Result result("OID add and lookup");

   result.test_eq("OIDS::oid2str_or_empty returns empty string for non-existent OID object",
                  Botan::OIDS::oid2str_or_empty(Botan::OID("1.2.345.6.888")), std::string());

   result.test_eq("OIDS::str2oid_or_empty returns empty OID for non-existent OID name",
                  Botan::OIDS::str2oid_or_empty("botan-test-oid3").to_string(), Botan::OID().to_string());

   // add oid -> string mapping
   Botan::OIDS::add_oid2str(Botan::OID("1.2.345.6.888"), "botan-test-oid3");
   result.test_eq("Lookup works after adding the OID",
                  Botan::OIDS::oid2str_or_throw(Botan::OID("1.2.345.6.888")), "botan-test-oid3");

   // still returns empty OID
   result.test_eq("OIDS::str2oid_or_empty still returns empty OID without adding name mapping",
                  Botan::OIDS::str2oid_or_empty("botan-test-oid3").to_string(), Botan::OID().to_string());

   // add string -> oid mapping
   Botan::OIDS::add_str2oid(Botan::OID("1.2.345.6.888"), "botan-test-oid3");
   result.test_eq("OIDS::str2oid_or_empty returns value after adding name mapping",
                  Botan::OIDS::str2oid_or_empty("botan-test-oid3").to_string(), Botan::OID({1,2,345,6,888}).to_string());

   return result;
   }

class OID_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         std::vector<std::function<Test::Result()>> fns =
            {
            test_OID_to_string,
            test_add_have_OID,
            test_add_have_OID_str,
            test_add_and_lookup,
            };

         for(size_t i = 0; i != fns.size(); ++i)
            {
            try
               {
               results.emplace_back(fns[ i ]());
               }
            catch(const std::exception& e)
               {
               results.emplace_back(Test::Result::Failure("OID tests " + std::to_string(i), e.what()));
               }
            }

         return results;
         }
   };

BOTAN_REGISTER_TEST("asn1", "oid", OID_Tests);

#endif

}

}
