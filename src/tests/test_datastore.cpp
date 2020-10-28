/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)

#include <botan/datastor.h>

namespace Botan_Tests {

class Datastore_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         Test::Result result("Data_Store");

         Botan::Data_Store ds1;
         Botan::Data_Store ds2;

         result.confirm("equality", ds1 == ds2);

         result.test_eq("has_value", ds1.has_value("key"), false);
         result.test_eq("get1 with default", ds1.get1("key", "default"), "default");

         result.test_throws("get1", "Data_Store::get1: No values set for missing_key",
                            [&ds1]() { ds1.get1("missing_key"); });

         result.test_eq("search_for", ds1.search_for([](std::string, std::string) { return true; }).size(), 0);

         ds1.add("key", "value");

         result.test_eq("search_for", ds1.search_for([](std::string, std::string) { return true; }).size(), 1);

         result.test_eq("equality", ds1 == ds2, false);

         result.test_eq("has_value", ds1.has_value("key"), true);
         result.test_eq("get1 with default", ds1.get1("key", "default"), "value");
         result.test_eq("get1", ds1.get1("key"), "value");

         result.test_eq("get1_memvec", ds1.get1_memvec("memvec").size(), 0);

         const std::vector<uint8_t> memvec = { 9, 1, 1, 4 };
         ds1.add("memvec", memvec);

         result.test_eq("get1_memvec", ds1.get1_memvec("memvec"), memvec);

         result.test_eq("get1_uint32", ds1.get1_uint32("memvec"), size_t(9010104));

         result.test_eq("get1_uint32", ds1.get1_uint32("missing", 999), size_t(999));

         ds1.add("key", "value2");

         result.test_throws("get1", "Data_Store::get1: More than one value for key",
                            [&ds1]() { ds1.get1("key"); });

         result.test_eq("get multiple", ds1.get("key").size(), 2);

         return {result};
         }
   };

BOTAN_REGISTER_TEST("x509", "x509_datastore", Datastore_Tests);

}

#endif
