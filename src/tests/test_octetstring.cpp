/*
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <botan/symkey.h>

namespace Botan_Tests {

namespace {

Test::Result test_from_rng()
   {
   Test::Result result("OctetString");

   Botan::OctetString os(Test::rng(), 32);
   result.test_eq("length is 32 bytes", os.size(), 32);

   return result;
   }

Test::Result test_from_hex()
   {
   Test::Result result("OctetString");

   Botan::OctetString os("0123456789ABCDEF");
   result.test_eq("length is 8 bytes", os.size(), 8);

   return result;
   }

Test::Result test_from_byte()
   {
   Test::Result result("OctetString");

   auto rand_bytes = Test::rng().random_vec(8);
   Botan::OctetString os(rand_bytes.data(), rand_bytes.size());
   result.test_eq("length is 8 bytes", os.size(), 8);

   return result;
   }

Test::Result test_odd_parity()
   {
   Test::Result result("OctetString");

   Botan::OctetString os("FFFFFFFFFFFFFFFF");
   os.set_odd_parity();
   Botan::OctetString expected("FEFEFEFEFEFEFEFE");
   result.test_eq("odd parity set correctly", os, expected);

   Botan::OctetString os2("EFCBDA4FAA997F63");
   os2.set_odd_parity();
   Botan::OctetString expected2("EFCBDA4FAB987F62");
   result.test_eq("odd parity set correctly", os2, expected2);

   return result;
   }

Test::Result test_to_string()
   {
   Test::Result result("OctetString");

   Botan::OctetString os("0123456789ABCDEF");
   result.test_eq("OctetString::to_string() returns correct string", os.to_string(), "0123456789ABCDEF");

   return result;
   }

Test::Result test_xor()
   {
   Test::Result result("OctetString");

   Botan::OctetString os1("0000000000000000");
   Botan::OctetString os2("FFFFFFFFFFFFFFFF");

   Botan::OctetString xor_result = os1 ^ os2;
   result.test_eq("OctetString XOR operations works as expected", xor_result, os2);

   xor_result = os1;
   xor_result ^= os2;
   result.test_eq("OctetString XOR operations works as expected", xor_result, os2);

   xor_result = os2 ^ os2;
   result.test_eq("OctetString XOR operations works as expected", xor_result, os1);

   Botan::OctetString os3("0123456789ABCDEF");
   xor_result = os3 ^ os2;
   Botan::OctetString expected("FEDCBA9876543210");
   result.test_eq("OctetString XOR operations works as expected", xor_result, expected);

   return result;
   }

Test::Result test_equality()
   {
   Test::Result result("OctetString");

   const Botan::OctetString os1("0000000000000000");
   const Botan::OctetString os1_copy = os1;
   const Botan::OctetString os2("FFFFFFFFFFFFFFFF");
   const Botan::OctetString os2_copy = os2;

   result.confirm("OctetString equality operations works as expected", os1 == os1_copy);
   result.confirm("OctetString equality operations works as expected", os2 == os2_copy);
   result.confirm("OctetString equality operations works as expected", os1 != os2);

   return result;
   }

Test::Result test_append()
   {
   Test::Result result("OctetString");

   Botan::OctetString os1("0000");
   Botan::OctetString os2("FFFF");
   Botan::OctetString expected("0000FFFF");

   Botan::OctetString append_result = os1 + os2;

   result.test_eq("OctetString append operations works as expected", append_result, expected);

   return result;
   }

class OctetString_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         std::vector<std::function<Test::Result()>> fns =
            {
            test_from_rng,
            test_from_hex,
            test_from_byte,
            test_odd_parity,
            test_to_string,
            test_xor,
            test_equality,
            test_append
            };

         for(size_t i = 0; i != fns.size(); ++i)
            {
            try
               {
               results.push_back(fns[ i ]());
               }
            catch(std::exception& e)
               {
               results.push_back(Test::Result::Failure("OctetString tests " + std::to_string(i), e.what()));
               }
            }

         return results;
         }
   };

BOTAN_REGISTER_TEST("utils", "octetstring", OctetString_Tests);

}

}
