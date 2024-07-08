/*
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS)

   #include <botan/tls_signature_scheme.h>

   #include <botan/ec_group.h>

namespace Botan_Tests {

namespace {

std::vector<Test::Result> test_signature_scheme() {
   std::vector<Test::Result> results;

   auto not_unknown = [](const std::string& s) { return s.find("Unknown") == std::string::npos; };

   for(const auto& s : Botan::TLS::Signature_Scheme::all_available_schemes()) {
      results.push_back(CHECK(s.to_string().c_str(), [&](auto& result) {
         result.confirm("is_set handles all cases", s.is_set());
         result.confirm("is_available handles all cases", s.is_available());

         result.confirm("to_string handles all cases", not_unknown(s.to_string()));
         result.confirm("hash_function_name handles all cases", not_unknown(s.hash_function_name()));
         result.confirm("padding_string handles all cases", not_unknown(s.padding_string()));
         result.confirm("algorithm_name handles all cases", not_unknown(s.algorithm_name()));

         result.confirm("format handles all cases", s.format().has_value());
         result.confirm("algorithm_identifier handles all cases",
                        Botan::AlgorithmIdentifier() != s.key_algorithm_identifier());
      }));
   }

   Botan::TLS::Signature_Scheme bogus(0x1337);
   results.push_back(CHECK("bogus scheme", [&](auto& result) {
      result.confirm("is_set still works", bogus.is_set());
      result.confirm("is not available", !bogus.is_available());

      result.confirm("to_string deals with bogus schemes", !not_unknown(bogus.to_string()));
      result.confirm("hash_function_name deals with bogus schemes", !not_unknown(bogus.hash_function_name()));
      result.confirm("padding_string deals with bogus schemes", !not_unknown(bogus.padding_string()));
      result.confirm("algorithm_name deals with bogus schemes", !not_unknown(bogus.algorithm_name()));

      result.confirm("format deals with bogus schemes", !bogus.format().has_value());
      result.confirm("algorithm_identifier deals with bogus schemes",
                     Botan::AlgorithmIdentifier() == bogus.key_algorithm_identifier());
   }));

   return results;
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tls", "tls_signature_scheme", test_signature_scheme);

}  // namespace Botan_Tests

#endif  // BOTAN_HAS_TLS
