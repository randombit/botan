/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS_CBC)
   #include <botan/internal/tls_cbc.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_TLS_CBC)

class TLS_CBC_Padding_Tests : public Text_Based_Test
   {
   public:
      TLS_CBC_Padding_Tests() : Text_Based_Test("tls_cbc.vec", "Record,Output") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         const std::vector<uint8_t> record    = get_req_bin(vars, "Record");
         const size_t output = get_req_sz(vars, "Output");

         uint16_t res = Botan::TLS::check_tls_cbc_padding(record.data(), record.size());

         Test::Result result("TLS CBC padding check");
         result.test_eq("Expected", res, output);
         return result;
         }
   };

BOTAN_REGISTER_TEST("tls_cbc_padding", TLS_CBC_Padding_Tests);

#endif

}

