/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PBKDF)
  #include <botan/pbkdf.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_PBKDF)
class PBKDF_KAT_Tests : public Text_Based_Test
   {
   public:
      PBKDF_KAT_Tests() : Text_Based_Test(Test::data_dir("pbkdf"),
                                          {"OutputLen", "Iterations", "Salt", "Passphrase", "Output"})
         {}

      Test::Result run_one_test(const std::string& pbkdf_name, const VarMap& vars)
         {
         Test::Result result(pbkdf_name);
         std::unique_ptr<Botan::PBKDF> pbkdf(Botan::get_pbkdf(pbkdf_name));

         if(!pbkdf)
            {
            warn_about_missing(pbkdf_name);
            return result;
            }

         const size_t outlen = get_req_sz(vars, "OutputLen");
         const size_t iterations = get_req_sz(vars, "Iterations");
         const std::vector<uint8_t> salt = get_req_bin(vars, "Salt");
         const std::string passphrase = get_req_str(vars, "Passphrase");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Output");

         const Botan::secure_vector<byte> derived =
            pbkdf->derive_key(outlen, passphrase, salt.data(), salt.size(), iterations).bits_of();

         result.test_eq("derived key", derived, expected);

         return result;
         }

   };

BOTAN_REGISTER_TEST("pbkdf", PBKDF_KAT_Tests);

#endif

}

}

size_t test_pbkdf()
   {
   return Botan_Tests::basic_error_report("pbkdf");
   }
