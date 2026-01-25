/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ECDSA)
   #include <botan/ec_group.h>
   #include <botan/ecdsa.h>
   #include <botan/x509_key.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECDSA)

class ECC_Explicit_Curve_Tests final : public Text_Based_Test {
   public:
      ECC_Explicit_Curve_Tests() : Text_Based_Test("pubkey/ecc_explicit_curve.vec", "Pubkey,Result") {}

      Test::Result run_one_test(const std::string& /*unused*/, const VarMap& vars) override {
         Test::Result result("ECC explicit curve validation");

         const auto pubkey = vars.get_req_bin("Pubkey");
         const auto expected_result = vars.get_req_str("Result");

         try {
            auto pk = Botan::X509::load_key(pubkey);

            auto used_explicit = dynamic_cast<const Botan::ECDSA_PublicKey&>(*pk).domain().used_explicit_encoding();

            result.confirm("Loaded ECC key marked as an explicit encoding", used_explicit);

            if(expected_result == "OK") {
               result.test_success("Accepted valid explicit curve parameters");
            } else {
               result.test_failure("Accepted invalid explicit curve parameters");
            }
         } catch(Botan::Exception& e) {
            const std::string err(e.what());
            if(expected_result == "OK") {
               result.test_failure("Rejected valid explicit curve parameters", err);
            } else {
               result.test_success("Rejected invalid explicit curve parameters");

               if(err.find(expected_result) != std::string::npos) {
                  result.test_success("Rejection error matches expected");
               } else {
                  result.test_failure("Rejection failure other than what was expected", err);
               }
            }
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ecc_explicit_curve", ECC_Explicit_Curve_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
