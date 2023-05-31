/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/ber_dec.h>
   #include <botan/pkix_types.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_X509_CERTIFICATES)
class X509_DN_Comparisons_Tests final : public Text_Based_Test {
   public:
      X509_DN_Comparisons_Tests() : Text_Based_Test("x509_dn.vec", "DN1,DN2") {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override {
         const std::vector<uint8_t> dn_bits1 = vars.get_req_bin("DN1");
         const std::vector<uint8_t> dn_bits2 = vars.get_req_bin("DN2");

         const bool dn_same = (type == "Equal");

         Test::Result result("X509_DN comparisons");
         try {
            Botan::X509_DN dn1;
            Botan::BER_Decoder bd1(dn_bits1);
            dn1.decode_from(bd1);

            Botan::X509_DN dn2;
            Botan::BER_Decoder bd2(dn_bits2);
            dn2.decode_from(bd2);

            const bool compared_same = (dn1 == dn2);
            result.test_eq("Comparison matches expected", dn_same, compared_same);

            const bool lt1 = (dn1 < dn2);
            const bool lt2 = (dn2 < dn1);

            if(dn_same) {
               result.test_eq("same means neither is less than", lt1, false);
               result.test_eq("same means neither is less than", lt2, false);
            } else {
               result.test_eq("different means one is less than", lt1 || lt2, true);
               result.test_eq("different means only one is less than", lt1 && lt2, false);
            }
         } catch(Botan::Exception& e) {
            result.test_failure(e.what());
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("x509", "x509_dn_cmp", X509_DN_Comparisons_Tests);
#endif

}  // namespace Botan_Tests
