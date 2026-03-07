/*
* (C) 2026 Damiano Mazzella
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PKCS12_KDF)
   #include <botan/internal/pkcs12_kdf.h>

namespace Botan_Tests {

namespace {

class PKCS12_KDF_Tests final : public Text_Based_Test {
   public:
      PKCS12_KDF_Tests() : Text_Based_Test("pkcs12_kdf/pkcs12_kdf.vec", "Passphrase,Salt,Iterations,ID,Output") {}

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override {
         const std::string passphrase = vars.get_req_str("Passphrase");
         const std::vector<uint8_t> salt = vars.get_req_bin("Salt");
         const size_t iterations = vars.get_req_sz("Iterations");
         const size_t id = vars.get_req_sz("ID");
         const std::vector<uint8_t> expected = vars.get_req_bin("Output");

         Test::Result result("PKCS12 KDF");

         // header is like "PKCS12_KDF(SHA-1)" — extract hash name between parentheses
         std::string hash_name = "SHA-1";
         const auto open = header.find('(');
         const auto close = header.find(')');
         if(open != std::string::npos && close != std::string::npos && close > open) {
            hash_name = header.substr(open + 1, close - open - 1);
         }

         const size_t outlen = expected.size();
         std::vector<uint8_t> derived(outlen);

         try {
            Botan::pkcs12_kdf(derived.data(),
                              outlen,
                              passphrase,
                              salt.data(),
                              salt.size(),
                              iterations,
                              static_cast<uint8_t>(id),
                              hash_name);
         } catch(std::exception& e) {
            result.test_failure("derive", e.what());
            return result;
         }

         result.test_bin_eq("derived key", derived, expected);

         return result;
      }
};

BOTAN_REGISTER_TEST("pkcs12", "pkcs12_kdf", PKCS12_KDF_Tests);

}  // namespace

}  // namespace Botan_Tests

#endif
