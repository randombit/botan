/*
* (C) 2026 Damiano Mazzella
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PBKDF1)
   #include <botan/internal/pbkdf1.h>
   #include <botan/internal/parsing.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_PBKDF1)

class PBKDF1_Tests final : public Text_Based_Test {
   public:
      PBKDF1_Tests() : Text_Based_Test("pbkdf1/pbkdf1.vec", "Passphrase,Salt,Iterations,ID,Output") {}

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override {
         const std::string passphrase = vars.get_req_str("Passphrase");
         const std::vector<uint8_t> salt = vars.get_req_bin("Salt");
         const size_t iterations = vars.get_req_sz("Iterations");
         const size_t id = vars.get_opt_sz("ID", 1);
         const std::vector<uint8_t> expected = vars.get_req_bin("Output");

         Test::Result result("PBKDF1");

         // header is like "PBKDF1(SHA-1)" — extract algorithm name using parser
         std::string hash_name = "SHA-1";
         const auto parts = Botan::parse_algorithm_name(header);
         if(parts.size() > 1) {
            const std::string algo_spec = parts[1];
            hash_name = algo_spec;
         }

         // Derive with the library pbkdf1 implementation directly
         const size_t outlen = expected.size();
         std::vector<uint8_t> derived(outlen);

         try {
               Botan::pbkdf1(derived.data(), outlen, passphrase, salt.data(), salt.size(), iterations,
                              static_cast<uint8_t>(id), hash_name);
         } catch(std::exception& e) {
            result.test_failure("derive", e.what());
            return result;
         }

         result.test_bin_eq("derived key", derived, expected);

         return result;
      }
};

BOTAN_REGISTER_TEST("pbkdf", "pbkdf1", PBKDF1_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
