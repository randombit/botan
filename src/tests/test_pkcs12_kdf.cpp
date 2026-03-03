/*
* PKCS#12 KDF test vectors runner
*/

#include "tests.h"

#if defined(BOTAN_HAS_PKCS12_KDF)
   #include <botan/internal/pkcs12_kdf.h>
   #include <botan/internal/parsing.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_PKCS12_KDF)

class PKCS12_KDF_KAT_Tests final : public Text_Based_Test {
   public:
      PKCS12_KDF_KAT_Tests() : Text_Based_Test("pbkdf/pkcs12_kdf.vec", "Password,Salt,Iterations,ID,OutputLen,Output") {}

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override {
         const std::string password = vars.get_req_str("Password");
         const std::vector<uint8_t> salt = vars.get_req_bin("Salt");
         const size_t iterations = vars.get_req_sz("Iterations");
         const size_t id = vars.get_opt_sz("ID", 1);
         const std::vector<uint8_t> expected = vars.get_req_bin("Output");

         Test::Result result("PKCS12-KDF");

         

         // header is like "PKCS12_KDF(SHA-1)" — extract algorithm name using parser
         std::string hash_name = "SHA-1";
         try {
            const auto parts = Botan::parse_algorithm_name(header);
            if(parts.size() > 1) {
               const std::string algo_spec = parts[1];
               const auto inner = Botan::parse_algorithm_name(algo_spec);
               if(inner.size() > 1) {
                  hash_name = inner[1];
               } else {
                  hash_name = algo_spec;
               }
            }
         } catch(...) {
            // leave default
         }

         // Derive with the library pkcs12_kdf implementation directly
         const size_t outlen = expected.size();
         std::vector<uint8_t> derived(outlen);

         try {
            Botan::pkcs12_kdf(derived.data(), outlen, password, salt.data(), salt.size(), iterations,
                              static_cast<uint8_t>(id), hash_name);
         } catch(std::exception& e) {
            result.test_failure("derive", e.what());
            return result;
         }

         result.test_bin_eq("derived key", derived, expected);

         return result;
      }
};

BOTAN_REGISTER_TEST("pbkdf", "pkcs12_kdf", PKCS12_KDF_KAT_Tests);

#endif

} // namespace

} // namespace Botan_Tests
