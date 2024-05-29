/*
* (C) 2015,2016 Kai Michaelis
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/x509path.h>
   #include <botan/internal/calendar.h>
#endif

#include <utility>

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_EMSA_PKCS1) && \
   defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

class Name_Constraint_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         const std::vector<std::tuple<std::string, std::string, std::string, std::string>> test_cases = {
            std::make_tuple("Root_Email_Name_Constraint.crt",
                            "Invalid_Email_Name_Constraint.crt",
                            "",
                            "Certificate does not pass name constraint"),
            std::make_tuple("Root_DN_Name_Constraint.crt",
                            "Invalid_DN_Name_Constraint.crt",
                            "",
                            "Certificate does not pass name constraint"),
            std::make_tuple("Root_DN_Name_Constraint.crt", "Valid_DN_Name_Constraint.crt", "", "Verified"),
            std::make_tuple(
               "Root_DNS_Name_Constraint.crt", "Valid_DNS_Name_Constraint.crt", "aexample.com", "Verified"),
            std::make_tuple("Root_IP_Name_Constraint.crt", "Valid_IP_Name_Constraint.crt", "", "Verified"),
            std::make_tuple("Root_IP_Name_Constraint.crt",
                            "Invalid_IP_Name_Constraint.crt",
                            "",
                            "Certificate does not pass name constraint"),
         };
         std::vector<Test::Result> results;
         const Botan::Path_Validation_Restrictions restrictions(false, 80);

         std::chrono::system_clock::time_point validation_time =
            Botan::calendar_point(2016, 10, 21, 4, 20, 0).to_std_timepoint();

         for(const auto& t : test_cases) {
            Botan::X509_Certificate root(Test::data_file("x509/name_constraint/" + std::get<0>(t)));
            Botan::X509_Certificate sub(Test::data_file("x509/name_constraint/" + std::get<1>(t)));
            Botan::Certificate_Store_In_Memory trusted;
            Test::Result result("X509v3 Name Constraints: " + std::get<1>(t));

            trusted.add_certificate(root);
            Botan::Path_Validation_Result path_result = Botan::x509_path_validate(
               sub, restrictions, trusted, std::get<2>(t), Botan::Usage_Type::TLS_SERVER_AUTH, validation_time);

            if(path_result.successful_validation() && path_result.trust_root() != root) {
               path_result = Botan::Path_Validation_Result(Botan::Certificate_Status_Code::CANNOT_ESTABLISH_TRUST);
            }

            result.test_eq("validation result", path_result.result_string(), std::get<3>(t));
            results.emplace_back(result);
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("x509", "x509_path_name_constraint", Name_Constraint_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
