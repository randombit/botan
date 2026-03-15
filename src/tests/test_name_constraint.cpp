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

         const std::chrono::system_clock::time_point validation_time =
            Botan::calendar_point(2016, 10, 21, 4, 20, 0).to_std_timepoint();

         for(const auto& t : test_cases) {
            const Botan::X509_Certificate root(Test::data_file("x509/name_constraint/" + std::get<0>(t)));
            const Botan::X509_Certificate sub(Test::data_file("x509/name_constraint/" + std::get<1>(t)));
            Botan::Certificate_Store_In_Memory trusted;
            Test::Result result("X509v3 Name Constraints: " + std::get<1>(t));

            trusted.add_certificate(root);
            Botan::Path_Validation_Result path_result = Botan::x509_path_validate(
               sub, restrictions, trusted, std::get<2>(t), Botan::Usage_Type::TLS_SERVER_AUTH, validation_time);

            if(path_result.successful_validation() && path_result.trust_root() != root) {
               path_result = Botan::Path_Validation_Result(Botan::Certificate_Status_Code::CANNOT_ESTABLISH_TRUST);
            }

            result.test_str_eq("validation result", path_result.result_string(), std::get<3>(t));
            results.emplace_back(result);
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("x509", "x509_path_name_constraint", Name_Constraint_Tests);

// Verify that DNS constraints are case-insensitive also when falling back to the CN
class Name_Constraint_Excluded_CN_Case_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("X509v3 Name Constraints: excluded DNS with mixed-case CN and no SAN");

         const Botan::X509_Certificate root(
            Test::data_file("x509/name_constraint/Root_DNS_Excluded_Mixed_Case_CN.crt"));
         const Botan::X509_Certificate leaf(
            Test::data_file("x509/name_constraint/Invalid_DNS_Excluded_Mixed_Case_CN.crt"));

         Botan::Certificate_Store_In_Memory trusted;
         trusted.add_certificate(root);

         const Botan::Path_Validation_Restrictions restrictions(false, 80);
         const auto validation_time = Botan::calendar_point(2026, 6, 1, 0, 0, 0).to_std_timepoint();

         const auto path_result = Botan::x509_path_validate(
            leaf, restrictions, trusted, "" /* hostname */, Botan::Usage_Type::UNSPECIFIED, validation_time);

         result.test_str_eq(
            "validation result", path_result.result_string(), "Certificate does not pass name constraint");

         return {result};
      }
};

BOTAN_REGISTER_TEST("x509", "x509_name_constraint_excluded_cn_case", Name_Constraint_Excluded_CN_Case_Test);

#endif

}  // namespace

}  // namespace Botan_Tests
