/*
* (C) 2015,2016 Kai Michaelis
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/x509path.h>
   #include <botan/calendar.h>
#endif

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
#include <map>
#include <cstdlib>

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_X509_CERTIFICATES)

class Name_Constraint_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         const std::vector<std::tuple<std::string, std::string, std::string, std::string>> test_cases =
            {
            std::make_tuple(
               "Root_Email_Name_Constraint.crt",
               "Invalid_Email_Name_Constraint.crt",
               "Invalid Email Name Constraint",
               "Certificate does not pass name constraint"),
            std::make_tuple(
               "Root_DN_Name_Constraint.crt",
               "Invalid_DN_Name_Constraint.crt",
               "Invalid DN Name Constraint",
               "Certificate does not pass name constraint"),
            std::make_tuple(
               "Root_DN_Name_Constraint.crt",
               "Valid_DN_Name_Constraint.crt",
               "Valid DN Name Constraint",
               "Verified"),
            std::make_tuple(
               "Root_DNS_Name_Constraint.crt",
               "Valid_DNS_Name_Constraint.crt",
               "aexample.com",
               "Verified"),
            std::make_tuple(
               "Root_IP_Name_Constraint.crt",
               "Valid_IP_Name_Constraint.crt",
               "Valid IP Name Constraint",
               "Verified"),
            std::make_tuple(
               "Root_IP_Name_Constraint.crt",
               "Invalid_IP_Name_Constraint.crt",
               "Invalid IP Name Constraint",
               "Certificate does not pass name constraint"),
            };
         std::vector<Test::Result> results;
         const Botan::Path_Validation_Restrictions restrictions(false, 80);

         std::chrono::system_clock::time_point validation_time =
            Botan::calendar_point(2016, 10, 21, 4, 20, 0).to_std_timepoint();

         for(const auto& t : test_cases)
            {
            Botan::X509_Certificate root(Test::data_file("name_constraint/" + std::get<0>(t)));
            Botan::X509_Certificate sub(Test::data_file("name_constraint/" + std::get<1>(t)));
            Botan::Certificate_Store_In_Memory trusted;
            Test::Result result("X509v3 Name Constraints: " + std::get<1>(t));

            trusted.add_certificate(root);
            Botan::Path_Validation_Result path_result = Botan::x509_path_validate(
                     sub, restrictions, trusted, std::get<2>(t), Botan::Usage_Type::TLS_SERVER_AUTH,
                     validation_time);

            if(path_result.successful_validation() && path_result.trust_root() != root)
               {
               path_result = Botan::Path_Validation_Result(Botan::Certificate_Status_Code::CANNOT_ESTABLISH_TRUST);
               }

            result.test_eq("validation result", path_result.result_string(), std::get<3>(t));
            results.push_back(result);
            }

         return results;
         }
   };

BOTAN_REGISTER_TEST("x509_path_name_constraint", Name_Constraint_Tests);

#endif

}

}
