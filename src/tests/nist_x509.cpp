/*
* (C) 2006,2011,2012,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*
* Code to run the X.509v3 processing tests described in "Conformance
*  Testing of Relying Party Client Certificate Path Proccessing Logic",
*  which is available on NIST's web site.
*
* Known Failures/Problems:
*  - Policy extensions are not implemented, so we skip tests #34-#53.
*  - Tests #75 and #76 are skipped as they make use of relatively
*    obscure CRL extensions which are not supported.
*/

#include "tests.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)

#include <botan/x509path.h>
#include <botan/fs.h>

#include <algorithm>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <map>
#include <cstdlib>

using namespace Botan;

std::map<size_t, Path_Validation_Result::Code> get_expected();

size_t test_nist_x509()
   {
   const std::string root_test_dir = "src/tests/data/nist_x509/";
   const size_t total_tests = 76;

   if(list_all_readable_files_in_or_under(root_test_dir).empty())
      {
      std::cout << "No FS access, skipping NIST X.509 validation tests" << std::endl;
      test_report("NIST X.509 path validation", 0, 0);
      return 0;
      }

   size_t unexp_failure = 0;
   size_t unexp_success = 0;
   size_t wrong_error = 0;
   size_t skipped = 0;
   size_t ran = 0;

   auto expected_results = get_expected();

   try {

   for(size_t test_no = 1; test_no <= total_tests; ++test_no)
      {
      const std::string test_dir = root_test_dir + "/test" + (test_no <= 9 ? "0" : "") + std::to_string(test_no);
      const std::vector<std::string> all_files = list_all_readable_files_in_or_under(test_dir);

      std::vector<std::string> certs, crls;
      std::string root_cert, to_verify;

      for(size_t k = 0; k != all_files.size(); k++)
         {
         const std::string current = all_files[k];

         if(current.find("int") != std::string::npos &&
            current.find(".crt") != std::string::npos)
            certs.push_back(current);
         else if(current.find("root.crt") != std::string::npos)
            root_cert = current;
         else if(current.find("end.crt") != std::string::npos)
            to_verify = current;
         else if(current.find(".crl") != std::string::npos)
            crls.push_back(current);
         }

      if(expected_results.find(test_no) == expected_results.end())
         {
         skipped++;
         continue;
         }

      ++ran;

      Certificate_Store_In_Memory store;

      store.add_certificate(X509_Certificate(root_cert));

      X509_Certificate end_user(to_verify);

      for(size_t i = 0; i != certs.size(); i++)
         store.add_certificate(X509_Certificate(certs[i]));

      for(size_t i = 0; i != crls.size(); i++)
         {
         DataSource_Stream in(crls[i]);
         X509_CRL crl(in);
         store.add_crl(crl);
         }

      Path_Validation_Restrictions restrictions(true);

      Path_Validation_Result validation_result =
         x509_path_validate(end_user,
                            restrictions,
                            store);

      auto expected = expected_results[test_no];

      Path_Validation_Result::Code result = validation_result.result();

      if(result != expected)
         {
         std::cout << "NIST X.509 test #" << test_no << ": ";

         const std::string result_str = Path_Validation_Result::status_string(result);
         const std::string exp_str = Path_Validation_Result::status_string(expected);

         if(expected == Certificate_Status_Code::VERIFIED)
            {
            std::cout << "unexpected failure: " << result_str << std::endl;
            unexp_failure++;
            }
         else if(result == Certificate_Status_Code::VERIFIED)
            {
            std::cout << "unexpected success, expected " << exp_str << std::endl;
            unexp_success++;
            }
         else
            {
            std::cout << "wrong error, got '" << result_str << "' expected '" << exp_str << "'" << std::endl;
            wrong_error++;
            }
         }
      }
   }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      ++unexp_failure;
      }

   const size_t all_failures = unexp_failure + unexp_success + wrong_error;

   test_report("NIST X.509 path validation", ran, all_failures);

   return all_failures;
   }

/*
  The expected results are essentially the error codes that best coorespond
  to the problem described in the testing documentation.

  There are a few cases where the tests say there should or should not be an
  error, and I disagree. A few of the tests have test results different from
  what they "should" be: these changes are marked as such, and have comments
  explaining the problem at hand.
*/
std::map<size_t, Path_Validation_Result::Code> get_expected()
   {
   std::map<size_t, Path_Validation_Result::Code> expected_results;

   /* OK, not a super great way of doing this... */
   expected_results[1] = Certificate_Status_Code::VERIFIED;
   expected_results[2] = Certificate_Status_Code::SIGNATURE_ERROR;
   expected_results[3] = Certificate_Status_Code::SIGNATURE_ERROR;
   expected_results[4] = Certificate_Status_Code::VERIFIED;
   expected_results[5] = Certificate_Status_Code::CERT_NOT_YET_VALID;
   expected_results[6] = Certificate_Status_Code::CERT_NOT_YET_VALID;
   expected_results[7] = Certificate_Status_Code::VERIFIED;
   expected_results[8] = Certificate_Status_Code::CERT_NOT_YET_VALID;
   expected_results[9] = Certificate_Status_Code::CERT_HAS_EXPIRED;
   expected_results[10] = Certificate_Status_Code::CERT_HAS_EXPIRED;
   expected_results[11] = Certificate_Status_Code::CERT_HAS_EXPIRED;
   expected_results[12] = Certificate_Status_Code::VERIFIED;
   expected_results[13] = Certificate_Status_Code::CERT_ISSUER_NOT_FOUND;

   expected_results[14] = Certificate_Status_Code::CERT_ISSUER_NOT_FOUND;
   expected_results[15] = Certificate_Status_Code::VERIFIED;
   expected_results[16] = Certificate_Status_Code::VERIFIED;
   expected_results[17] = Certificate_Status_Code::VERIFIED;
   expected_results[18] = Certificate_Status_Code::VERIFIED;

   expected_results[19] = Certificate_Status_Code::NO_REVOCATION_DATA;
   expected_results[20] = Certificate_Status_Code::CERT_IS_REVOKED;
   expected_results[21] = Certificate_Status_Code::CERT_IS_REVOKED;

   expected_results[22] = Certificate_Status_Code::CA_CERT_NOT_FOR_CERT_ISSUER;
   expected_results[23] = Certificate_Status_Code::CA_CERT_NOT_FOR_CERT_ISSUER;
   expected_results[24] = Certificate_Status_Code::VERIFIED;
   expected_results[25] = Certificate_Status_Code::CA_CERT_NOT_FOR_CERT_ISSUER;
   expected_results[26] = Certificate_Status_Code::VERIFIED;
   expected_results[27] = Certificate_Status_Code::VERIFIED;
   expected_results[28] = Certificate_Status_Code::CA_CERT_NOT_FOR_CERT_ISSUER;
   expected_results[29] = Certificate_Status_Code::CA_CERT_NOT_FOR_CERT_ISSUER;
   expected_results[30] = Certificate_Status_Code::VERIFIED;

   expected_results[31] = Certificate_Status_Code::CA_CERT_NOT_FOR_CRL_ISSUER;
   expected_results[32] = Certificate_Status_Code::CA_CERT_NOT_FOR_CRL_ISSUER;
   expected_results[33] = Certificate_Status_Code::VERIFIED;

   /*
    Policy tests: a little trickier because there are other inputs
    which affect the result.

    In the case of the tests currently in the suite, the default
    method (with acceptable policy being "any-policy" and with no
    explict policy required), will almost always result in a verified
    status. This is not particularly helpful. So, we should do several
    different tests for each test set:

       1) With the user policy as any-policy and no explicit policy
       2) With the user policy as any-policy and an explicit policy required
       3) With the user policy as test-policy-1 (2.16.840.1.101.3.1.48.1) and
          an explict policy required
       4) With the user policy as either test-policy-1 or test-policy-2 and an
          explicit policy required

     This provides reasonably good coverage of the possible outcomes.
   */

   expected_results[34] = Certificate_Status_Code::VERIFIED;
   expected_results[35] = Certificate_Status_Code::VERIFIED;
   expected_results[36] = Certificate_Status_Code::VERIFIED;
   expected_results[37] = Certificate_Status_Code::VERIFIED;
   expected_results[38] = Certificate_Status_Code::VERIFIED;
   expected_results[39] = Certificate_Status_Code::VERIFIED;
   expected_results[40] = Certificate_Status_Code::VERIFIED;
   expected_results[41] = Certificate_Status_Code::VERIFIED;
   expected_results[42] = Certificate_Status_Code::VERIFIED;
   expected_results[43] = Certificate_Status_Code::VERIFIED;
   expected_results[44] = Certificate_Status_Code::VERIFIED;

   //expected_results[45] = Certificate_Status_Code::EXPLICT_POLICY_REQUIRED;
   //expected_results[46] = Certificate_Status_Code::ACCEPT;
   //expected_results[47] = Certificate_Status_Code::EXPLICT_POLICY_REQUIRED;

   expected_results[48] = Certificate_Status_Code::VERIFIED;
   expected_results[49] = Certificate_Status_Code::VERIFIED;
   expected_results[50] = Certificate_Status_Code::VERIFIED;
   expected_results[51] = Certificate_Status_Code::VERIFIED;
   expected_results[52] = Certificate_Status_Code::VERIFIED;
   expected_results[53] = Certificate_Status_Code::VERIFIED;

   expected_results[54] = Certificate_Status_Code::CERT_CHAIN_TOO_LONG;
   expected_results[55] = Certificate_Status_Code::CERT_CHAIN_TOO_LONG;
   expected_results[56] = Certificate_Status_Code::VERIFIED;
   expected_results[57] = Certificate_Status_Code::VERIFIED;
   expected_results[58] = Certificate_Status_Code::CERT_CHAIN_TOO_LONG;
   expected_results[59] = Certificate_Status_Code::CERT_CHAIN_TOO_LONG;
   expected_results[60] = Certificate_Status_Code::CERT_CHAIN_TOO_LONG;
   expected_results[61] = Certificate_Status_Code::CERT_CHAIN_TOO_LONG;
   expected_results[62] = Certificate_Status_Code::VERIFIED;
   expected_results[63] = Certificate_Status_Code::VERIFIED;

   expected_results[64] = Certificate_Status_Code::CRL_BAD_SIGNATURE;

   expected_results[65] = Certificate_Status_Code::NO_REVOCATION_DATA;
   expected_results[66] = Certificate_Status_Code::NO_REVOCATION_DATA;

   expected_results[67] = Certificate_Status_Code::VERIFIED;

   expected_results[68] = Certificate_Status_Code::CERT_IS_REVOKED;
   expected_results[69] = Certificate_Status_Code::CERT_IS_REVOKED;
   expected_results[70] = Certificate_Status_Code::CERT_IS_REVOKED;
   expected_results[71] = Certificate_Status_Code::CERT_IS_REVOKED;
   expected_results[72] = Certificate_Status_Code::CRL_HAS_EXPIRED;
   expected_results[73] = Certificate_Status_Code::CRL_HAS_EXPIRED;
   expected_results[74] = Certificate_Status_Code::VERIFIED;

   /* These tests use weird CRL extensions which aren't supported yet */
   //expected_results[75] = ;
   //expected_results[76] = ;

   return expected_results;
   }

#else

size_t test_nist_x509() { return 0; }

#endif
