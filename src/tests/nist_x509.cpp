/*
  Code to run the X.509v3 processing tests described in "Conformance
  Testing of Relying Party Client Certificate Path Proccessing Logic",
  which is available on NIST's web site.

Known Failures/Problems

Policy extensions are not implemented, so we skip tests #34-#53.

Tests #75 and #76 are skipped as they make use of relatively obscure CRL
extensions which are not supported.

In addition, please note that some of the tests have their results altered from
what the test result should be according to NIST's documentation. The changes
are clearly marked (see x509test.cpp; search for "CHANGE OF TEST RESULT") and
there are comments explaining why the results where changed. Currently, tests
#19, #65, and #67 have had their results changed from the official results.
*/

#include "tests.h"

#include <botan/x509path.h>
#include <botan/init.h>

#include <algorithm>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <map>
#include <cstdlib>

#include <dirent.h>

using namespace Botan;

std::vector<std::string> dir_listing(const std::string&);

void run_one_test(u32bit, Path_Validation_Result::Code,
                  std::string, std::string,
                  std::vector<std::string>,
                  std::vector<std::string>);

std::map<size_t, Path_Validation_Result::Code> expected_results;
size_t unexp_failure, unexp_success, wrong_error, skipped;

void populate_expected_results();

size_t test_nist_x509()
   {
   unexp_failure = unexp_success = wrong_error = skipped = 0;

   try {

   populate_expected_results();

   const std::string root_test_dir = "src/test-data/nist_x509/";
   std::vector<std::string> test_dirs = dir_listing(root_test_dir);
   std::sort(test_dirs.begin(), test_dirs.end());

   for(size_t j = 0; j != test_dirs.size(); j++)
      {
      const std::string test_dir = root_test_dir + test_dirs[j] + "/";
      std::vector<std::string> all_files = dir_listing(test_dir);

      std::vector<std::string> certs, crls;
      std::string root_cert, to_verify;

      for(size_t k = 0; k != all_files.size(); k++)
         {
         const std::string current = all_files[k];
         if(current.find("int") != std::string::npos &&
            current.find(".crt") != std::string::npos)
            certs.push_back(test_dir + current);
         else if(current.find("root.crt") != std::string::npos)
            root_cert = test_dir + current;
         else if(current.find("end.crt") != std::string::npos)
            to_verify = test_dir + current;
         else if(current.find(".crl") != std::string::npos)
            crls.push_back(test_dir + current);
         }

      if(expected_results.find(j+1) == expected_results.end())
         {
#if 0
         std::cout << "Testing disabled for test #" << j+1
                   << " <skipped>" << std::endl;
#endif
         skipped++;
         continue;
         }

      run_one_test(j+1, expected_results[j+1],
                   root_cert, to_verify, certs, crls);
      }

   }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      return 1;
      }

   std::cout << "Total unexpected failures: " << unexp_failure << std::endl;
   std::cout << "Total unexpected successes: " << unexp_success << std::endl;
   std::cout << "Total incorrect failures: " << wrong_error << std::endl;
   std::cout << "Tests skipped: " << skipped << std::endl;

   return unexp_failure + unexp_success + wrong_error;
   }

void run_one_test(u32bit test_no, Path_Validation_Result::Code expected,
                  std::string root_cert, std::string to_verify,
                  std::vector<std::string> certs,
                  std::vector<std::string> crls)
   {
   std::cout << "NIST X.509 test #" << test_no << "... ";

   Certificate_Store_In_Memory store;

   store.add_certificate(X509_Certificate(root_cert));

   X509_Certificate end_user(to_verify);

   for(size_t j = 0; j != certs.size(); j++)
      store.add_certificate(X509_Certificate(certs[j]));

   for(size_t j = 0; j != crls.size(); j++)
      {
      DataSource_Stream in(crls[j]);

      X509_CRL crl(in);
      /*
      std::vector<CRL_Entry> crl_entries = crl.get_revoked();
      for(u32bit k = 0; k != crl_entries.size(); k++)
         {
         std::cout << "Revoked: " << std::flush;
         for(u32bit l = 0; l != crl_entries[k].serial.size(); l++)
            printf("%02X", crl_entries[k].serial[l]);
         std::cout << std::endl;
         }
      */
      store.add_crl(crl);
      }

   Path_Validation_Restrictions restrictions(true);

   Path_Validation_Result validation_result =
      x509_path_validate(end_user,
                         restrictions,
                         store);

   Path_Validation_Result::Code result = validation_result.result();

   if(result == expected)
      {
      std::cout << "passed" << std::endl;
      return;
      }

   const std::string result_str = Path_Validation_Result::status_string(result);
   const std::string exp_str = Path_Validation_Result::status_string(expected);

   if(expected == Certificate_Status_Code::VERIFIED)
      {
      std::cout << "unexpected failure: " << result_str << std::endl;
      unexp_failure++;
      }
   else if(result == Certificate_Status_Code::VERIFIED)
      {
      std::cout << "unexpected success: " << exp_str << std::endl;
      unexp_success++;
      }
   else
      {
      std::cout << "wrong error: " << result_str << "/" << exp_str << std::endl;
      wrong_error++;
      }
   }

std::vector<std::string> dir_listing(const std::string& dir_name)
   {
   DIR* dir = opendir(dir_name.c_str());
   if(!dir)
      {
      std::cout << "Error, couldn't open dir " << dir_name << std::endl;
      std::exit(1);
      }

   std::vector<std::string> listing;

   while(true)
      {
      struct dirent* dir_ent = readdir(dir);

      if(dir_ent == 0)
         break;
      const std::string entry = dir_ent->d_name;
      if(entry == "." || entry == "..")
         continue;

      listing.push_back(entry);
      }
   closedir(dir);

   return listing;
   }

/*
  The expected results are essentially the error codes that best coorespond
  to the problem described in the testing documentation.

  There are a few cases where the tests say there should or should not be an
  error, and I disagree. A few of the tests have test results different from
  what they "should" be: these changes are marked as such, and have comments
  explaining the problem at hand.
*/
void populate_expected_results()
   {
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

   expected_results[19] = Certificate_Status_Code::CRL_NOT_FOUND;
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

   expected_results[64] = Certificate_Status_Code::SIGNATURE_ERROR;

   expected_results[65] = Certificate_Status_Code::CRL_NOT_FOUND;
   expected_results[66] = Certificate_Status_Code::CRL_NOT_FOUND;

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
   }
