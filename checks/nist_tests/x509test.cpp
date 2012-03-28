/*
  Code to run the X.509v3 processing tests described in "Conformance
  Testing of Relying Party Client Certificate Path Proccessing Logic",
  which is available on NIST's web site.
*/

#include <botan/x509path.h>
#include <botan/init.h>
using namespace Botan;

#include <algorithm>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <map>
#include <cstdlib>

#include <dirent.h>

std::vector<std::string> dir_listing(const std::string&);

void run_one_test(u32bit, Path_Validation_Result::Code,
                  std::string, std::string,
                  std::vector<std::string>,
                  std::vector<std::string>);

std::map<u32bit, Path_Validation_Result::Code> expected_results;

u32bit unexp_failure, unexp_success, wrong_error, skipped;

void populate_expected_results();

int main()
   {
   const std::string root_test_dir = "tests/";
   unexp_failure = unexp_success = wrong_error = skipped = 0;

   try {

   LibraryInitializer init;

   populate_expected_results();

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

   return 0;
   }

void run_one_test(u32bit test_no, Path_Validation_Result::Code expected,
                  std::string root_cert, std::string to_verify,
                  std::vector<std::string> certs,
                  std::vector<std::string> crls)
   {
   std::cout << "Processing test #" << test_no << "... ";
   std::cout.flush();

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

   if(expected == Path_Validation_Result::VERIFIED)
      {
      std::cout << "unexpected failure: " << result << std::endl;
      unexp_failure++;
      }
   else if(result == Path_Validation_Result::VERIFIED)
      {
      std::cout << "unexpected success: " << expected << std::endl;
      unexp_success++;
      }
   else
      {
      std::cout << "wrong error: " << result << "/" << expected << std::endl;
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
   expected_results[1] = Path_Validation_Result::VERIFIED;
   expected_results[2] = Path_Validation_Result::SIGNATURE_ERROR;
   expected_results[3] = Path_Validation_Result::SIGNATURE_ERROR;
   expected_results[4] = Path_Validation_Result::VERIFIED;
   expected_results[5] = Path_Validation_Result::CERT_NOT_YET_VALID;
   expected_results[6] = Path_Validation_Result::CERT_NOT_YET_VALID;
   expected_results[7] = Path_Validation_Result::VERIFIED;
   expected_results[8] = Path_Validation_Result::CERT_NOT_YET_VALID;
   expected_results[9] = Path_Validation_Result::CERT_HAS_EXPIRED;
   expected_results[10] = Path_Validation_Result::CERT_HAS_EXPIRED;
   expected_results[11] = Path_Validation_Result::CERT_HAS_EXPIRED;
   expected_results[12] = Path_Validation_Result::VERIFIED;
   expected_results[13] = Path_Validation_Result::CERT_ISSUER_NOT_FOUND;

   expected_results[14] = Path_Validation_Result::CERT_ISSUER_NOT_FOUND;
   expected_results[15] = Path_Validation_Result::VERIFIED;
   expected_results[16] = Path_Validation_Result::VERIFIED;
   expected_results[17] = Path_Validation_Result::VERIFIED;
   expected_results[18] = Path_Validation_Result::VERIFIED;

   expected_results[19] = Path_Validation_Result::CRL_NOT_FOUND;
   expected_results[20] = Path_Validation_Result::CERT_IS_REVOKED;
   expected_results[21] = Path_Validation_Result::CERT_IS_REVOKED;

   expected_results[22] = Path_Validation_Result::CA_CERT_NOT_FOR_CERT_ISSUER;
   expected_results[23] = Path_Validation_Result::CA_CERT_NOT_FOR_CERT_ISSUER;
   expected_results[24] = Path_Validation_Result::VERIFIED;
   expected_results[25] = Path_Validation_Result::CA_CERT_NOT_FOR_CERT_ISSUER;
   expected_results[26] = Path_Validation_Result::VERIFIED;
   expected_results[27] = Path_Validation_Result::VERIFIED;
   expected_results[28] = Path_Validation_Result::CA_CERT_NOT_FOR_CERT_ISSUER;
   expected_results[29] = Path_Validation_Result::CA_CERT_NOT_FOR_CERT_ISSUER;
   expected_results[30] = Path_Validation_Result::VERIFIED;

   expected_results[31] = Path_Validation_Result::CA_CERT_NOT_FOR_CRL_ISSUER;
   expected_results[32] = Path_Validation_Result::CA_CERT_NOT_FOR_CRL_ISSUER;
   expected_results[33] = Path_Validation_Result::VERIFIED;

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

   expected_results[34] = Path_Validation_Result::VERIFIED;
   expected_results[35] = Path_Validation_Result::VERIFIED;
   expected_results[36] = Path_Validation_Result::VERIFIED;
   expected_results[37] = Path_Validation_Result::VERIFIED;
   expected_results[38] = Path_Validation_Result::VERIFIED;
   expected_results[39] = Path_Validation_Result::VERIFIED;
   expected_results[40] = Path_Validation_Result::VERIFIED;
   expected_results[41] = Path_Validation_Result::VERIFIED;
   expected_results[42] = Path_Validation_Result::VERIFIED;
   expected_results[43] = Path_Validation_Result::VERIFIED;
   expected_results[44] = Path_Validation_Result::VERIFIED;

   //expected_results[45] = Path_Validation_Result::EXPLICT_POLICY_REQUIRED;
   //expected_results[46] = Path_Validation_Result::ACCEPT;
   //expected_results[47] = Path_Validation_Result::EXPLICT_POLICY_REQUIRED;

   expected_results[48] = Path_Validation_Result::VERIFIED;
   expected_results[49] = Path_Validation_Result::VERIFIED;
   expected_results[50] = Path_Validation_Result::VERIFIED;
   expected_results[51] = Path_Validation_Result::VERIFIED;
   expected_results[52] = Path_Validation_Result::VERIFIED;
   expected_results[53] = Path_Validation_Result::VERIFIED;

   expected_results[54] = Path_Validation_Result::CERT_CHAIN_TOO_LONG;
   expected_results[55] = Path_Validation_Result::CERT_CHAIN_TOO_LONG;
   expected_results[56] = Path_Validation_Result::VERIFIED;
   expected_results[57] = Path_Validation_Result::VERIFIED;
   expected_results[58] = Path_Validation_Result::CERT_CHAIN_TOO_LONG;
   expected_results[59] = Path_Validation_Result::CERT_CHAIN_TOO_LONG;
   expected_results[60] = Path_Validation_Result::CERT_CHAIN_TOO_LONG;
   expected_results[61] = Path_Validation_Result::CERT_CHAIN_TOO_LONG;
   expected_results[62] = Path_Validation_Result::VERIFIED;
   expected_results[63] = Path_Validation_Result::VERIFIED;

   expected_results[64] = Path_Validation_Result::SIGNATURE_ERROR;

   expected_results[65] = Path_Validation_Result::CRL_NOT_FOUND;
   expected_results[66] = Path_Validation_Result::CRL_NOT_FOUND;

   expected_results[67] = Path_Validation_Result::VERIFIED;

   expected_results[68] = Path_Validation_Result::CERT_IS_REVOKED;
   expected_results[69] = Path_Validation_Result::CERT_IS_REVOKED;
   expected_results[70] = Path_Validation_Result::CERT_IS_REVOKED;
   expected_results[71] = Path_Validation_Result::CERT_IS_REVOKED;
   expected_results[72] = Path_Validation_Result::CRL_HAS_EXPIRED;
   expected_results[73] = Path_Validation_Result::CRL_HAS_EXPIRED;
   expected_results[74] = Path_Validation_Result::VERIFIED;

   /* These tests use weird CRL extensions which aren't supported yet */
   //expected_results[75] = ;
   //expected_results[76] = ;
   }
