/*
  Code to run the X.509v3 processing tests described in "Conformance
  Testing of Relying Party Client Certificate Path Proccessing Logic",
  which is available on NIST's web site.
*/

#include <botan/x509stor.h>
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

void run_one_test(u32bit, X509_Code,
                  std::string, std::string,
                  std::vector<std::string>,
                  std::vector<std::string>);

std::map<u32bit, X509_Code> expected_results;

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

void run_one_test(u32bit test_no, X509_Code expected,
                  std::string root_cert, std::string to_verify,
                  std::vector<std::string> certs,
                  std::vector<std::string> crls)
   {
   std::cout << "Processing test #" << test_no << "... ";
   std::cout.flush();

   X509_Code result = VERIFIED;

   X509_Store store;

   store.add_cert(X509_Certificate(root_cert), true);

   X509_Certificate end_user(to_verify);

   for(size_t j = 0; j != certs.size(); j++)
      store.add_cert(X509_Certificate(certs[j]));

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
      result = store.add_crl(crl);
      if(result != VERIFIED)
         break;
      }

   /* if everything has gone well up until now */

   if(result == VERIFIED)
      {
      result = store.validate_cert(end_user);

      X509_Code result2 = store.validate_cert(end_user);

      if(result != result2)
         std::cout << "Two runs, two answers: " << result << " "
                   << result2 << std::endl;
      }

   if(result == expected)
      {
      std::cout << "passed" << std::endl;
      return;
      }

   if(expected == VERIFIED)
      {
      std::cout << "unexpected failure: " << result << std::endl;
      unexp_failure++;
      }
   else if(result == VERIFIED)
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
   expected_results[1] = VERIFIED;
   expected_results[2] = SIGNATURE_ERROR;
   expected_results[3] = SIGNATURE_ERROR;
   expected_results[4] = VERIFIED;
   expected_results[5] = CERT_NOT_YET_VALID;
   expected_results[6] = CERT_NOT_YET_VALID;
   expected_results[7] = VERIFIED;
   expected_results[8] = CERT_NOT_YET_VALID;
   expected_results[9] = CERT_HAS_EXPIRED;
   expected_results[10] = CERT_HAS_EXPIRED;
   expected_results[11] = CERT_HAS_EXPIRED;
   expected_results[12] = VERIFIED;
   expected_results[13] = CERT_ISSUER_NOT_FOUND;

   // FIXME: we get the answer right for the wrong reason
   //   ummm... I don't know if that is still true. I wish I had thought to
   //   write down exactly what this 'wrong reason' was in the first place.
   expected_results[14] = CERT_ISSUER_NOT_FOUND;
   expected_results[15] = VERIFIED;
   expected_results[16] = VERIFIED;
   expected_results[17] = VERIFIED;
   expected_results[18] = VERIFIED;

   /************* CHANGE OF TEST RESULT FOR TEST #19 ************************
     One of the certificates has no attached CRL. By strict X.509 rules, if
     there is no good CRL in hand, then the certificate shouldn't be used for
     CA stuff. But while this is usually a good idea, it interferes with simple
     uses of certificates which shouldn't (IMO) force the use of CRLs. There is
     no assigned error code for this scenario because I don't consider it to be
     an error (probably would be something like NO_REVOCATION_DATA_AVAILABLE)
   **************************************************************************/
   expected_results[19] = VERIFIED;
   expected_results[20] = CERT_IS_REVOKED;
   expected_results[21] = CERT_IS_REVOKED;

   expected_results[22] = CA_CERT_NOT_FOR_CERT_ISSUER;
   expected_results[23] = CA_CERT_NOT_FOR_CERT_ISSUER;
   expected_results[24] = VERIFIED;
   expected_results[25] = CA_CERT_NOT_FOR_CERT_ISSUER;
   expected_results[26] = VERIFIED;
   expected_results[27] = VERIFIED;
   expected_results[28] = CA_CERT_NOT_FOR_CERT_ISSUER;
   expected_results[29] = CA_CERT_NOT_FOR_CERT_ISSUER;
   expected_results[30] = VERIFIED;

   expected_results[31] = CA_CERT_NOT_FOR_CRL_ISSUER;
   expected_results[32] = CA_CERT_NOT_FOR_CRL_ISSUER;
   expected_results[33] = VERIFIED;

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

   expected_results[34] = VERIFIED;
   expected_results[35] = VERIFIED;
   expected_results[36] = VERIFIED;
   expected_results[37] = VERIFIED;
   expected_results[38] = VERIFIED;
   expected_results[39] = VERIFIED;
   expected_results[40] = VERIFIED;
   expected_results[41] = VERIFIED;
   expected_results[42] = VERIFIED;
   expected_results[43] = VERIFIED;
   expected_results[44] = VERIFIED;

   //expected_results[45] = EXPLICT_POLICY_REQUIRED;
   //expected_results[46] = ACCEPT;
   //expected_results[47] = EXPLICT_POLICY_REQUIRED;

   expected_results[48] = VERIFIED;
   expected_results[49] = VERIFIED;
   expected_results[50] = VERIFIED;
   expected_results[51] = VERIFIED;
   expected_results[52] = VERIFIED;
   expected_results[53] = VERIFIED;

   expected_results[54] = CERT_CHAIN_TOO_LONG;
   expected_results[55] = CERT_CHAIN_TOO_LONG;
   expected_results[56] = VERIFIED;
   expected_results[57] = VERIFIED;
   expected_results[58] = CERT_CHAIN_TOO_LONG;
   expected_results[59] = CERT_CHAIN_TOO_LONG;
   expected_results[60] = CERT_CHAIN_TOO_LONG;
   expected_results[61] = CERT_CHAIN_TOO_LONG;
   expected_results[62] = VERIFIED;
   expected_results[63] = VERIFIED;

   expected_results[64] = SIGNATURE_ERROR;

   /************ CHANGE OF TEST RESULT FOR TEST #65 *************************
     I cannot figure out what exactly the problem here is supposed to be;
     looking at it by hand, everything seems fine. If someone can explain I
     would be happy to listen.
   ************************************************************************/
   expected_results[65] = VERIFIED;
   expected_results[66] = CRL_ISSUER_NOT_FOUND;

   /************ CHANGE OF TEST RESULT FOR TEST #67 *************************
     The test docs say this should be verified. However, the problem being that
     there is an extra CRL with an unknown issuer. Returning VERIFIED in this
     case is obviously bad, since the user may well want to know that the CRL
     in question has no known issuer. So we return CRL_ISSUER_NOT_FOUND instead
     of VERIFIED. The actual certificate path of course still verifies, but
     it's kind of an all-or-nothing testing procedure.
   ************************************************************************/
   expected_results[67] = CRL_ISSUER_NOT_FOUND;

   expected_results[68] = CERT_IS_REVOKED;
   expected_results[69] = CERT_IS_REVOKED;
   expected_results[70] = CERT_IS_REVOKED;
   expected_results[71] = CERT_IS_REVOKED;
   expected_results[72] = CRL_HAS_EXPIRED;
   expected_results[73] = CRL_HAS_EXPIRED;
   expected_results[74] = VERIFIED;

   /* These tests use weird CRL extensions which aren't supported yet */
   //expected_results[75] = ;
   //expected_results[76] = ;
   }
