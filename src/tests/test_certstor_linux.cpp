/*
* (C) 1999-2019 Jack Lloyd
* (C) 2019      René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_CERTSTOR_FLATFILE) && defined(BOTAN_SYSTEM_CERT_BUNDLE)

#include "test_certstor_utils.h"
#include <botan/certstor_flatfile.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/hex.h>

namespace Botan_Tests {

namespace {

Test::Result open_certificate_store()
   {
   Test::Result result("linux Certificate Store - Open Store");

   try
      {
      result.start_timer();
      Botan::Flatfile_Certificate_Store unused(BOTAN_SYSTEM_CERT_BUNDLE);
      result.end_timer();
      result.test_gt("found some certificates", unused.all_subjects().size(), 0);
      }
   catch(std::exception& e)
      {
      result.test_failure(e.what());
      }

   result.test_success();

   return result;
   }

Test::Result find_certificate_by_pubkey_sha1()
   {
   Test::Result result("linux Certificate Store - Find Certificate by SHA1(pubkey)");

   try
      {
      result.start_timer();
      Botan::Flatfile_Certificate_Store certstore(BOTAN_SYSTEM_CERT_BUNDLE);
      auto cert = certstore.find_cert_by_pubkey_sha1(get_key_id());
      result.end_timer();

      if(result.test_not_null("found certificate", cert.get()))
         {
         auto cns = cert->subject_dn().get_attribute("CN");
         result.test_is_eq("exactly one CN", cns.size(), 1ul);
         result.test_eq("CN", cns.front(), "DST Root CA X3");
         }
      }
   catch(std::exception& e)
      {
      result.test_failure(e.what());
      }

   result.test_throws("on invalid SHA1 hash data", [&]
      {
      Botan::Flatfile_Certificate_Store certstore(BOTAN_SYSTEM_CERT_BUNDLE);
      certstore.find_cert_by_pubkey_sha1({});
      });

   return result;
   }

Test::Result find_cert_by_subject_dn()
   {
   Test::Result result("linux Certificate Store - Find Certificate by subject DN");

   try
      {
      auto dn = get_dn();

      result.start_timer();
      Botan::Flatfile_Certificate_Store certstore(BOTAN_SYSTEM_CERT_BUNDLE);
      auto cert = certstore.find_cert(dn, std::vector<uint8_t>());
      result.end_timer();

      if(result.test_not_null("found certificate", cert.get()))
         {
         auto cns = cert->subject_dn().get_attribute("CN");
         result.test_is_eq("exactly one CN", cns.size(), 1ul);
         result.test_eq("CN", cns.front(), "DST Root CA X3");
         }
      }
   catch(std::exception& e)
      {
      result.test_failure(e.what());
      }

   return result;
   }

Test::Result find_cert_by_subject_dn_and_key_id()
   {
   Test::Result result("linux Certificate Store - Find Certificate by subject DN and key ID");

   try
      {
      auto dn = get_dn();

      result.start_timer();
      Botan::Flatfile_Certificate_Store certstore(BOTAN_SYSTEM_CERT_BUNDLE);
      auto cert = certstore.find_cert(dn, get_key_id());
      result.end_timer();

      if(result.test_not_null("found certificate", cert.get()))
         {
         auto cns = cert->subject_dn().get_attribute("CN");
         result.test_is_eq("exactly one CN", cns.size(), 1ul);
         result.test_eq("CN", cns.front(), "DST Root CA X3");
         }
      }
   catch(std::exception& e)
      {
      result.test_failure(e.what());
      }

   return result;
   }

Test::Result find_certs_by_subject_dn_and_key_id()
   {
   Test::Result result("linux Certificate Store - Find Certificates by subject DN and key ID");

   try
      {
      auto dn = get_dn();

      result.start_timer();
      Botan::Flatfile_Certificate_Store certstore(BOTAN_SYSTEM_CERT_BUNDLE);
      auto certs = certstore.find_all_certs(dn, get_key_id());
      result.end_timer();

      if(result.confirm("result not empty", !certs.empty()) &&
            result.test_eq("exactly one certificate", certs.size(), 1))
         {
         auto cns = certs.front()->subject_dn().get_attribute("CN");
         result.test_is_eq("exactly one CN", cns.size(), 1ul);
         result.test_eq("CN", cns.front(), "DST Root CA X3");
         }
      }
   catch(std::exception& e)
      {
      result.test_failure(e.what());
      }

   return result;
   }

Test::Result find_all_subjects()
   {
   Test::Result result("linux Certificate Store - Find all Certificate Subjects");

   try
      {
      result.start_timer();
      Botan::Flatfile_Certificate_Store certstore(BOTAN_SYSTEM_CERT_BUNDLE);
      auto subjects = certstore.all_subjects();
      result.end_timer();

      if(result.confirm("result not empty", !subjects.empty()))
         {
         auto dn = get_dn();
         auto needle = std::find_if(subjects.cbegin(),
                                    subjects.cend(),
                                    [=](const Botan::X509_DN &subject)
            {
            return subject == dn;
            });

         if(result.confirm("found expected certificate", needle != subjects.end()))
            {
            result.confirm("expected certificate", *needle == dn);
            }
         }
      }
   catch(std::exception& e)
      {
      result.test_failure(e.what());
      }

   return result;
   }

Test::Result no_certificate_matches()
   {
   Test::Result result("linux Certificate Store - can deal with no matches (regression test)");

   try
      {
      auto dn  = get_unknown_dn();
      auto kid = get_unknown_key_id();

      result.start_timer();
      Botan::Flatfile_Certificate_Store certstore(BOTAN_SYSTEM_CERT_BUNDLE);

      auto certs = certstore.find_all_certs(dn, kid);
      auto cert = certstore.find_cert(dn, kid);
      auto pubk_cert = certstore.find_cert_by_pubkey_sha1(kid);
      result.end_timer();

      result.confirm("find_all_certs did not find the dummy", certs.empty());
      result.confirm("find_cert did not find the dummy", !cert);
      result.confirm("find_cert_by_pubkey_sha1 did not find the dummy", !pubk_cert);
      }
   catch(std::exception& e)
      {
      result.test_failure(e.what());
      }

   return result;
   }

class Certstor_Linux_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(open_certificate_store());
         results.push_back(find_certificate_by_pubkey_sha1());
         results.push_back(find_cert_by_subject_dn());
         results.push_back(find_cert_by_subject_dn_and_key_id());
         results.push_back(find_certs_by_subject_dn_and_key_id());
         results.push_back(find_all_subjects());
         results.push_back(no_certificate_matches());

         return results;
         }
   };

BOTAN_REGISTER_TEST("certstor_linux", Certstor_Linux_Tests);

}

}

#endif
