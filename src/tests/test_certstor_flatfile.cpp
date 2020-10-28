/*
* (C) 1999-2019 Jack Lloyd
* (C) 2019      René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_CERTSTOR_FLATFILE)

#include "test_certstor_utils.h"
#include <botan/certstor_flatfile.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/hex.h>

namespace Botan_Tests {

namespace {

std::string get_valid_ca_bundle_path()
   {
   return Test::data_file("x509/misc/certstor/valid_ca_bundle.pem");
   }

std::string get_ca_bundle_containing_user_cert()
   {
   return Test::data_file("x509/misc/certstor/ca_bundle_containing_non_ca.pem");
   }

Test::Result open_certificate_store()
   {
   Test::Result result("Flatfile Certificate Store - Open Store");

   try
      {
      result.start_timer();
      Botan::Flatfile_Certificate_Store unused(get_valid_ca_bundle_path());
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
   Test::Result result("Flatfile Certificate Store - Find Certificate by SHA1(pubkey)");

   try
      {
      result.start_timer();
      Botan::Flatfile_Certificate_Store certstore(get_valid_ca_bundle_path());
      auto cert = certstore.find_cert_by_pubkey_sha1(get_key_id());
      result.end_timer();

      if(result.test_not_null("found certificate", cert.get()))
         {
         auto cns = cert->subject_dn().get_attribute("CN");
         result.test_int_eq("exactly one CN", cns.size(), 1);
         result.test_eq("CN", cns.front(), "DST Root CA X3");
         }
      }
   catch(std::exception& e)
      {
      result.test_failure(e.what());
      }

   result.test_throws("on invalid SHA1 hash data", [&]
      {
      Botan::Flatfile_Certificate_Store certstore(get_valid_ca_bundle_path());
      certstore.find_cert_by_pubkey_sha1({});
      });

   return result;
   }

Test::Result find_cert_by_subject_dn()
   {
   Test::Result result("Flatfile Certificate Store - Find Certificate by subject DN");

   try
      {
      auto dn = get_dn();

      result.start_timer();
      Botan::Flatfile_Certificate_Store certstore(get_valid_ca_bundle_path());
      auto cert = certstore.find_cert(dn, std::vector<uint8_t>());
      result.end_timer();

      if(result.test_not_null("found certificate", cert.get()))
         {
         auto cns = cert->subject_dn().get_attribute("CN");
         result.test_int_eq("exactly one CN", cns.size(), 1);
         result.test_eq("CN", cns.front(), "DST Root CA X3");
         }
      }
   catch(std::exception& e)
      {
      result.test_failure(e.what());
      }

   return result;
   }

Test::Result find_cert_by_utf8_subject_dn()
   {
   Test::Result result("Flatfile Certificate Store - Find Certificate by UTF8 subject DN");

   try
      {
      auto dn = get_utf8_dn();

      result.start_timer();
      Botan::Flatfile_Certificate_Store certstore(get_valid_ca_bundle_path());
      auto cert = certstore.find_cert(dn, std::vector<uint8_t>());

      result.end_timer();

      if(result.test_not_null("found certificate", cert.get()))
         {
         auto cns = cert->subject_dn().get_attribute("CN");
         result.test_is_eq("exactly one CN", cns.size(), size_t(1));
         result.test_eq("CN", cns.front(), "D-TRUST Root Class 3 CA 2 EV 2009");
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
   Test::Result result("Flatfile Certificate Store - Find Certificate by subject DN and key ID");

   try
      {
      auto dn = get_dn();

      result.start_timer();
      Botan::Flatfile_Certificate_Store certstore(get_valid_ca_bundle_path());
      auto cert = certstore.find_cert(dn, get_key_id());
      result.end_timer();

      if(result.test_not_null("found certificate", cert.get()))
         {
         auto cns = cert->subject_dn().get_attribute("CN");
         result.test_int_eq("exactly one CN", cns.size(), 1);
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
   Test::Result result("Flatfile Certificate Store - Find Certificates by subject DN and key ID");

   try
      {
      auto dn = get_dn();

      result.start_timer();
      Botan::Flatfile_Certificate_Store certstore(get_valid_ca_bundle_path());
      auto certs = certstore.find_all_certs(dn, get_key_id());
      result.end_timer();

      if(result.confirm("result not empty", !certs.empty()) &&
            result.test_eq("exactly one certificate", certs.size(), 1))
         {
         auto cns = certs.front()->subject_dn().get_attribute("CN");
         result.test_int_eq("exactly one CN", cns.size(), 1);
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
   Test::Result result("Flatfile Certificate Store - Find all Certificate Subjects");

   try
      {
      result.start_timer();
      Botan::Flatfile_Certificate_Store certstore(get_valid_ca_bundle_path());
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
   Test::Result result("Flatfile Certificate Store - can deal with no matches (regression test)");

   try
      {
      auto dn  = get_unknown_dn();
      auto kid = get_unknown_key_id();

      result.start_timer();
      Botan::Flatfile_Certificate_Store certstore(get_valid_ca_bundle_path());

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

Test::Result certstore_contains_user_certificate()
   {
   Test::Result result("Flatfile Certificate Store - rejects bundles with non-CA certs");

   try
      {
      result.start_timer();
      Botan::Flatfile_Certificate_Store certstore(get_ca_bundle_containing_user_cert());
      result.test_failure("CA bundle with non-CA certs should be rejected");
      }
   catch(Botan::Invalid_Argument&)
      {
      result.test_success();
      }

   return result;
   }

class Certstor_Flatfile_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(open_certificate_store());
         results.push_back(find_certificate_by_pubkey_sha1());
         results.push_back(find_cert_by_subject_dn());
         results.push_back(find_cert_by_utf8_subject_dn());
         results.push_back(find_cert_by_subject_dn_and_key_id());
         results.push_back(find_certs_by_subject_dn_and_key_id());
         results.push_back(find_all_subjects());
         results.push_back(no_certificate_matches());
         results.push_back(certstore_contains_user_certificate());

         return results;
         }
   };

BOTAN_REGISTER_TEST("x509", "certstor_flatfile", Certstor_Flatfile_Tests);

}

}

#endif
