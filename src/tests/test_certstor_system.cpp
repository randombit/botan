/*
* (C) 1999-2021 Jack Lloyd
* (C) 2019,2021 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_CERTSTOR_SYSTEM)

   #include "test_certstor_utils.h"
   #include <botan/certstor_system.h>
   #include <algorithm>
   #include <memory>

namespace Botan_Tests {

namespace {

Test::Result find_certificate_by_pubkey_sha1(Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - Find Certificate by SHA1(pubkey)");

   try {
      result.start_timer();
      auto cert = certstore.find_cert_by_pubkey_sha1(get_key_id());
      result.end_timer();

      if(result.test_not_nullopt("found certificate", cert)) {
         auto cns = cert->subject_dn().get_attribute("CN");
         result.test_is_eq("exactly one CN", cns.size(), size_t(1));
         result.test_eq("CN", cns.front(), get_subject_cn());
      }
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   result.test_throws("on invalid SHA1 hash data", [&] { certstore.find_cert_by_pubkey_sha1({}); });

   return result;
}

Test::Result find_certificate_by_pubkey_sha1_with_unmatching_key_id(Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - Find Certificate by SHA1(pubkey) - regression test for GH #2779");

   if(!certstore.find_cert(get_dn_of_cert_with_different_key_id(), {}).has_value()) {
      result.note_missing("OS does not trust the certificate used for this regression test, skipping");
      return result;
   }

   try {
      result.start_timer();
      auto cert = certstore.find_cert_by_pubkey_sha1(get_pubkey_sha1_of_cert_with_different_key_id());
      result.end_timer();

      if(result.test_not_nullopt("found certificate", cert)) {
         auto cns = cert->subject_dn().get_attribute("CN");
         result.test_is_eq("exactly one CN", cns.size(), size_t(1));
         result.test_eq("CN", cns.front(), "SecureTrust CA");
      }
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result find_cert_by_subject_dn(Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - Find Certificate by subject DN");

   try {
      auto dn = get_dn();

      result.start_timer();
      auto cert = certstore.find_cert(dn, std::vector<uint8_t>());
      result.end_timer();

      if(result.test_not_nullopt("found certificate", cert)) {
         auto cns = cert->subject_dn().get_attribute("CN");
         result.test_is_eq("exactly one CN", cns.size(), size_t(1));
         result.test_eq("CN", cns.front(), get_subject_cn());
      }
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result find_cert_by_utf8_subject_dn(Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - Find Certificate by UTF8 subject DN");

   try {
      const auto DNs = get_utf8_dn_alternatives();

      unsigned int found = 0;

      result.start_timer();
      for(const auto& [cn, dn] : DNs) {
         if(auto cert = certstore.find_cert(dn, {})) {
            auto cns = cert->subject_dn().get_attribute("CN");
            result.test_is_eq("exactly one CN", cns.size(), size_t(1));
            result.test_eq("CN", cns.front(), cn);

            ++found;
         }
      }
      result.end_timer();

      if(found == 0) {
         std::string tried_cns;
         for(const auto& [cn, dn] : DNs) {
            tried_cns += cn + ", ";
         }

         result.test_note("Tried to find any of those CNs: " + tried_cns);
         result.test_failure("Did not find any certificate via an UTF-8 encoded DN");
      }

      result.test_gte("found at least one certificate", found, 1);
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result find_cert_by_subject_dn_and_key_id(Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - Find Certificate by subject DN and key ID");

   try {
      auto dn = get_dn();

      result.start_timer();
      auto cert = certstore.find_cert(dn, get_key_id());
      result.end_timer();

      if(result.test_not_nullopt("found certificate", cert)) {
         auto cns = cert->subject_dn().get_attribute("CN");
         result.test_is_eq("exactly one CN", cns.size(), size_t(1));
         result.test_eq("CN", cns.front(), get_subject_cn());
      }
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result find_certs_by_subject_dn_and_key_id(Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - Find Certificates by subject DN and key ID");

   try {
      auto dn = get_dn();

      result.start_timer();
      auto certs = certstore.find_all_certs(dn, get_key_id());
      result.end_timer();

      if(result.confirm("result not empty", !certs.empty()) &&
         result.test_eq("exactly one certificate", certs.size(), 1)) {
         auto cns = certs.front().subject_dn().get_attribute("CN");
         result.test_is_eq("exactly one CN", cns.size(), size_t(1));
         result.test_eq("CN", cns.front(), get_subject_cn());
      }
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result find_all_certs_by_subject_dn(Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - Find all Certificates by subject DN");

   try {
      auto dn = get_dn();

      result.start_timer();
      auto certs = certstore.find_all_certs(dn, std::vector<uint8_t>());
      result.end_timer();

      // check for duplications
      sort(certs.begin(), certs.end());
      for(size_t i = 1; i < certs.size(); ++i) {
         if(certs[i - 1] == certs[i]) {
            result.test_failure("find_all_certs produced duplicated result");
         }
      }

      if(result.confirm("result not empty", !certs.empty())) {
         auto cns = certs.front().subject_dn().get_attribute("CN");
         result.test_gte("at least one CN", cns.size(), size_t(1));
         result.test_eq("CN", cns.front(), get_subject_cn());
      }
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result find_all_subjects(Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - Find all Certificate Subjects");

   try {
      result.start_timer();
      auto subjects = certstore.all_subjects();
      result.end_timer();

      if(result.confirm("result not empty", !subjects.empty())) {
         auto dn = get_dn();
         auto needle = std::find_if(
            subjects.cbegin(), subjects.cend(), [=](const Botan::X509_DN& subject) { return subject == dn; });

         if(result.confirm("found expected certificate", needle != subjects.end())) {
            result.confirm("expected certificate", *needle == dn);
         }
      }
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result find_cert_by_issuer_dn_and_serial_number(Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - Find Certificate by issuer DN and serial number");

   try {
      result.start_timer();
      auto cert = certstore.find_cert_by_issuer_dn_and_serial_number(get_dn(), get_serial_number());
      result.end_timer();

      if(result.test_not_nullopt("found certificate", cert)) {
         auto cns = cert->subject_dn().get_attribute("CN");
         result.test_is_eq("exactly one CN", cns.size(), size_t(1));
         result.test_eq("CN", cns.front(), get_subject_cn());
         result.test_eq("serial number", cert->serial_number(), get_serial_number());
      }
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result no_certificate_matches(Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - can deal with no matches (regression test)");

   try {
      auto dn = get_unknown_dn();
      auto kid = get_unknown_key_id();

      result.start_timer();
      auto certs = certstore.find_all_certs(dn, kid);
      auto cert = certstore.find_cert(dn, kid);
      auto pubk_cert = certstore.find_cert_by_pubkey_sha1(kid);
      result.end_timer();

      result.confirm("find_all_certs did not find the dummy", certs.empty());
      result.confirm("find_cert did not find the dummy", !cert);
      result.confirm("find_cert_by_pubkey_sha1 did not find the dummy", !pubk_cert);
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

   #if defined(BOTAN_HAS_CERTSTOR_MACOS)

Test::Result certificate_matching_with_dn_normalization(Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - normalization of X.509 DN (regression test)");

   try {
      auto dn = get_skewed_dn();

      result.start_timer();
      auto certs = certstore.find_all_certs(dn, std::vector<uint8_t>());
      auto cert = certstore.find_cert(dn, std::vector<uint8_t>());
      result.end_timer();

      if(result.confirm("find_all_certs did find the skewed DN", !certs.empty()) &&
         result.confirm("find_cert did find the skewed DN", cert.has_value())) {
         result.test_eq(
            "it is the correct cert", certs.front().subject_dn().get_first_attribute("CN"), get_subject_cn());
         result.test_eq("it is the correct cert", cert->subject_dn().get_first_attribute("CN"), get_subject_cn());
      }
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

   #endif

class Certstor_System_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result open_result("System Certificate Store - Open Keychain");

         std::unique_ptr<Botan::Certificate_Store> system;

         try {
            open_result.start_timer();
            system = std::make_unique<Botan::System_Certificate_Store>();
            open_result.end_timer();
         } catch(Botan::Not_Implemented& e) {
            BOTAN_UNUSED(e);
            open_result.test_note("Skipping due to not available in current build");
            return {open_result};
         } catch(std::exception& e) {
            open_result.test_failure(e.what());
            return {open_result};
         }

         open_result.test_success();

         std::vector<Test::Result> results;
         results.push_back(open_result);

         results.push_back(find_certificate_by_pubkey_sha1(*system));
         results.push_back(find_certificate_by_pubkey_sha1_with_unmatching_key_id(*system));
         results.push_back(find_cert_by_subject_dn(*system));
         results.push_back(find_cert_by_subject_dn_and_key_id(*system));
         results.push_back(find_all_certs_by_subject_dn(*system));
         results.push_back(find_certs_by_subject_dn_and_key_id(*system));
         results.push_back(find_all_subjects(*system));
         results.push_back(no_certificate_matches(*system));
         results.push_back(find_cert_by_utf8_subject_dn(*system));
         results.push_back(find_cert_by_issuer_dn_and_serial_number(*system));
   #if defined(BOTAN_HAS_CERTSTOR_MACOS)
         results.push_back(certificate_matching_with_dn_normalization(*system));
   #endif

         return results;
      }
};

BOTAN_REGISTER_TEST("x509", "certstor_system", Certstor_System_Tests);

}  // namespace

}  // namespace Botan_Tests

#endif
