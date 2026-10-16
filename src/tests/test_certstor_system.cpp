/*
* (C) 1999-2021 Jack Lloyd
* (C) 2019,2021 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_CERTSTOR_SYSTEM)

   #include "test_certstor_utils.h"
   #include <botan/assert.h>
   #include <botan/certstor_system.h>
   #include <botan/hex.h>
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

      if(result.test_opt_not_null("found certificate", cert)) {
         auto cns = cert->subject_dn().get_attribute("CN");
         result.test_sz_eq("exactly one CN", cns.size(), 1);
         result.test_str_eq("CN", cns.front(), get_subject_cn());
      }
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   result.test_throws("on invalid SHA1 hash data", [&] { certstore.find_cert_by_pubkey_sha1({}); });

   return result;
}

Test::Result find_certificate_by_pubkey_sha1_with_unmatching_key_id(const Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - Find Certificate by SHA1(pubkey) - regression test for GH #2779");

   if(!certstore.find_cert(get_dn_of_cert_with_different_key_id(), {}).has_value()) {
      result.note_missing("OS does not trust the certificate used for this regression test, skipping");
      return result;
   }

   try {
      result.start_timer();
      auto cert = certstore.find_cert_by_pubkey_sha1(get_pubkey_sha1_of_cert_with_different_key_id());
      result.end_timer();

      if(result.test_opt_not_null("found certificate", cert)) {
         auto cns = cert->subject_dn().get_attribute("CN");
         result.test_sz_eq("exactly one CN", cns.size(), 1);
         result.test_str_eq("CN", cns.front(), "SecureTrust CA");
      }
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result find_cert_by_subject_dn(const Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - Find Certificate by subject DN");

   try {
      const auto dn = get_dn();

      result.start_timer();
      auto cert = certstore.find_cert(dn, std::vector<uint8_t>());
      result.end_timer();

      if(result.test_opt_not_null("found certificate", cert)) {
         auto cns = cert->subject_dn().get_attribute("CN");
         result.test_sz_eq("exactly one CN", cns.size(), 1);
         result.test_str_eq("CN", cns.front(), get_subject_cn());
      }
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result find_cert_by_utf8_subject_dn(const Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - Find Certificate by UTF8 subject DN");

   try {
      const auto DNs = get_utf8_dn_alternatives();

      unsigned int found = 0;

      result.start_timer();
      for(const auto& [cn, dn] : DNs) {
         if(auto cert = certstore.find_cert(dn, {})) {
            auto cns = cert->subject_dn().get_attribute("CN");
            result.test_sz_eq("exactly one CN", cns.size(), 1);
            result.test_str_eq("CN", cns.front(), cn);

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

      result.test_sz_gte("found at least one certificate", found, 1);
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result find_cert_by_subject_dn_and_key_id(const Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - Find Certificate by subject DN and key ID");

   try {
      const auto dn = get_dn();

      result.start_timer();
      auto cert = certstore.find_cert(dn, get_key_id());
      result.end_timer();

      if(result.test_opt_not_null("found certificate", cert)) {
         auto cns = cert->subject_dn().get_attribute("CN");
         result.test_sz_eq("exactly one CN", cns.size(), 1);
         result.test_str_eq("CN", cns.front(), get_subject_cn());
      }
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result find_certs_by_subject_dn_and_key_id(const Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - Find Certificates by subject DN and key ID");

   try {
      const auto dn = get_dn();

      result.start_timer();
      auto certs = certstore.find_all_certs(dn, get_key_id());
      result.end_timer();

      if(result.test_is_true("result not empty", !certs.empty()) &&
         result.test_sz_eq("exactly one certificate", certs.size(), 1)) {
         auto cns = certs.front().subject_dn().get_attribute("CN");
         result.test_sz_eq("exactly one CN", cns.size(), 1);
         result.test_str_eq("CN", cns.front(), get_subject_cn());
         result.test_is_true("returned cert is considered contained", certstore.contains(certs.front()));
      }
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result find_all_certs_by_subject_dn(const Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - Find all Certificates by subject DN");

   try {
      const auto dn = get_dn();

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

      // check all returned certs are considered contained
      for(const auto& cert : certs) {
         result.test_is_true("contains returns true", certstore.contains(cert));
      }

      if(result.test_is_true("result not empty", !certs.empty())) {
         auto cns = certs.front().subject_dn().get_attribute("CN");
         result.test_sz_gte("at least one CN", cns.size(), size_t(1));
         result.test_str_eq("CN", cns.front(), get_subject_cn());
      }
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result find_all_subjects(const Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - Find all Certificate Subjects");

   try {
      result.start_timer();
      auto subjects = certstore.all_subjects();
      result.end_timer();

      if(result.test_is_true("result not empty", !subjects.empty())) {
         const auto dn = get_dn();
         const auto needle = std::find_if(
            subjects.cbegin(), subjects.cend(), [=](const Botan::X509_DN& subject) { return subject == dn; });

         if(result.test_is_true("found expected certificate", needle != subjects.end())) {
            result.test_is_true("expected certificate", *needle == dn);
         }
      }
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result find_cert_by_issuer_dn_and_serial_number(const Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - Find Certificate by issuer DN and serial number");

   try {
      result.start_timer();
      auto cert = certstore.find_cert_by_issuer_dn_and_serial_number(get_dn(), get_serial_number());
      result.end_timer();

      if(result.test_opt_not_null("found certificate", cert)) {
         auto cns = cert->subject_dn().get_attribute("CN");
         result.test_sz_eq("exactly one CN", cns.size(), 1);
         result.test_str_eq("CN", cns.front(), get_subject_cn());
         result.test_bin_eq("serial number", cert->serial_number(), get_serial_number());
         result.test_is_true("returned cert is considered contained", certstore.contains(cert.value()));
      }
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result no_certificate_matches(const Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - can deal with no matches (regression test)");

   try {
      const auto dn = get_unknown_dn();
      const auto kid = get_unknown_key_id();

      result.start_timer();
      const auto certs = certstore.find_all_certs(dn, kid);
      const auto cert = certstore.find_cert(dn, kid);
      const auto pubk_cert = certstore.find_cert_by_pubkey_sha1(kid);
      result.end_timer();

      result.test_is_true("find_all_certs did not find the dummy", certs.empty());
      result.test_is_true("find_cert did not find the dummy", !cert);
      result.test_is_true("find_cert_by_pubkey_sha1 did not find the dummy", !pubk_cert);
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result repeated_lookups_share_parsed_certificate(const Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - repeated lookups share the parsed certificate");

   try {
      const auto dn = get_dn();

      result.start_timer();
      const auto first = certstore.find_cert(dn, {});
      const auto second = certstore.find_cert(dn, {});
      result.end_timer();

      if(result.test_opt_not_null("first lookup found the certificate", first) &&
         result.test_opt_not_null("second lookup found the certificate", second)) {
         result.test_is_true("both lookups return the same certificate", *first == *second);

         // certificate_data_sha256() returns a view into the parsed certificate
         // data. Equal pointers prove that the two objects share it, i.e. the
         // second lookup was served from the cache instead of parsing again.
         result.test_is_true("parsed certificate data is shared between the lookups",
                             first->certificate_data_sha256().data() == second->certificate_data_sha256().data());
      }
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result contains_trusted_root_loaded_from_file(const Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - contains() for a trusted root loaded from a file");

   try {
      // ISRG Root X1 is the first certificate in this bundle. Loading it from
      // a file (rather than from the keychain) exercises the encoding that the
      // lookup hands to the keychain.
      const Botan::X509_Certificate root(Test::data_file("x509/misc/certstor/ca_bundle_containing_non_ca.pem"));

      if(result.test_str_eq(
            "fixture is the expected root", root.subject_dn().get_first_attribute("CN"), get_subject_cn())) {
         result.start_timer();
         const bool contained = certstore.contains(root);
         result.end_timer();

         result.test_is_true("root loaded from file is contained", contained);
      }
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result contains_rejects_untrusted_certificate(Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - contains() for a certificate that is not in the store");

   try {
      // self-signed test root of the x509test suite, certainly not in any
      // system keychain
      const Botan::X509_Certificate unknown(Test::data_file("x509/x509test/root.pem"));

      bool contained = true;
      result.test_no_throw("contains() does not throw for an unknown certificate",
                           [&] { contained = certstore.contains(unknown); });
      result.test_is_false("unknown certificate is not contained", contained);
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result contains_every_certificate_in_the_store(const Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - contains() for every certificate in the store");

   try {
      const auto subjects = certstore.all_subjects();

      size_t checked = 0;
      size_t not_found = 0;

      result.start_timer();
      for(const auto& dn : subjects) {
         const auto certs = certstore.find_all_certs(dn, {});
         if(certs.empty()) {
            // subject DN could not be looked up again (DN normalization
            // issue unrelated to contains()); just note it
            ++not_found;
         }

         for(const auto& cert : certs) {
            if(!certstore.contains(cert)) {
               result.test_failure("certificate is not considered contained: " + cert.subject_dn().to_string());
            }
            ++checked;
         }
      }
      result.end_timer();

      result.test_sz_gte("checked at least one certificate", checked, 1);
      result.test_note("checked " + std::to_string(checked) + " certificates, " + std::to_string(not_found) +
                       " subjects could not be looked up again");
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

bool skipped_in_issuer_and_serial_number_sweep(const Botan::X509_Certificate& cert) {
   #if defined(BOTAN_HAS_CERTSTOR_WINDOWS)
   // The Windows store does not find this certificate by issuer DN and
   // serial number. The reason is currently unknown and needs investigation
   // (see GH #5929).
   return cert.subject_dn().get_first_attribute("CN") == "TWCA Root Certification Authority";
   #else
   BOTAN_UNUSED(cert);
   return false;
   #endif
}

Test::Result find_every_certificate_by_issuer_dn_and_serial_number(const Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - Find every certificate in the store by issuer DN and serial number");

   try {
      const auto subjects = certstore.all_subjects();

      size_t checked = 0;
      size_t skipped = 0;
      size_t leading_zero = 0;
      size_t short_serial = 0;
      size_t zero_serial = 0;

      result.start_timer();
      for(const auto& dn : subjects) {
         for(const auto& cert : certstore.find_all_certs(dn, {})) {
            // count the serial number encodings this covers
            const auto contents = cert.serial().der_contents();
            if(cert.serial().is_zero()) {
               ++zero_serial;
            } else if(contents.front() == 0x00) {
               ++leading_zero;
            } else if(contents.size() <= 2) {
               ++short_serial;
            }

            if(skipped_in_issuer_and_serial_number_sweep(cert)) {
               ++skipped;
               continue;
            }

            const auto found =
               certstore.find_cert_by_issuer_dn_and_serial_number(cert.issuer_dn(), cert.serial_number());
            if(!found.has_value()) {
               result.test_failure("certificate not found by issuer DN and serial number: " +
                                   cert.subject_dn().to_string());
            } else if(!(*found == cert)) {
               result.test_failure("lookup by issuer DN and serial number of " + cert.subject_dn().to_string() +
                                   " returned a different certificate: " + found->subject_dn().to_string() +
                                   " with serial number " + Botan::hex_encode(found->serial_number()));
            }
            ++checked;
         }
      }
      result.end_timer();

      result.test_sz_gte("checked at least one certificate", checked, 1);
      result.test_note("checked " + std::to_string(checked) + " certificates (" + std::to_string(leading_zero) +
                       " with a leading zero octet, " + std::to_string(short_serial) + " short, " +
                       std::to_string(zero_serial) + " zero serial numbers), skipped " + std::to_string(skipped));
   } catch(std::exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

Test::Result find_cert_by_issuer_dn_and_unknown_serial_number(Botan::Certificate_Store& certstore) {
   Test::Result result("System Certificate Store - Find Certificate by issuer DN and unknown serial number");

   try {
      auto serial = get_serial_number();
      serial.back() ^= 0x01;

      std::optional<Botan::X509_Certificate> cert;
      result.test_no_throw("lookup with an unknown serial number does not throw",
                           [&] { cert = certstore.find_cert_by_issuer_dn_and_serial_number(get_dn(), serial); });
      result.test_opt_is_null("no certificate for an unknown serial number", cert);
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

      if(result.test_is_true("find_all_certs did find the skewed DN", !certs.empty()) &&
         result.test_is_true("find_cert did find the skewed DN", cert.has_value())) {
         result.test_str_eq(
            "it is the correct cert", certs.front().subject_dn().get_first_attribute("CN"), get_subject_cn());
         result.test_str_eq("it is the correct cert", cert->subject_dn().get_first_attribute("CN"), get_subject_cn());
      }

      // check all returned certs are considered contained
      for(const auto& ret : certs) {
         result.test_is_true("contains returns true", certstore.contains(ret));
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
         } catch(Botan::Not_Implemented&) {
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
         results.push_back(repeated_lookups_share_parsed_certificate(*system));
         results.push_back(contains_trusted_root_loaded_from_file(*system));
         results.push_back(contains_rejects_untrusted_certificate(*system));
         results.push_back(contains_every_certificate_in_the_store(*system));
         results.push_back(find_every_certificate_by_issuer_dn_and_serial_number(*system));
         results.push_back(find_cert_by_issuer_dn_and_unknown_serial_number(*system));
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
