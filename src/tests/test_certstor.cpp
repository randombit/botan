/*
* (C) 2016 Kai Michaelis, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/certstor.h>
   #include <botan/pk_keys.h>
   #include <botan/pkcs8.h>
   #include <botan/pkix_types.h>
   #include <botan/x509cert.h>
   #include <botan/internal/filesystem.h>

   #if defined(BOTAN_HAS_CERTSTOR_SQLITE3)
      #include <botan/certstor_sqlite.h>
      #include <botan/sqlite3.h>
   #endif
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_HAS_RSA) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

class CertificateAndKey {
   public:
      CertificateAndKey(const Botan::X509_Certificate& cert, std::shared_ptr<Botan::Private_Key> key) :
            m_certificate(cert), m_private_key(std::move(key)) {}

      bool operator!=(const CertificateAndKey& rhs) const {
         if(m_certificate != rhs.m_certificate) {
            return false;
         }
         // XXX: this is comparing the pointers, is that really correct?
         if(m_private_key != rhs.m_private_key) {
            return false;
         }
         return true;
      }

      const Botan::X509_DN& subject_dn() const { return certificate().subject_dn(); }

      const Botan::X509_Certificate& certificate() const { return m_certificate; }

      const Botan::Private_Key& private_key() const { return *m_private_key; }

   private:
      const Botan::X509_Certificate m_certificate;
      const std::shared_ptr<Botan::Private_Key> m_private_key;
};

   #if defined(BOTAN_HAS_CERTSTOR_SQLITE3)
Test::Result test_certstor_sqlite3_insert_find_remove_test(const std::vector<CertificateAndKey>& certsandkeys) {
   Test::Result result("Certificate Store SQLITE3 - Insert, Find, Remove");

   try {
      auto rng = Test::new_rng(__func__);
      const std::string passwd(reinterpret_cast<const char*>(rng->random_vec(8).data()), 8);
      // Just create a database in memory for testing (https://sqlite.org/inmemorydb.html)
      Botan::Certificate_Store_In_SQLite store(":memory:", passwd, *rng);

      for(const auto& a : certsandkeys) {
         store.insert_key(a.certificate(), a.private_key());
      }

      for(const auto& certandkey : certsandkeys) {
         const auto& cert = certandkey.certificate();
         const auto& key = certandkey.private_key();
         const auto wo_keyid = store.find_cert(cert.subject_dn(), {});
         const auto w_keyid = store.find_cert(cert.subject_dn(), cert.subject_key_id());

         if(!wo_keyid || !w_keyid) {
            result.test_failure("Can't retrieve certificate");
            return result;
         }

         const auto priv = store.find_key(cert);
         if(!priv && (certsandkeys[1] != certandkey && certsandkeys[0] != certandkey)) {
            result.test_failure("Can't retrieve private key for " + cert.fingerprint("SHA-1"));
            return result;
         }

         result.test_eq("Got wrong certificate", cert.fingerprint(), w_keyid->fingerprint());

         if(priv) {
            result.test_eq("Got wrong private key", key.private_key_bits(), priv->private_key_bits());

            const auto rev_certs = store.find_certs_for_key(*priv);

            if(rev_certs.empty()) {
               result.test_failure("No certificate");
            } else {
               const bool found =
                  std::any_of(rev_certs.begin(), rev_certs.end(), [&](const Botan::X509_Certificate& c) {
                     return c.fingerprint() == cert.fingerprint();
                  });

               result.test_eq("Got wrong/no certificate", found, true);
            }
         }

         if(certsandkeys[4] != certandkey && certsandkeys[5] != certandkey) {
            result.test_eq("Got wrong certificate", cert.fingerprint(), wo_keyid->fingerprint());
         }

         result.test_eq("Can't remove certificate", store.remove_cert(cert), true);
         result.test_eq("Can't remove certificate", !store.find_cert(cert.subject_dn(), cert.subject_key_id()), true);

         if(priv) {
            store.remove_key(key);
         }

         result.test_eq("Can't remove key", !store.find_key(cert), true);
      }

      return result;
   } catch(std::exception& e) {
      result.test_failure(e.what());
      return result;
   }
}

Test::Result test_certstor_sqlite3_crl_test(const std::vector<CertificateAndKey>& certsandkeys) {
   Test::Result result("Certificate Store SQLITE3 - CRL");
   try {
      auto rng = Test::new_rng(__func__);
      const std::string passwd(reinterpret_cast<const char*>(rng->random_vec(8).data()), 8);
      // Just create a database in memory for testing (https://sqlite.org/inmemorydb.html)
      Botan::Certificate_Store_In_SQLite store(":memory:", passwd, *rng);

      for(const auto& a : certsandkeys) {
         store.insert_cert(a.certificate());
      }

      store.revoke_cert(certsandkeys[0].certificate(), Botan::CRL_Code::CaCompromise);
      store.revoke_cert(certsandkeys[3].certificate(), Botan::CRL_Code::CaCompromise);
      store.revoke_cert(certsandkeys[3].certificate(), Botan::CRL_Code::CaCompromise);

      {
         const auto crls = store.generate_crls();

         result.test_eq("Can't revoke certificate", crls.size(), 2);
         result.test_eq(
            "Can't revoke certificate",
            crls[0].is_revoked(certsandkeys[0].certificate()) ^ crls[1].is_revoked(certsandkeys[0].certificate()),
            true);
         result.test_eq(
            "Can't revoke certificate",
            crls[0].is_revoked(certsandkeys[3].certificate()) ^ crls[1].is_revoked(certsandkeys[3].certificate()),
            true);
      }

      store.affirm_cert(certsandkeys[3].certificate());

      {
         const auto crls = store.generate_crls();

         result.test_eq("Can't revoke certificate, wrong crl size", crls.size(), 1);
         result.test_eq(
            "Can't revoke certificate, cert 0 not revoked", crls[0].is_revoked(certsandkeys[0].certificate()), true);
      }

      const auto cert0_crl = store.find_crl_for(certsandkeys[0].certificate());

      result.test_eq("Can't revoke certificate, crl for cert 0", !cert0_crl, false);
      result.test_eq("Can't revoke certificate, crl for cert 0 size check", cert0_crl->get_revoked().size(), 1);
      result.test_eq(
         "Can't revoke certificate, no crl for cert 0", cert0_crl->is_revoked(certsandkeys[0].certificate()), true);

      const auto cert3_crl = store.find_crl_for(certsandkeys[3].certificate());

      result.test_eq("Can't revoke certificate, crl for cert 3", !cert3_crl, true);

      return result;
   } catch(std::exception& e) {
      result.test_failure(e.what());
      return result;
   }
}

Test::Result test_certstor_sqlite3_all_subjects_test(const std::vector<CertificateAndKey>& certsandkeys) {
   Test::Result result("Certificate Store SQLITE3 - All subjects");
   try {
      auto rng = Test::new_rng(__func__);
      const std::string passwd(reinterpret_cast<const char*>(rng->random_vec(8).data()), 8);
      // Just create a database in memory for testing (https://sqlite.org/inmemorydb.html)
      Botan::Certificate_Store_In_SQLite store(":memory:", passwd, *rng);

      for(const auto& a : certsandkeys) {
         store.insert_cert(a.certificate());
      }

      const auto subjects = store.all_subjects();

      result.test_eq("Check subject list length", subjects.size(), 6);

      for(const auto& sub : subjects) {
         const std::string ss = sub.to_string();

         result.test_eq("Check subject " + ss,
                        certsandkeys[0].subject_dn() == sub || certsandkeys[1].subject_dn() == sub ||
                           certsandkeys[2].subject_dn() == sub || certsandkeys[3].subject_dn() == sub ||
                           certsandkeys[4].subject_dn() == sub || certsandkeys[5].subject_dn() == sub,
                        true);
      }
      return result;
   } catch(std::exception& e) {
      result.test_failure(e.what());
      return result;
   }
}

Test::Result test_certstor_sqlite3_find_all_certs_test(const std::vector<CertificateAndKey>& certsandkeys) {
   Test::Result result("Certificate Store SQLITE3 - Find all certs");
   try {
      auto rng = Test::new_rng(__func__);
      const std::string passwd(reinterpret_cast<const char*>(rng->random_vec(8).data()), 8);
      // Just create a database in memory for testing (https://sqlite.org/inmemorydb.html)
      Botan::Certificate_Store_In_SQLite store(":memory:", passwd, *rng);

      for(const auto& a : certsandkeys) {
         store.insert_cert(a.certificate());
      }

      for(const auto& a : certsandkeys) {
         auto res_vec = store.find_all_certs(a.subject_dn(), a.certificate().subject_key_id());
         if(res_vec.size() != 1) {
            result.test_failure("SQLITE all lookup error");
            return result;
         } else {
            const std::string a_str = a.subject_dn().to_string();
            const std::string res_str = res_vec.at(0).subject_dn().to_string();
            result.test_eq("Check subject " + a_str, a_str, res_str);
         }
      }

      Botan::X509_Certificate same_dn_1 =
         Botan::X509_Certificate(Test::data_file("x509/bsi/common_14/common_14_sub_ca.ca.pem.crt"));
      Botan::X509_Certificate same_dn_2 =
         Botan::X509_Certificate(Test::data_file("x509/bsi/common_14/common_14_wrong_sub_ca.ca.pem.crt"));

      store.insert_cert(same_dn_1);
      store.insert_cert(same_dn_2);
      auto res_vec = store.find_all_certs(same_dn_1.subject_dn(), {});

      if(res_vec.size() != 2) {
         result.test_failure("SQLITE all lookup error (duplicate) " + std::to_string(res_vec.size()));
         return result;
      } else {
         const std::string cert_dn = same_dn_1.subject_dn().to_string();
         const std::string res0_dn = res_vec.at(0).subject_dn().to_string();

         result.test_eq("Check subject " + cert_dn, cert_dn, res0_dn);

         const std::string res1_dn = res_vec.at(1).subject_dn().to_string();
         result.test_eq("Check subject " + cert_dn, cert_dn, res1_dn);
      }
   } catch(const std::exception& e) {
      result.test_failure(e.what());
      return result;
   }
   return result;
}

   #endif

Test::Result test_certstor_find_hash_subject(const std::vector<CertificateAndKey>& certsandkeys) {
   Test::Result result("Certificate Store - Find by subject hash");

   try {
      Botan::Certificate_Store_In_Memory store;

      for(const auto& a : certsandkeys) {
         store.add_certificate(a.certificate());
      }

      for(const auto& certandkey : certsandkeys) {
         const auto& cert = certandkey.certificate();
         const auto hash = cert.raw_subject_dn_sha256();

         const auto found = store.find_cert_by_raw_subject_dn_sha256(hash);
         if(!found) {
            result.test_failure("Can't retrieve certificate " + cert.fingerprint("SHA-1"));
            return result;
         }

         result.test_eq("Got wrong certificate", hash, found->raw_subject_dn_sha256());
      }

      const auto found = store.find_cert_by_raw_subject_dn_sha256(std::vector<uint8_t>(32, 0));
      if(found) {
         result.test_failure("Certificate found for dummy hash");
         return result;
      }

      return result;
   } catch(std::exception& e) {
      result.test_failure(e.what());
      return result;
   }
}

Test::Result test_certstor_load_allcert() {
   Test::Result result("Certificate Store - Load every cert of every files");
   // test_dir_bundled dir should contain only one file with 2 certificates
   // concatenated (ValidCert and root)
   const std::string test_dir_bundled = Test::data_dir() + "/x509/misc/bundledcertdir";

   try {
      result.test_note("load certs from dir: " + test_dir_bundled);
      // Certificate_Store_In_Memory constructor loads every cert of every files of the dir.
      Botan::Certificate_Store_In_Memory store(test_dir_bundled);

      // X509_Certificate constructor loads only the first certificate found in the file.
      Botan::X509_Certificate root_cert(Test::data_dir() + "/x509/x509test/root.pem");
      Botan::X509_Certificate valid_cert(Test::data_dir() + "/x509/x509test/ValidCert.pem");
      std::vector<uint8_t> key_id;
      result.confirm("Root cert found", store.find_cert(root_cert.subject_dn(), key_id) != std::nullopt);
      result.confirm("ValidCert found", store.find_cert(valid_cert.subject_dn(), key_id) != std::nullopt);
      return result;
   } catch(std::exception& e) {
      result.test_failure(e.what());
      return result;
   }
}

class Certstor_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         if(Botan::has_filesystem_impl() == false) {
            return {Test::Result::Note("Certificate Store", "Skipping due to missing filesystem access")};
         }

         const std::string test_dir = Test::data_dir() + "/x509/certstor";

         struct CertificateAndKeyFilenames {
               const std::string certificate;
               const std::string private_key;
         } const certsandkeys_filenames[]{
            {"cert1.crt", "key01.pem"},
            {"cert2.crt", "key01.pem"},
            {"cert3.crt", "key03.pem"},
            {"cert4.crt", "key04.pem"},
            {"cert5a.crt", "key05.pem"},
            {"cert5b.crt", "key06.pem"},
         };

         const std::vector<std::string> all_files = Botan::get_files_recursive(test_dir);

         if(all_files.empty()) {
            Test::Result result("Certificate Store");
            result.test_failure("No test files found in " + test_dir);
            return {result};
         }

         std::vector<CertificateAndKey> certsandkeys;

         for(const auto& certandkey_filenames : certsandkeys_filenames) {
            const Botan::X509_Certificate certificate(test_dir + "/" + certandkey_filenames.certificate);

            Botan::DataSource_Stream key_stream(test_dir + "/" + certandkey_filenames.private_key);
            std::shared_ptr<Botan::Private_Key> private_key = Botan::PKCS8::load_key(key_stream);

            if(!private_key) {
               Test::Result result("Certificate Store");
               result.test_failure("Failed to load key from disk at path: " + test_dir + "/" +
                                   certandkey_filenames.private_key);
               return {result};
            }

            certsandkeys.push_back(CertificateAndKey(certificate, private_key));
         }

         std::vector<Test::Result> results;

         results.push_back(test_certstor_find_hash_subject(certsandkeys));
         results.push_back(test_certstor_load_allcert());
   #if defined(BOTAN_HAS_CERTSTOR_SQLITE3)
         results.push_back(test_certstor_sqlite3_insert_find_remove_test(certsandkeys));
         results.push_back(test_certstor_sqlite3_crl_test(certsandkeys));
         results.push_back(test_certstor_sqlite3_all_subjects_test(certsandkeys));
         results.push_back(test_certstor_sqlite3_find_all_certs_test(certsandkeys));
   #endif
         return results;
      }
};

BOTAN_REGISTER_TEST("x509", "certstor", Certstor_Tests);
#endif
}  // namespace
}  // namespace Botan_Tests
