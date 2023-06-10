/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/certstor_system.h>

#include <botan/pkix_types.h>
#include <botan/x509cert.h>

#if defined(BOTAN_HAS_CERTSTOR_MACOS)
   #include <botan/certstor_macos.h>
#elif defined(BOTAN_HAS_CERTSTOR_WINDOWS)
   #include <botan/certstor_windows.h>
#elif defined(BOTAN_HAS_CERTSTOR_FLATFILE) && defined(BOTAN_SYSTEM_CERT_BUNDLE)
   #include <botan/certstor_flatfile.h>
#endif

namespace Botan {

System_Certificate_Store::System_Certificate_Store() {
#if defined(BOTAN_HAS_CERTSTOR_MACOS)
   m_system_store = std::make_shared<Certificate_Store_MacOS>();
#elif defined(BOTAN_HAS_CERTSTOR_WINDOWS)
   m_system_store = std::make_shared<Certificate_Store_Windows>();
#elif defined(BOTAN_HAS_CERTSTOR_FLATFILE) && defined(BOTAN_SYSTEM_CERT_BUNDLE)
   m_system_store = std::make_shared<Flatfile_Certificate_Store>(BOTAN_SYSTEM_CERT_BUNDLE, true);
#else
   throw Not_Implemented("No system certificate store available in this build");
#endif
}

std::optional<X509_Certificate> System_Certificate_Store::find_cert(const X509_DN& subject_dn,
                                                                    const std::vector<uint8_t>& key_id) const {
   return m_system_store->find_cert(subject_dn, key_id);
}

std::vector<X509_Certificate> System_Certificate_Store::find_all_certs(const X509_DN& subject_dn,
                                                                       const std::vector<uint8_t>& key_id) const {
   return m_system_store->find_all_certs(subject_dn, key_id);
}

std::optional<X509_Certificate> System_Certificate_Store::find_cert_by_pubkey_sha1(
   const std::vector<uint8_t>& key_hash) const {
   return m_system_store->find_cert_by_pubkey_sha1(key_hash);
}

std::optional<X509_Certificate> System_Certificate_Store::find_cert_by_raw_subject_dn_sha256(
   const std::vector<uint8_t>& subject_hash) const {
   return m_system_store->find_cert_by_raw_subject_dn_sha256(subject_hash);
}

std::optional<X509_CRL> System_Certificate_Store::find_crl_for(const X509_Certificate& subject) const {
   return m_system_store->find_crl_for(subject);
}

std::vector<X509_DN> System_Certificate_Store::all_subjects() const {
   return m_system_store->all_subjects();
}

}  // namespace Botan
