/*
* Certificate Store
* (C) 1999-2021 Jack Lloyd
* (C) 2018-2019 Patrik Fiedler, Tim Oesterreich
* (C) 2021      René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/certstor_windows.h>

#include <botan/ber_dec.h>
#include <botan/hash.h>
#include <botan/pkix_types.h>
#include <array>
#include <functional>
#include <vector>

#define NOMINMAX 1
#define _WINSOCKAPI_  // stop windows.h including winsock.h
#include <windows.h>

#include <wincrypt.h>

#define WINCRYPT_UNUSED_PARAM \
   0  // for avoiding warnings when passing NULL to unused params in win32 api that accept integer types

namespace Botan {
namespace {

const std::array<const char*, 2> cert_store_names{"Root", "CA"};

/**
 * Abstract RAII wrapper for PCCERT_CONTEXT and HCERTSTORE
 * The Windows API partly takes care of those pointers destructions itself.
 * Especially, iteratively calling `CertFindCertificateInStore` with the previous PCCERT_CONTEXT
 * will free the context and return a new one. In this case, this guard takes care of freeing the context
 * in case of an exception and at the end of the iterative process.
 */
template <class T>
class Handle_Guard {
   public:
      Handle_Guard(T context) : m_context(context) {}

      Handle_Guard(const Handle_Guard<T>& rhs) = delete;

      Handle_Guard(Handle_Guard<T>&& rhs) : m_context(std::move(rhs.m_context)) { rhs.m_context = nullptr; }

      ~Handle_Guard() { close<T>(); }

      operator bool() const { return m_context != nullptr; }

      bool assign(T context) {
         m_context = context;
         return m_context != nullptr;
      }

      T& get() { return m_context; }

      const T& get() const { return m_context; }

      T operator->() { return m_context; }

   private:
      template <class T2 = T>
      typename std::enable_if<std::is_same<T2, PCCERT_CONTEXT>::value>::type close() {
         if(m_context) {
            CertFreeCertificateContext(m_context);
         }
      }

      template <class T2 = T>
      typename std::enable_if<std::is_same<T2, HCERTSTORE>::value>::type close() {
         if(m_context) {
            // second parameter is a flag that tells the store how to deallocate memory
            // using the default "0", this function works like decreasing the reference counter
            // in a shared_ptr
            CertCloseStore(m_context, 0);
         }
      }

      T m_context;
};

HCERTSTORE open_cert_store(const char* cert_store_name) {
   auto store = CertOpenSystemStoreA(WINCRYPT_UNUSED_PARAM, cert_store_name);
   if(!store) {
      throw Internal_Error("failed to open windows certificate store '" + std::string(cert_store_name) +
                           "' (Error Code: " + std::to_string(::GetLastError()) + ")");
   }
   return store;
}

std::vector<X509_Certificate> search_cert_stores(
   const _CRYPTOAPI_BLOB& blob,
   const DWORD& find_type,
   std::function<bool(const std::vector<X509_Certificate>& certs, const X509_Certificate& cert)> filter,
   bool return_on_first_found) {
   std::vector<X509_Certificate> certs;
   for(const auto store_name : cert_store_names) {
      Handle_Guard<HCERTSTORE> windows_cert_store = open_cert_store(store_name);
      Handle_Guard<PCCERT_CONTEXT> cert_context = nullptr;
      while(cert_context.assign(CertFindCertificateInStore(windows_cert_store.get(),
                                                           PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                                                           WINCRYPT_UNUSED_PARAM,
                                                           find_type,
                                                           &blob,
                                                           cert_context.get()))) {
         X509_Certificate cert(cert_context->pbCertEncoded, cert_context->cbCertEncoded);
         if(filter(certs, cert)) {
            if(return_on_first_found) {
               return {cert};
            }
            certs.push_back(cert);
         }
      }
   }

   return certs;
}

bool already_contains_certificate(const std::vector<X509_Certificate>& certs, X509_Certificate cert) {
   return std::any_of(certs.begin(), certs.end(), [&](const X509_Certificate& c) { return c == cert; });
}

std::vector<X509_Certificate> find_cert_by_dn_and_key_id(const X509_DN& subject_dn,
                                                         const std::vector<uint8_t>& key_id,
                                                         bool return_on_first_found) {
   _CRYPTOAPI_BLOB blob;
   DWORD find_type;
   std::vector<uint8_t> dn_data;  // has to live until search completes

   // if key_id is available, prefer searching that, as it should be "more unique" than the subject DN
   if(key_id.empty()) {
      find_type = CERT_FIND_SUBJECT_NAME;
      dn_data = subject_dn.DER_encode();
      blob.cbData = static_cast<DWORD>(dn_data.size());
      blob.pbData = reinterpret_cast<BYTE*>(dn_data.data());
   } else {
      find_type = CERT_FIND_KEY_IDENTIFIER;
      blob.cbData = static_cast<DWORD>(key_id.size());
      blob.pbData = const_cast<BYTE*>(key_id.data());
   }

   auto filter = [&](const std::vector<X509_Certificate>& certs, const X509_Certificate& cert) {
      return !already_contains_certificate(certs, cert) && (key_id.empty() || cert.subject_dn() == subject_dn);
   };

   return search_cert_stores(blob, find_type, filter, return_on_first_found);
}

}  // namespace

Certificate_Store_Windows::Certificate_Store_Windows() {}

std::vector<X509_DN> Certificate_Store_Windows::all_subjects() const {
   std::vector<X509_DN> subject_dns;
   for(const auto store_name : cert_store_names) {
      Handle_Guard<HCERTSTORE> windows_cert_store = open_cert_store(store_name);
      Handle_Guard<PCCERT_CONTEXT> cert_context = nullptr;

      // Handle_Guard::assign exchanges the underlying pointer. No RAII is needed here, because the Windows API takes care of
      // freeing the previous context.
      while(cert_context.assign(CertEnumCertificatesInStore(windows_cert_store.get(), cert_context.get()))) {
         BER_Decoder dec(cert_context->pCertInfo->Subject.pbData, cert_context->pCertInfo->Subject.cbData);

         X509_DN dn;
         dn.decode_from(dec);
         subject_dns.emplace_back(std::move(dn));
      }
   }

   return subject_dns;
}

std::optional<X509_Certificate> Certificate_Store_Windows::find_cert(const X509_DN& subject_dn,
                                                                     const std::vector<uint8_t>& key_id) const {
   const auto certs = find_cert_by_dn_and_key_id(subject_dn, key_id, true);
   if(certs.empty())
      return std::nullopt;
   else
      return certs.front();
}

std::vector<X509_Certificate> Certificate_Store_Windows::find_all_certs(const X509_DN& subject_dn,
                                                                        const std::vector<uint8_t>& key_id) const {
   return find_cert_by_dn_and_key_id(subject_dn, key_id, false);
}

std::optional<X509_Certificate> Certificate_Store_Windows::find_cert_by_pubkey_sha1(
   const std::vector<uint8_t>& key_hash) const {
   if(key_hash.size() != 20) {
      throw Invalid_Argument("Certificate_Store_Windows::find_cert_by_pubkey_sha1 invalid hash");
   }

   CRYPT_HASH_BLOB blob;
   blob.cbData = static_cast<DWORD>(key_hash.size());
   blob.pbData = const_cast<BYTE*>(key_hash.data());

   auto filter = [&](const std::vector<X509_Certificate>&, const X509_Certificate&) { return true; };

   // This assumes that the to-be-found certificate adheres to RFC 3280 (Section 4.2.1.2), because
   // the windows API does not allow to search for the SHA-1 of the certificate's public key directly.
   // Most certificates adhere to the above mentioned convention...
   const auto certs = search_cert_stores(blob, CERT_FIND_KEY_IDENTIFIER, filter, true);
   if(!certs.empty())
      return certs.front();

   // ... for certificates that don't adhere to RFC 3280 (Section 4.2.1.2), we will need to use a
   // fallback implementation that does an exhaustive search of all available certificates.
   return find_cert_by_pubkey_sha1_via_exhaustive_search(key_hash);
}

std::optional<X509_Certificate> Certificate_Store_Windows::find_cert_by_raw_subject_dn_sha256(
   const std::vector<uint8_t>& subject_hash) const {
   BOTAN_UNUSED(subject_hash);
   throw Not_Implemented("Certificate_Store_Windows::find_cert_by_raw_subject_dn_sha256");
}

std::optional<X509_CRL> Certificate_Store_Windows::find_crl_for(const X509_Certificate& subject) const {
   // TODO: this could be implemented by using the CertFindCRLInStore function
   BOTAN_UNUSED(subject);
   return std::nullopt;
}

std::optional<X509_Certificate> Certificate_Store_Windows::find_cert_by_pubkey_sha1_via_exhaustive_search(
   const std::vector<uint8_t>& key_hash) const {
   if(const auto cache_hit = m_non_rfc3289_certs.find(key_hash); cache_hit != m_non_rfc3289_certs.end()) {
      return cache_hit->second;
   }

   auto sha1 = HashFunction::create_or_throw("SHA-1");
   for(const auto store_name : cert_store_names) {
      Handle_Guard<HCERTSTORE> windows_cert_store = open_cert_store(store_name);
      Handle_Guard<PCCERT_CONTEXT> cert_context = nullptr;

      // Handle_Guard::assign exchanges the underlying pointer. No RAII is needed here, because the Windows API takes care of
      // freeing the previous context.
      while(cert_context.assign(CertEnumCertificatesInStore(windows_cert_store.get(), cert_context.get()))) {
         const auto pubkey_blob = cert_context->pCertInfo->SubjectPublicKeyInfo.PublicKey;
         const auto key_hash_candidate = sha1->process(static_cast<uint8_t*>(pubkey_blob.pbData), pubkey_blob.cbData);

         if(std::equal(key_hash.begin(), key_hash.end(), key_hash_candidate.begin())) {
            X509_Certificate result(cert_context->pbCertEncoded, cert_context->cbCertEncoded);
            m_non_rfc3289_certs[key_hash] = result;
            return result;
         }
      }
   }

   // insert a negative query result into the cache
   m_non_rfc3289_certs[key_hash] = std::nullopt;
   return std::nullopt;
}

}  // namespace Botan
