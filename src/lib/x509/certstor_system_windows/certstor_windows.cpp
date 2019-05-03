/*
* Certificate Store
* (C) 1999-2019 Jack Lloyd
* (C) 2018-2019 Patrik Fiedler, Tim Oesterreich
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/certstor_windows.h>
#include <botan/der_enc.h>

#include <array>
#include <vector>

#define NOMINMAX 1
#define _WINSOCKAPI_ // stop windows.h including winsock.h
#include <Windows.h>
#include <Wincrypt.h>

namespace Botan {
namespace {

const std::array<const char*, 2> cert_store_names{"Root", "CA"};

HCERTSTORE openCertStore(const char* cert_store_name)
   {
   auto store = CertOpenSystemStore(NULL, cert_store_name);
   if(!store)
      {
      throw Botan::Internal_Error(
         "failed to open windows certificate store '" + std::string(cert_store_name) +
         "' (Error Code: " +
         std::to_string(::GetLastError()) + ")");
      }
   return store;
   }

bool already_contains_certificate(
   const std::vector<std::shared_ptr<const Botan::X509_Certificate>>& certs, std::shared_ptr<Botan::X509_Certificate> cert)
   {
   return std::any_of(certs.begin(), certs.end(),
                      [&](std::shared_ptr<const Botan::X509_Certificate> c)
      {
      return *c == *cert;
      });
   }

/**
 * Abstract RAII wrapper for PCCERT_CONTEXT and HCERTSTORE
 * The Windows API partly takes care of those pointers destructions itself.
 * Especially, iteratively calling `CertFindCertificateInStore` with the previous PCCERT_CONTEXT
 * will free the context and return a new one. In this case, this guard takes care of freeing the context
 * in case of an exception and at the end of the iterative process.
 */
template<class T>
class Handle_Guard
   {
   public:
      Handle_Guard(T context)
         : m_context(context)
         {
         }

      Handle_Guard(const Handle_Guard<T>& rhs) = delete;
      Handle_Guard(Handle_Guard<T>&& rhs) :
         m_context(std::move(rhs.m_context))
         {
         rhs.m_context = nullptr;
         }

      ~Handle_Guard()
         {
         close<T>();
         }

      operator bool() const
         {
         return m_context != nullptr;
         }

      bool assign(T context)
         {
         m_context = context;
         return m_context != nullptr;
         }

      T& get()
         {
         return m_context;
         }

      const T& get() const
         {
         return m_context;
         }

      T operator->()
         {
         return m_context;
         }

   private:
      template<class T>
      void close()
         {
         static_assert(false, "Handle_Guard is not available for this type");
         }

      template<>
      void close<PCCERT_CONTEXT> ()
         {
         if(m_context)
            {
            CertFreeCertificateContext(m_context);
            }
         }

      template<>
      void close<HCERTSTORE> ()
         {
         if(m_context)
            {
            CertCloseStore(m_context, 0);
            }
         }

      T m_context;
   };
}

Certificate_Store_Windows::Certificate_Store_Windows() {}

std::vector<X509_DN> Certificate_Store_Windows::all_subjects() const
   {
   std::vector<X509_DN> subject_dns;
   for(auto& store_name : cert_store_names)
      {
      Handle_Guard<HCERTSTORE> windows_cert_store = openCertStore(store_name);
      Handle_Guard<PCCERT_CONTEXT> cert_context = nullptr;

      // Handle_Guard::assign exchanges the underlying pointer. No RAII is needed here, because the Windows API takes care of
      // freeing the previous context.
      while(cert_context.assign(CertEnumCertificatesInStore(windows_cert_store.get(), cert_context.get())))
         {
         X509_Certificate cert(cert_context->pbCertEncoded, cert_context->cbCertEncoded);
         subject_dns.push_back(cert.subject_dn());
         }
      }

   return subject_dns;
   }

std::shared_ptr<const X509_Certificate>
Certificate_Store_Windows::find_cert(const Botan::X509_DN&           subject_dn,
                                     const std::vector<uint8_t>& key_id) const
   {
   const auto certs = find_all_certs(subject_dn, key_id);
   return certs.empty() ? nullptr : certs.front();
   }

std::vector<std::shared_ptr<const X509_Certificate>> Certificate_Store_Windows::find_all_certs(
         const X509_DN& subject_dn,
         const std::vector<uint8_t>& key_id) const
   {
   std::vector<uint8_t> dn_data;
   DER_Encoder encoder(dn_data);
   subject_dn.encode_into(encoder);

   CERT_NAME_BLOB blob;
   blob.cbData = static_cast<DWORD>(dn_data.size());
   blob.pbData = reinterpret_cast<BYTE*>(dn_data.data());

   std::vector<std::shared_ptr<const X509_Certificate>> certs;
   for(auto& store_name : cert_store_names)
      {
      Handle_Guard<HCERTSTORE> windows_cert_store = openCertStore(store_name);
      Handle_Guard<PCCERT_CONTEXT> cert_context = nullptr;
      while(cert_context.assign(CertFindCertificateInStore(
                                   windows_cert_store.get(), PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                                   NULL, CERT_FIND_SUBJECT_NAME,
                                   &blob, cert_context.get())))
         {
         auto cert = std::make_shared<X509_Certificate>(cert_context->pbCertEncoded, cert_context->cbCertEncoded);
         if(!already_contains_certificate(certs, cert) && (key_id.empty() || cert->subject_key_id() == key_id))
            {
            certs.push_back(cert);
            }
         }
      }
   return certs;
   }

std::shared_ptr<const Botan::X509_Certificate>
Certificate_Store_Windows::find_cert_by_pubkey_sha1(
   const std::vector<uint8_t>& key_hash) const
   {
   if(key_hash.size() != 20)
      {
      throw Invalid_Argument("Certificate_Store_Windows::find_cert_by_pubkey_sha1 invalid hash");
      }

   CRYPT_HASH_BLOB blob;
   blob.cbData = static_cast<DWORD>(key_hash.size());
   blob.pbData = const_cast<BYTE*>(key_hash.data());

   for(auto& store_name : cert_store_names)
      {
      Handle_Guard<HCERTSTORE> windows_cert_store = openCertStore(store_name);
      Handle_Guard<PCCERT_CONTEXT> cert_context = CertFindCertificateInStore(
               windows_cert_store.get(), PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
               0, CERT_FIND_KEY_IDENTIFIER,
               &blob, nullptr);

      if(cert_context)
         {
         return std::make_shared<X509_Certificate>(cert_context->pbCertEncoded, cert_context->cbCertEncoded);
         }
      }

   return nullptr;
   }

std::shared_ptr<const X509_Certificate>
Certificate_Store_Windows::find_cert_by_raw_subject_dn_sha256(const std::vector<uint8_t>& subject_hash) const
   {
   BOTAN_UNUSED(subject_hash);
   throw Not_Implemented("Certificate_Store_Windows::find_cert_by_raw_subject_dn_sha256");
   }

std::shared_ptr<const X509_CRL> Certificate_Store_Windows::find_crl_for(const X509_Certificate& subject) const
   {
   BOTAN_UNUSED(subject);
   return {};
   }
}
