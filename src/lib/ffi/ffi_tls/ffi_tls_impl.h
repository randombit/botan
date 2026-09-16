/*
* (C) 2026 Moritz Schmitt
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FFI_TLS_IMPL_H_
#define BOTAN_FFI_TLS_IMPL_H_

#include <botan/ffi_tls.h>

#include <botan/certstor.h>
#include <botan/credentials_manager.h>
#include <botan/pk_keys.h>
#include <botan/tls_policy.h>
#include <botan/tls_session_manager.h>
#include <botan/x509cert.h>
#include <botan/internal/ffi_util.h>
#include <memory>
#include <string>
#include <vector>

namespace Botan_FFI {

/**
* The Credentials_Manager behind botan_tls_credentials_t.
*
* Trust anchors and CRLs live in an in-memory certificate store; further
* stores (a directory, the system store) are kept as separate objects. The
* certificate chains are used for server and for client authentication
* alike. All setters copy their input; the object is configured once and
* then only read, so it can be shared between channels.
*/
class BOTAN_TEST_API FFI_TLS_Credentials final : public Botan::Credentials_Manager {
   public:
      void add_trusted_cert(const Botan::X509_Certificate& cert);

      void add_crl(const Botan::X509_CRL& crl);

      void add_store(std::shared_ptr<Botan::Certificate_Store> store);

      /// @p chain is leaf first and not empty; @p key belongs to the leaf
      void add_cert_chain(std::vector<Botan::X509_Certificate> chain, std::shared_ptr<Botan::Private_Key> key);

      std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(const std::string& type,
                                                                             const std::string& context) override;

      std::vector<Botan::X509_Certificate> find_cert_chain(
         const std::vector<std::string>& cert_key_types,
         const std::vector<Botan::AlgorithmIdentifier>& cert_signature_schemes,
         const std::vector<Botan::X509_DN>& acceptable_CAs,
         const std::string& type,
         const std::string& context) override;

      using Botan::Credentials_Manager::private_key_for;

      std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::X509_Certificate& cert,
                                                          const std::string& type,
                                                          const std::string& context) override;

   private:
      struct Chain {
            std::vector<Botan::X509_Certificate> certs;
            std::shared_ptr<Botan::Private_Key> key;
      };

      Botan::Certificate_Store_In_Memory m_trusted;
      std::vector<std::shared_ptr<Botan::Certificate_Store>> m_extra_stores;
      std::vector<Chain> m_chains;
};

}  // namespace Botan_FFI

extern "C" {

// TLS::Client and TLS::Server take their collaborators as std::shared_ptr,
// so the handles hold one.
BOTAN_FFI_DECLARE_SHARED_STRUCT(botan_tls_policy_struct, const Botan::TLS::Policy, 0x19781017);
BOTAN_FFI_DECLARE_SHARED_STRUCT(botan_tls_credentials_struct, Botan_FFI::FFI_TLS_Credentials, 0x5C3A9E41);
BOTAN_FFI_DECLARE_SHARED_STRUCT(botan_tls_session_manager_struct, Botan::TLS::Session_Manager, 0xB7D2E60C);

}  // extern "C"

#endif
