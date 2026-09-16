/*
* (C) 2026 Moritz Schmitt
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi_tls.h>

#include <botan/assert.h>
#include <botan/certstor.h>
#include <botan/pkcs8.h>
#include <botan/system_rng.h>
#include <botan/tls_policy.h>
#include <botan/tls_session_manager_memory.h>
#include <botan/tls_session_manager_noop.h>
#include <botan/x509_crl.h>
#include <botan/x509cert.h>
#include <botan/internal/ffi_cert.h>
#include <botan/internal/ffi_pkey.h>
#include <botan/internal/ffi_rng.h>
#include <botan/internal/ffi_tls_impl.h>
#include <botan/internal/ffi_util.h>
#include <algorithm>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if defined(BOTAN_HAS_CERTSTOR_SYSTEM)
   #include <botan/certstor_system.h>
#endif

namespace Botan_FFI {

void FFI_TLS_Credentials::add_trusted_cert(const Botan::X509_Certificate& cert) {
   m_trusted.add_certificate(cert);
}

void FFI_TLS_Credentials::add_crl(const Botan::X509_CRL& crl) {
   m_trusted.add_crl(crl);
}

void FFI_TLS_Credentials::add_store(std::shared_ptr<Botan::Certificate_Store> store) {
   m_extra_stores.push_back(std::move(store));
}

void FFI_TLS_Credentials::add_cert_chain(std::vector<Botan::X509_Certificate> chain,
                                         std::shared_ptr<Botan::Private_Key> key) {
   BOTAN_ARG_CHECK(!chain.empty(), "Certificate chain must not be empty");
   BOTAN_ARG_CHECK(key != nullptr, "Private key must not be null");
   m_chains.push_back(Chain{std::move(chain), std::move(key)});
}

std::vector<Botan::Certificate_Store*> FFI_TLS_Credentials::trusted_certificate_authorities(
   const std::string& /*type*/, const std::string& /*context*/) {
   std::vector<Botan::Certificate_Store*> stores;
   stores.push_back(&m_trusted);
   for(const auto& store : m_extra_stores) {
      stores.push_back(store.get());
   }
   return stores;
}

std::vector<Botan::X509_Certificate> FFI_TLS_Credentials::find_cert_chain(
   const std::vector<std::string>& cert_key_types,
   const std::vector<Botan::AlgorithmIdentifier>& /*cert_signature_schemes*/,
   const std::vector<Botan::X509_DN>& acceptable_CAs,
   const std::string& type,
   const std::string& context) {
   // A chain is usable if the peer accepts the type of its key. On a server,
   // if any chain (of whatever key type) has a leaf certificate matching the
   // server name the client asked for, only such chains are offered; the
   // TLS 1.2 server asks once per key type, so a chain for another name must
   // not be offered under a different key type when a matching one exists.
   // Among the usable chains the first one issued by a certificate authority
   // the peer named wins, otherwise the first usable chain is used, since the
   // peer may still accept it.
   const bool restrict_to_hostname = type == "tls-server" && !context.empty() &&
                                     std::any_of(m_chains.begin(), m_chains.end(), [&](const Chain& chain) {
                                        return chain.certs.front().matches_dns_name(context);
                                     });

   const Chain* first_usable = nullptr;

   for(const auto& chain : m_chains) {
      if(!cert_key_types.empty() &&
         std::find(cert_key_types.begin(), cert_key_types.end(), chain.key->algo_name()) == cert_key_types.end()) {
         continue;
      }

      if(restrict_to_hostname && !chain.certs.front().matches_dns_name(context)) {
         continue;
      }

      bool preferred = true;

      if(!acceptable_CAs.empty()) {
         preferred = std::any_of(chain.certs.begin(), chain.certs.end(), [&](const Botan::X509_Certificate& cert) {
            return std::find(acceptable_CAs.begin(), acceptable_CAs.end(), cert.issuer_dn()) != acceptable_CAs.end();
         });
      }

      if(preferred) {
         return chain.certs;
      }

      if(first_usable == nullptr) {
         first_usable = &chain;
      }
   }

   if(first_usable != nullptr) {
      return first_usable->certs;
   }

   return {};
}

std::shared_ptr<Botan::Private_Key> FFI_TLS_Credentials::private_key_for(const Botan::X509_Certificate& cert,
                                                                         const std::string& /*type*/,
                                                                         const std::string& /*context*/) {
   for(const auto& chain : m_chains) {
      if(chain.certs.front() == cert) {
         return chain.key;
      }
   }
   return nullptr;
}

}  // namespace Botan_FFI

extern "C" {

using namespace Botan_FFI;

/*
* Policies
*/

int botan_tls_policy_init(botan_tls_policy_t* policy, const char* name) {
   if(any_null_pointers(policy)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   *policy = nullptr;

   return ffi_guard_thunk(__func__, [=]() -> int {
      const std::string policy_name(name != nullptr ? name : "default");

      if(policy_name == "default") {
         return ffi_new_object(policy, std::make_shared<Botan::TLS::Policy>());
      } else if(policy_name == "strict") {
         return ffi_new_object(policy, std::make_shared<Botan::TLS::Strict_Policy>());
      } else if(policy_name == "bsi_tr_02102_2") {
         return ffi_new_object(policy, std::make_shared<Botan::TLS::BSI_TR_02102_2>());
      }

      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   });
}

int botan_tls_policy_init_from_text(botan_tls_policy_t* policy, const char* text) {
   if(any_null_pointers(policy, text)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   *policy = nullptr;

   return ffi_guard_thunk(__func__, [=]() -> int {
      return ffi_new_object(policy, std::make_shared<Botan::TLS::Text_Policy>(std::string_view(text)));
   });
}

int botan_tls_policy_view_text(botan_tls_policy_t policy, botan_view_ctx ctx, botan_view_str_fn view) {
   return BOTAN_FFI_VISIT(policy, [=](const auto& p) { return invoke_view_callback(view, ctx, p->to_string()); });
}

int botan_tls_policy_destroy(botan_tls_policy_t policy) {
   return BOTAN_FFI_CHECKED_DELETE(policy);
}

/*
* Credentials
*/

int botan_tls_credentials_init(botan_tls_credentials_t* creds) {
   if(any_null_pointers(creds)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   *creds = nullptr;

   return ffi_guard_thunk(__func__,
                          [=]() -> int { return ffi_new_object(creds, std::make_shared<FFI_TLS_Credentials>()); });
}

int botan_tls_credentials_add_trusted_cert(botan_tls_credentials_t creds, botan_x509_cert_t cert) {
   return BOTAN_FFI_VISIT(creds, [=](const auto& c) { c->add_trusted_cert(safe_get(cert)); });
}

int botan_tls_credentials_add_crl(botan_tls_credentials_t creds, botan_x509_crl_t crl) {
   return BOTAN_FFI_VISIT(creds, [=](const auto& c) { c->add_crl(safe_get(crl)); });
}

int botan_tls_credentials_add_trusted_dir(botan_tls_credentials_t creds, const char* path) {
   if(any_null_pointers(creds, path)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
   return BOTAN_FFI_VISIT(creds, [=](const auto& c) -> int {
      // The directory constructor silently yields an empty store for a
      // missing or unreadable directory, which would make every verification
      // fail without any hint why; report that as an error instead.
      auto store = std::make_shared<Botan::Certificate_Store_In_Memory>(std::string_view(path));
      if(store->all_subjects().empty()) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
      c->add_store(std::move(store));
      return BOTAN_FFI_SUCCESS;
   });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_tls_credentials_use_system_store(botan_tls_credentials_t creds) {
   if(any_null_pointers(creds)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_CERTSTOR_SYSTEM)
   return BOTAN_FFI_VISIT(creds,
                          [](const auto& c) { c->add_store(std::make_shared<Botan::System_Certificate_Store>()); });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_tls_credentials_add_cert_chain(botan_tls_credentials_t creds,
                                         const botan_x509_cert_t* chain,
                                         size_t chain_len,
                                         botan_privkey_t key) {
   if(any_null_pointers(creds, chain, key)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   if(chain_len == 0) {
      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   }

   return BOTAN_FFI_VISIT(creds, [=](const auto& c) -> int {
      std::vector<Botan::X509_Certificate> certs;
      certs.reserve(chain_len);
      for(size_t i = 0; i != chain_len; ++i) {
         certs.push_back(safe_get(chain[i]));
      }

      // Copy the key by re-encoding it, so that the caller's handle need not
      // outlive the credentials. private_key_info() is the PKCS #8
      // PrivateKeyInfo, which load_key() decodes back into a key object.
      const auto pkcs8 = safe_get(key).private_key_info();
      std::shared_ptr<Botan::Private_Key> key_copy = Botan::PKCS8::load_key(pkcs8);

      if(key_copy->public_key()->fingerprint_public() != certs.front().subject_public_key()->fingerprint_public()) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }

      c->add_cert_chain(std::move(certs), std::move(key_copy));
      return BOTAN_FFI_SUCCESS;
   });
}

int botan_tls_credentials_destroy(botan_tls_credentials_t creds) {
   return BOTAN_FFI_CHECKED_DELETE(creds);
}

/*
* Session managers
*/

int botan_tls_session_manager_init_memory(botan_tls_session_manager_t* mgr, botan_rng_t rng, size_t max_sessions) {
   if(any_null_pointers(mgr)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   *mgr = nullptr;

   return ffi_guard_thunk(__func__, [=]() -> int {
      std::shared_ptr<Botan::RandomNumberGenerator> rng_ptr;

      if(rng != nullptr) {
         // The RNG is borrowed: the caller keeps it alive for as long as the
         // session manager exists, as documented in ffi_tls.h (the same
         // arrangement as in botan_tpm2_ctx_enable_crypto_backend).
         rng_ptr = std::shared_ptr<Botan::RandomNumberGenerator>(&safe_get(rng), [](auto*) {});
      } else {
         rng_ptr = std::make_shared<Botan::System_RNG>();
      }

      return ffi_new_object(mgr, std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng_ptr, max_sessions));
   });
}

int botan_tls_session_manager_init_noop(botan_tls_session_manager_t* mgr) {
   if(any_null_pointers(mgr)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   *mgr = nullptr;

   return ffi_guard_thunk(
      __func__, [=]() -> int { return ffi_new_object(mgr, std::make_shared<Botan::TLS::Session_Manager_Noop>()); });
}

int botan_tls_session_manager_destroy(botan_tls_session_manager_t mgr) {
   return BOTAN_FFI_CHECKED_DELETE(mgr);
}

}  // extern "C"
