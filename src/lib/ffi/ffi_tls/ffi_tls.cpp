/*
* (C) 2026 Moritz Schmitt
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi_tls.h>

#include <botan/assert.h>
#include <botan/certstor.h>
#include <botan/system_rng.h>
#include <botan/tls_alert.h>
#include <botan/tls_ciphersuite.h>
#include <botan/tls_client.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/tls_server.h>
#include <botan/tls_server_info.h>
#include <botan/tls_session_manager_memory.h>
#include <botan/tls_session_manager_noop.h>
#include <botan/tls_version.h>
#include <botan/x509_crl.h>
#include <botan/x509cert.h>
#include <botan/internal/ffi_cert.h>
#include <botan/internal/ffi_pkey.h>
#include <botan/internal/ffi_rng.h>
#include <botan/internal/ffi_tls_impl.h>
#include <botan/internal/ffi_util.h>
#include <botan/internal/stl_util.h>
#include <algorithm>
#include <memory>
#include <optional>
#include <span>
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
   m_chains.push_back({
      .certs = std::move(chain),
      .key = std::move(key),
   });
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
   // peer may still accept it. The names the peer sends may be those of trust
   // anchors as well as of subordinate CAs (RFC 8446 4.2.4); a Botan server for
   // instance sends the subjects of its trust stores. A root's name matches the
   // issuer of the last certificate of a chain, not the issuer of the leaf, so
   // every certificate of the chain is checked.
   const bool restrict_to_hostname = type == "tls-server" && !context.empty() &&
                                     std::any_of(m_chains.begin(), m_chains.end(), [&](const Chain& chain) {
                                        return chain.certs.front().matches_dns_name(context);
                                     });

   std::vector<Botan::X509_Certificate> result;

   for(const auto& chain : m_chains) {
      if(!cert_key_types.empty() && !Botan::value_exists(cert_key_types, chain.key->algo_name())) {
         continue;
      }

      if(restrict_to_hostname && !chain.certs.front().matches_dns_name(context)) {
         continue;
      }

      bool preferred = true;

      if(!acceptable_CAs.empty()) {
         preferred = std::any_of(chain.certs.begin(), chain.certs.end(), [&](const Botan::X509_Certificate& cert) {
            return Botan::value_exists(acceptable_CAs, cert.issuer_dn());
         });
      }

      if(preferred) {
         result = chain.certs;
         break;
      }

      if(result.empty()) {
         result = chain.certs;
      }
   }

   return result;
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

/*
* Alert enumerators are spelled AlertType::X here: GCC 11 crashes on the
* using-enum spelling Alert::X inside templates and generic lambdas.
*/
FFI_TLS_Callbacks::FFI_TLS_Callbacks(const FFI_TLS_Callbacks_Table& table,
                                     void* ctx,
                                     std::vector<std::string> server_protocols) :
      m_table(table), m_ctx(ctx), m_server_protocols(std::move(server_protocols)) {}

void FFI_TLS_Callbacks::tls_emit_data(std::span<const uint8_t> data) {
   if(m_failed) {
      throw Botan::TLS::TLS_Exception(Botan::TLS::AlertType::InternalError, "TLS transport failed earlier");
   }

   m_in_emit = true;
   const int rc = m_table.emit_data(m_ctx, data.data(), data.size());
   m_in_emit = false;

   if(rc != 0) {
      m_failed = true;
      throw Botan::TLS::TLS_Exception(Botan::TLS::AlertType::InternalError,
                                      "TLS emit_data callback failed with rc=" + std::to_string(rc));
   }
}

void FFI_TLS_Callbacks::tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) {
   const int rc = m_table.record_received(m_ctx, seq_no, data.data(), data.size());
   if(rc != 0) {
      throw Botan::TLS::TLS_Exception(Botan::TLS::AlertType::InternalError,
                                      "TLS record_received callback failed with rc=" + std::to_string(rc));
   }
}

void FFI_TLS_Callbacks::tls_alert(Botan::TLS::Alert alert) {
   const auto code = static_cast<uint16_t>(alert.type());
   const int rc = m_table.alert_received(m_ctx, code, alert.is_fatal() ? 1 : 0);
   if(rc != 0) {
      throw Botan::TLS::TLS_Exception(Botan::TLS::AlertType::InternalError,
                                      "TLS alert_received callback failed with rc=" + std::to_string(rc));
   }
}

void FFI_TLS_Callbacks::tls_session_established(const Botan::TLS::Session_Summary& summary) {
   m_summary = summary;
}

void FFI_TLS_Callbacks::tls_session_activated() {
   if(m_table.handshake_complete != nullptr) {
      const int rc = m_table.handshake_complete(m_ctx);
      if(rc != 0) {
         throw Botan::TLS::TLS_Exception(Botan::TLS::AlertType::InternalError,
                                         "TLS handshake_complete callback failed with rc=" + std::to_string(rc));
      }
   }
}

std::string FFI_TLS_Callbacks::tls_server_choose_app_protocol(const std::vector<std::string>& client_protos) {
   if(m_server_protocols.empty() || client_protos.empty()) {
      return "";
   }

   for(const auto& proto : m_server_protocols) {
      if(Botan::value_exists(client_protos, proto)) {
         return proto;
      }
   }

   throw Botan::TLS::TLS_Exception(Botan::TLS::AlertType::NoApplicationProtocol,
                                   "No application protocol in common with the client");
}

}  // namespace Botan_FFI

namespace {

using namespace Botan_FFI;

// NULL selects an internal system RNG
std::shared_ptr<Botan::RandomNumberGenerator> rng_for(botan_rng_t rng) {
   if(rng != nullptr) {
      return safe_get_sp(rng);
   }
   return std::make_shared<Botan::System_RNG>();
}

std::shared_ptr<Botan::TLS::Session_Manager> session_manager_for(botan_tls_session_manager_t sessions) {
   if(sessions != nullptr) {
      return safe_get_sp(sessions);
   }
   return std::make_shared<Botan::TLS::Session_Manager_Noop>();
}

std::vector<std::string> protocol_list(const char* const* protocols, size_t count) {
   std::vector<std::string> list;
   list.reserve(count);
   for(size_t i = 0; i != count; ++i) {
      if(protocols[i] == nullptr) {
         throw FFI_Error("Null pointer argument", BOTAN_FFI_ERROR_NULL_POINTER);
      }
      list.emplace_back(protocols[i]);
   }
   return list;
}

// The stock policies reject a version whose module is not compiled in as
// an invalid argument (BAD_PARAMETER); report NOT_IMPLEMENTED instead.
int check_offer_version(uint16_t offer_version) {
   if(offer_version == 0) {
      return BOTAN_FFI_SUCCESS;
   }
   if(offer_version == BOTAN_TLS_VERSION_TLS_12) {
#if defined(BOTAN_HAS_TLS_12)
      return BOTAN_FFI_SUCCESS;
#else
      return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }
   if(offer_version == BOTAN_TLS_VERSION_TLS_13) {
#if defined(BOTAN_HAS_TLS_13)
      return BOTAN_FFI_SUCCESS;
#else
      return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }
   return BOTAN_FFI_ERROR_BAD_PARAMETER;
}

int init_channel(botan_tls_channel_t* chan,
                 botan_tls_callbacks_t callbacks,
                 void* ctx,
                 botan_tls_policy_t policy,
                 botan_tls_credentials_t creds,
                 botan_tls_session_manager_t sessions,
                 botan_rng_t rng,
                 const char* const* alpn_protocols,
                 size_t alpn_count,
                 const char* server_name,
                 uint16_t server_port,
                 uint16_t offer_version,
                 bool is_client) {
   const auto& table = safe_get(callbacks);
   const auto protocols = protocol_list(alpn_protocols, alpn_count);

   auto state = std::make_unique<FFI_TLS_Channel>();
   state->callbacks =
      std::make_shared<FFI_TLS_Callbacks>(table, ctx, is_client ? std::vector<std::string>() : protocols);

   const auto session_manager = session_manager_for(sessions);
   const std::shared_ptr<Botan::Credentials_Manager> credentials = safe_get_sp(creds);
   const auto policy_ptr = safe_get_sp(policy);
   const auto rng_ptr = rng_for(rng);

   if(is_client) {
      const auto version = (offer_version == 0) ? Botan::TLS::Protocol_Version::latest_tls_version()
                                                : Botan::TLS::Protocol_Version(offer_version);
      state->channel = std::make_unique<Botan::TLS::Client>(state->callbacks,
                                                            session_manager,
                                                            credentials,
                                                            policy_ptr,
                                                            rng_ptr,
                                                            Botan::TLS::Server_Information(server_name, server_port),
                                                            version,
                                                            protocols);
   } else {
      state->channel =
         std::make_unique<Botan::TLS::Server>(state->callbacks, session_manager, credentials, policy_ptr, rng_ptr);
   }

   return ffi_new_object(chan, std::move(state));
}

}  // namespace

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
   return BOTAN_FFI_VISIT(policy, [=](const auto& p) { return invoke_view_callback(view, ctx, p.to_string()); });
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
   return BOTAN_FFI_VISIT(creds, [=](auto& c) { c.add_trusted_cert(safe_get(cert)); });
}

int botan_tls_credentials_add_crl(botan_tls_credentials_t creds, botan_x509_crl_t crl) {
   return BOTAN_FFI_VISIT(creds, [=](auto& c) { c.add_crl(safe_get(crl)); });
}

int botan_tls_credentials_add_trusted_dir(botan_tls_credentials_t creds, const char* path) {
   if(any_null_pointers(creds, path)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
   return BOTAN_FFI_VISIT(creds, [=](auto& c) -> int {
      // The directory constructor silently yields an empty store for a
      // missing or unreadable directory, which would make every verification
      // fail without any hint why; report that as an error instead.
      auto store = std::make_shared<Botan::Certificate_Store_In_Memory>(std::string_view(path));
      if(store->all_subjects().empty()) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
      c.add_store(std::move(store));
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
   return BOTAN_FFI_VISIT(creds, [](auto& c) { c.add_store(std::make_shared<Botan::System_Certificate_Store>()); });
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

   return BOTAN_FFI_VISIT(creds, [=](auto& c) -> int {
      std::vector<Botan::X509_Certificate> certs;
      certs.reserve(chain_len);
      for(size_t i = 0; i != chain_len; ++i) {
         certs.push_back(safe_get(chain[i]));
      }

      std::shared_ptr<Botan::Private_Key> key_ptr = safe_get_sp(key);

      if(key_ptr->public_key()->fingerprint_public() != certs.front().subject_public_key()->fingerprint_public()) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }

      c.add_cert_chain(std::move(certs), std::move(key_ptr));
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
      return ffi_new_object(mgr, std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng_for(rng), max_sessions));
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

/*
* Versions and ciphersuites
*/

int botan_tls_version_is_available(uint16_t version_code) {
   if(version_code == BOTAN_TLS_VERSION_TLS_12 || version_code == BOTAN_TLS_VERSION_TLS_13) {
      return Botan::TLS::Protocol_Version(version_code).known_version() ? 1 : 0;
   }
   return 0;
}

int botan_tls_ciphersuite_view_name(uint16_t ciphersuite_code, botan_view_ctx ctx, botan_view_str_fn view) {
   return ffi_guard_thunk(__func__, [=]() -> int {
      const auto suite = Botan::TLS::Ciphersuite::by_id(ciphersuite_code);
      if(!suite.has_value()) {
         return BOTAN_FFI_ERROR_NO_VALUE;
      }
      return invoke_view_callback(view, ctx, suite->to_string());
   });
}

/*
* Callbacks
*/

int botan_tls_callbacks_init(botan_tls_callbacks_t* cb,
                             botan_tls_emit_data_fn emit_data,
                             botan_tls_record_received_fn record_received,
                             botan_tls_alert_received_fn alert_received) {
   if(any_null_pointers(cb, emit_data, record_received, alert_received)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   *cb = nullptr;

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto table = std::make_unique<FFI_TLS_Callbacks_Table>();
      table->emit_data = emit_data;
      table->record_received = record_received;
      table->alert_received = alert_received;
      return ffi_new_object(cb, std::move(table));
   });
}

int botan_tls_callbacks_set_handshake_complete(botan_tls_callbacks_t cb, botan_tls_handshake_complete_fn fn) {
   return BOTAN_FFI_VISIT(cb, [=](auto& t) { t.handshake_complete = fn; });
}

int botan_tls_callbacks_destroy(botan_tls_callbacks_t cb) {
   return BOTAN_FFI_CHECKED_DELETE(cb);
}

/*
* Channels
*/

int botan_tls_channel_init_client(botan_tls_channel_t* chan,
                                  botan_tls_callbacks_t callbacks,
                                  void* ctx,
                                  botan_tls_policy_t policy,
                                  botan_tls_credentials_t creds,
                                  botan_tls_session_manager_t sessions,
                                  botan_rng_t rng,
                                  const char* server_name,
                                  uint16_t server_port,
                                  uint16_t offer_version,
                                  const char* const* alpn_protocols,
                                  size_t alpn_count,
                                  uint32_t flags) {
   if(any_null_pointers(chan, callbacks, policy, creds, server_name)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   if(alpn_protocols == nullptr && alpn_count > 0) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   *chan = nullptr;

   if(flags != 0) {
      return BOTAN_FFI_ERROR_BAD_FLAG;
   }

   if(*server_name == '\0') {
      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   }

   if(const int rc = check_offer_version(offer_version); rc != BOTAN_FFI_SUCCESS) {
      return rc;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      return init_channel(chan,
                          callbacks,
                          ctx,
                          policy,
                          creds,
                          sessions,
                          rng,
                          alpn_protocols,
                          alpn_count,
                          server_name,
                          server_port,
                          offer_version,
                          true);
   });
}

int botan_tls_channel_init_server(botan_tls_channel_t* chan,
                                  botan_tls_callbacks_t callbacks,
                                  void* ctx,
                                  botan_tls_policy_t policy,
                                  botan_tls_credentials_t creds,
                                  botan_tls_session_manager_t sessions,
                                  botan_rng_t rng,
                                  const char* const* alpn_protocols,
                                  size_t alpn_count,
                                  uint32_t flags) {
   if(any_null_pointers(chan, callbacks, policy, creds)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   if(alpn_protocols == nullptr && alpn_count > 0) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   *chan = nullptr;

   if(flags != 0) {
      return BOTAN_FFI_ERROR_BAD_FLAG;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      return init_channel(
         chan, callbacks, ctx, policy, creds, sessions, rng, alpn_protocols, alpn_count, "", 0, 0, false);
   });
}

int botan_tls_channel_received_data(botan_tls_channel_t chan, const uint8_t data[], size_t len, size_t* bytes_needed) {
   if(data == nullptr && len > 0) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(chan, [=](auto& c) -> int {
      if(c.callbacks->depth() > 0 || c.callbacks->failed()) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }

      const FFI_TLS_Callbacks::Depth_Guard guard(*c.callbacks);
      const size_t needed = c.channel->received_data(data, len);
      if(bytes_needed != nullptr) {
         *bytes_needed = needed;
      }
      return BOTAN_FFI_SUCCESS;
   });
}

int botan_tls_channel_send(botan_tls_channel_t chan, const uint8_t data[], size_t len) {
   if(data == nullptr && len > 0) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(chan, [=](auto& c) -> int {
      if(c.callbacks->in_emit() || c.callbacks->failed() || !c.channel->is_active()) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }

      const FFI_TLS_Callbacks::Depth_Guard guard(*c.callbacks);
      c.channel->send(data, len);
      return c.callbacks->failed() ? BOTAN_FFI_ERROR_TLS_ERROR : BOTAN_FFI_SUCCESS;
   });
}

int botan_tls_channel_close(botan_tls_channel_t chan) {
   return BOTAN_FFI_VISIT(chan, [=](auto& c) -> int {
      if(c.callbacks->depth() > 0 || c.callbacks->failed()) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }

      const FFI_TLS_Callbacks::Depth_Guard guard(*c.callbacks);
      c.channel->close();
      if(c.callbacks->failed()) {
         return BOTAN_FFI_ERROR_TLS_ERROR;
      }
      return BOTAN_FFI_SUCCESS;
   });
}

int botan_tls_channel_is_handshake_complete(botan_tls_channel_t chan) {
   return BOTAN_FFI_VISIT(chan, [](const auto& c) -> int { return c.channel->is_handshake_complete() ? 1 : 0; });
}

int botan_tls_channel_is_active(botan_tls_channel_t chan) {
   return BOTAN_FFI_VISIT(
      chan, [](const auto& c) -> int { return (!c.callbacks->failed() && c.channel->is_active()) ? 1 : 0; });
}

int botan_tls_channel_is_closed(botan_tls_channel_t chan) {
   return BOTAN_FFI_VISIT(
      chan, [](const auto& c) -> int { return (c.callbacks->failed() || c.channel->is_closed()) ? 1 : 0; });
}

int botan_tls_channel_is_closed_for_reading(botan_tls_channel_t chan) {
   return BOTAN_FFI_VISIT(
      chan, [](const auto& c) -> int { return (c.callbacks->failed() || c.channel->is_closed_for_reading()) ? 1 : 0; });
}

int botan_tls_channel_is_closed_for_writing(botan_tls_channel_t chan) {
   return BOTAN_FFI_VISIT(
      chan, [](const auto& c) -> int { return (c.callbacks->failed() || c.channel->is_closed_for_writing()) ? 1 : 0; });
}

int botan_tls_channel_destroy(botan_tls_channel_t chan) {
   if(chan != nullptr && chan->magic_ok()) {
      const auto* state = chan->unsafe_get();
      if(state != nullptr && state->callbacks != nullptr && state->callbacks->depth() > 0) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }
   }
   return BOTAN_FFI_CHECKED_DELETE(chan);
}

}  // extern "C"
