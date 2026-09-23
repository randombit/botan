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
#include <botan/tls_alert.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_channel.h>
#include <botan/tls_policy.h>
#include <botan/tls_session.h>
#include <botan/tls_session_manager.h>
#include <botan/x509cert.h>
#include <botan/internal/ffi_util.h>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Botan_FFI {

/**
* The Credentials_Manager behind botan_tls_credentials_t.
*
* Trust anchors and CRLs live in an in-memory certificate store; further
* stores (a directory, the system store) are kept as separate objects. The
* certificate chains are used for server and for client authentication
* alike. The setters copy certificates and CRLs and share the private keys.
* The object is not synchronized, but
* otherwise it may be modified at any time and shared between channels.
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

/**
* The callbacks behind botan_tls_callbacks_t; the context pointer belongs to
* the channel.
*/
struct FFI_TLS_Callbacks_Table {
      botan_tls_emit_data_fn emit_data = nullptr;
      botan_tls_record_received_fn record_received = nullptr;
      botan_tls_alert_received_fn alert_received = nullptr;
      botan_tls_handshake_complete_fn handshake_complete = nullptr;
};

/**
* The TLS::Callbacks of a channel: forwards the library's events to the C
* callbacks with the channel's context pointer, turns a failing callback into
* an exception that aborts the connection, and keeps the state the C API
* exposes.
*/
class FFI_TLS_Callbacks final : public Botan::TLS::Callbacks {
   public:
      /**
      * Increments the channel's callback depth while a channel function that
      * may run callbacks is executing.
      */
      class Depth_Guard final {
         public:
            explicit Depth_Guard(FFI_TLS_Callbacks& cb) : m_cb(cb) { ++m_cb.m_depth; }

            ~Depth_Guard() { --m_cb.m_depth; }

            Depth_Guard(const Depth_Guard&) = delete;
            Depth_Guard(Depth_Guard&&) = delete;
            Depth_Guard& operator=(const Depth_Guard&) = delete;
            Depth_Guard& operator=(Depth_Guard&&) = delete;

         private:
            FFI_TLS_Callbacks& m_cb;
      };

      FFI_TLS_Callbacks(const FFI_TLS_Callbacks_Table& table, void* ctx, std::vector<std::string> server_protocols);

      void tls_emit_data(std::span<const uint8_t> data) override;

      void tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) override;

      void tls_alert(Botan::TLS::Alert alert) override;

      void tls_session_established(const Botan::TLS::Session_Summary& summary) override;

      void tls_session_activated() override;

      std::string tls_server_choose_app_protocol(const std::vector<std::string>& client_protos) override;

      const std::optional<Botan::TLS::Session_Summary>& session_summary() const { return m_summary; }

      /// True after an emit_data callback failed; the channel is unusable then
      bool failed() const { return m_failed; }

      /// True while an emit_data callback is running
      bool in_emit() const { return m_in_emit; }

      /// Number of channel functions currently executing (0 outside callbacks)
      size_t depth() const { return m_depth; }

   private:
      FFI_TLS_Callbacks_Table m_table;
      void* m_ctx;
      std::vector<std::string> m_server_protocols;
      std::optional<Botan::TLS::Session_Summary> m_summary;
      bool m_failed = false;
      bool m_in_emit = false;
      size_t m_depth = 0;
};

/**
* The state behind botan_tls_channel_t; the callbacks pointer gives the C API
* access to the shim state.
*/
struct FFI_TLS_Channel {
      std::shared_ptr<FFI_TLS_Callbacks> callbacks;
      std::unique_ptr<Botan::TLS::Channel> channel;
};

}  // namespace Botan_FFI

extern "C" {

// TLS::Client and TLS::Server take their collaborators as std::shared_ptr,
// so the handles hold one.
BOTAN_FFI_DECLARE_SHARED_STRUCT(botan_tls_policy_struct, const Botan::TLS::Policy, 0x19781017);
BOTAN_FFI_DECLARE_SHARED_STRUCT(botan_tls_credentials_struct, Botan_FFI::FFI_TLS_Credentials, 0x5C3A9E41);
BOTAN_FFI_DECLARE_SHARED_STRUCT(botan_tls_session_manager_struct, Botan::TLS::Session_Manager, 0xB7D2E60C);
BOTAN_FFI_DECLARE_UNIQUE_STRUCT(botan_tls_callbacks_struct, Botan_FFI::FFI_TLS_Callbacks_Table, 0x3F8A2D57);
BOTAN_FFI_DECLARE_UNIQUE_STRUCT(botan_tls_channel_struct, Botan_FFI::FFI_TLS_Channel, 0xE818A572);

}  // extern "C"

#endif
