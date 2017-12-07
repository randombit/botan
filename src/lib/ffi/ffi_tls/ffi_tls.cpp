/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi_tls.h>
#include <botan/internal/ffi_rng.h>
#include <botan/internal/ffi_util.h>

#include <botan/tls_channel.h>
#include <botan/tls_policy.h>
#include <botan/tls_session.h>
#include <botan/tls_session_manager.h>

extern "C" {

using namespace Botan_FFI;

struct FFI_TLS_Channel_Struct {
      std::unique_ptr<Botan::TLS::Channel> channel;
      std::unique_ptr<Botan::TLS::Callbacks> callbacks;
};

BOTAN_FFI_DECLARE_STRUCT(botan_tls_session_manager_struct, Botan::TLS::Session_Manager, 0x634C6D67);
BOTAN_FFI_DECLARE_STRUCT(botan_tls_session_struct, Botan::TLS::Session, 0x93091969);
BOTAN_FFI_DECLARE_STRUCT(botan_tls_policy_struct, Botan::TLS::Policy, 0x6E590C76);
BOTAN_FFI_DECLARE_STRUCT(botan_tls_channel_struct, FFI_TLS_Channel_Struct, 0xE818A572);
}

namespace {

template <typename Policy_Type>
int botan_tls_policy_init(botan_tls_policy_t* policy) {
   if(policy == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   *policy = nullptr;

   return ffi_guard_thunk(__func__, [=]() -> int {
      *policy = new botan_tls_policy_struct(std::make_unique<Policy_Type>());
      return BOTAN_FFI_SUCCESS;
   });
}

}  // namespace

extern "C" {

int botan_tls_policy_default_init(botan_tls_policy_t* policy) {
   return botan_tls_policy_init<Botan::TLS::Policy>(policy);
}

int botan_tls_policy_nsa_suiteb_init(botan_tls_policy_t* policy) {
   return botan_tls_policy_init<Botan::TLS::NSA_Suite_B_192>(policy);
}

int botan_tls_policy_bsi_tr_02102_2_init(botan_tls_policy_t* policy) {
   return botan_tls_policy_init<Botan::TLS::BSI_TR_02102_2>(policy);
}

int botan_tls_policy_destroy(botan_tls_policy_t policy) {
   return BOTAN_FFI_CHECKED_DELETE(policy);
}

int botan_tls_session_manager_memory_init(botan_tls_session_manager_t* mgr, size_t max_sessions) {
   BOTAN_UNUSED(mgr, max_sessions);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
}

int botan_tls_session_manager_destroy(botan_tls_session_manager_t mgr) {
   return BOTAN_FFI_CHECKED_DELETE(mgr);
}

int botan_tls_session_get_version(botan_tls_session_t session, uint16_t* tls_version) {
   if(session == nullptr || tls_version == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(session, [=](const auto& s) { *tls_version = s.version().version_code(); });
}

int botan_tls_session_get_ciphersuite(botan_tls_session_t session, uint16_t* ciphersuite) {
   if(session == nullptr || ciphersuite == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(session, [=](const auto& s) { *ciphersuite = s.ciphersuite_code(); });
}

namespace {

class FFI_TLS_Callbacks final : public Botan::TLS::Callbacks {
   public:
      FFI_TLS_Callbacks(botan_tls_channel_output_fn output_fn,
                        botan_tls_channel_data_cb data_cb,
                        botan_tls_channel_alert_cb alert_cb,
                        botan_tls_channel_session_established session_cb) :
            m_output_fn(output_fn), m_data_cb(data_cb), m_alert_cb(alert_cb), m_session_cb(session_cb) {}

      void tls_emit_data(std::span<const uint8_t> data) override {
         BOTAN_UNUSED(data); // todo
      }

      void tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) override {
         BOTAN_UNUSED(seq_no);
         BOTAN_UNUSED(data); // todo
      }

      void tls_alert(Botan::TLS::Alert alert) override {
         BOTAN_UNUSED(alert); // todo
      }

      void tls_session_established(const Botan::TLS::Session_Summary& session) override {
         BOTAN_UNUSED(session); // todo
      }

   private:
      botan_tls_channel_output_fn m_output_fn;
      botan_tls_channel_data_cb m_data_cb;
      botan_tls_channel_alert_cb m_alert_cb;
      botan_tls_channel_session_established m_session_cb;
};

}  // namespace

int botan_tls_channel_init_client(botan_tls_channel_t* channel,
                                  botan_tls_channel_output_fn output_fn,
                                  botan_tls_channel_data_cb data_cb,
                                  botan_tls_channel_alert_cb alert_cb,
                                  botan_tls_channel_session_established session_cb,
                                  botan_tls_session_manager_t session_manager,
                                  const char* server_name) {
   if(channel == nullptr || output_fn == nullptr || data_cb == nullptr || alert_cb == nullptr ||
      session_cb == nullptr || session_manager == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;

   BOTAN_UNUSED(server_name); // fixme

   #if 0
   return ffi_guard_thunk(__func__, [=]() {
      *channel = nullptr;

      std::unique_ptr<Botan::TLS::Callbacks> ffi_cb(new FFI_TLS_Callbacks(output_fn, data_cb, alert_cb, session_cb));

      Client(const std::shared_ptr<Callbacks>& callbacks,
             const std::shared_ptr<Session_Manager>& session_manager,
             const std::shared_ptr<Credentials_Manager>& creds,
             const std::shared_ptr<const Policy>& policy,
             const std::shared_ptr<RandomNumberGenerator>& rng,
             Server_Information server_info = Server_Information(),
             Protocol_Version offer_version = Protocol_Version::latest_tls_version(),
             const std::vector<std::string>& next_protocols = {},
             size_t reserved_io_buffer_size = TLS::Client::IO_BUF_DEFAULT_SIZE);

      std::unique_ptr<Botan::TLS::Channel> c(new Botan::TLS::Client(*ffi_cb,
            Channel(Callbacks& callbacks,
              Session_Manager& session_manager,
              RandomNumberGenerator& rng,
              const Policy& policy,
              bool is_datagram,
                    size_t io_buf_sz = IO_BUF_DEFAULT_SIZE));



      return BOTAN_FFI_SUCCESS;
   });
#endif
}

int botan_tls_channel_init_server(botan_tls_channel_t* channel,
                                  botan_tls_channel_output_fn output_fn,
                                  botan_tls_channel_data_cb data_cb,
                                  botan_tls_channel_alert_cb alert_cb,
                                  botan_tls_channel_session_established session_cb,
                                  botan_tls_session_manager_t session_manager) {

   if(channel == nullptr || output_fn == nullptr || data_cb == nullptr || alert_cb == nullptr ||
      session_cb == nullptr || session_manager == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
}

int botan_tls_channel_received_data(botan_tls_channel_t chan, const uint8_t input[], size_t len) {
   return BOTAN_FFI_VISIT(chan, [=](const auto& c) { c.channel->received_data(input, len); });
}

int botan_tls_channel_send(botan_tls_channel_t chan, const uint8_t input[], size_t len) {
   return BOTAN_FFI_VISIT(chan, [=](const auto& c) { c.channel->send(input, len); });
}

int botan_tls_channel_close(botan_tls_channel_t chan) {
   return BOTAN_FFI_VISIT(chan, [](const auto& c) { c.channel->close(); });
}

int botan_tls_channel_destroy(botan_tls_channel_t chan) {
   return BOTAN_FFI_CHECKED_DELETE(chan);
}
}
