/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/internal/ffi_util.h>
#include <botan/internal/ffi_rng.h>

#if defined(BOTAN_HAS_TLS)
  #include <botan/tls_channel.h>
  #include <botan/tls_session.h>
  #include <botan/tls_session_manager.h>
  #include <botan/tls_policy.h>
#endif

extern "C" {

using namespace Botan_FFI;

#if defined(BOTAN_HAS_TLS)

struct FFI_TLS_Channel_Struct
   {
   std::unique_ptr<Botan::TLS::Channel> channel;
   std::unique_ptr<Botan::TLS::Callbacks> callbacks;
   };

BOTAN_FFI_DECLARE_STRUCT(botan_tls_session_manager_struct, Botan::TLS::Session_Manager, 0x634C6D67);
BOTAN_FFI_DECLARE_STRUCT(botan_tls_session_struct, Botan::TLS::Session, 0x93091969);
BOTAN_FFI_DECLARE_STRUCT(botan_tls_policy_struct, Botan::TLS::Policy, 0x6E590C76);
BOTAN_FFI_DECLARE_STRUCT(botan_tls_channel_struct, FFI_TLS_Channel_Struct, 0xE818A572);

#else

struct FFI_TLS_Dummy_Struct {};

BOTAN_FFI_DECLARE_STRUCT(botan_tls_session_manager_struct, FFI_TLS_Dummy_Struct, 0x634C6D67);
BOTAN_FFI_DECLARE_STRUCT(botan_tls_session_struct, FFI_TLS_Dummy_Struct, 0x93091969);
BOTAN_FFI_DECLARE_STRUCT(botan_tls_policy_struct, FFI_TLS_Dummy_Struct, 0x6E590C76);
BOTAN_FFI_DECLARE_STRUCT(botan_tls_channel_struct, FFI_TLS_Dummy_Struct, 0xE818A572);

#endif

}

namespace {

template<typename Policy_Type>
int botan_tls_policy_init(botan_tls_policy_t* policy)
   {
   if(policy == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

   *policy = nullptr;

#if defined(BOTAN_HAS_TLS)
   return ffi_guard_thunk(BOTAN_CURRENT_FUNCTION, [=]() -> int {
      policy = new botan_tls_policy_struct(new Botan::TLS::Policy);
      return BOTAN_FFI_SUCCESS;
      });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

}

extern "C" {

int botan_tls_policy_default_init(botan_tls_policy_t* policy)
   {
   return botan_tls_policy_init<Botan::TLS::Policy>(policy);
   }

int botan_tls_policy_nsa_suiteb_init(botan_tls_policy_t* policy)
   {
   return botan_tls_policy_init<Botan::TLS::NSA_Suite_B_128>(policy);
   }

int botan_tls_policy_bsi_tr_02102_2_init(botan_tls_policy_t* policy)
   {
   return botan_tls_policy_init<Botan::TLS::BSI_TR_02102_2>(policy);
   }

int botan_tls_policy_text_init(botan_tls_policy_t* policy, const char* policy_text)
   {
   if(policy == nullptr || policy_text == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

#if defined(BOTAN_HAS_TLS)
   return -1;
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_tls_policy_destroy(botan_tls_policy_t policy)
   {
   return BOTAN_FFI_CHECKED_DELETE(policy);
   }

int botan_tls_session_manager_memory_init(botan_tls_session_manager_t* mgr,
                                          size_t max_sessions)
   {
#if defined(BOTAN_HAS_TLS)
   return -1;
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_tls_session_manager_sql_init(botan_tls_session_manager_t* mgr,
                                       const char* sql_db_filename,
                                       const char* db_passphrase,
                                       size_t max_sessions)
   {
#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_TLS_SESSION_MANAGER_SQL_DB)
   return -1;
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_tls_session_manager_destroy(botan_tls_session_manager_t mgr)
   {
   return BOTAN_FFI_CHECKED_DELETE(mgr);
   }

int botan_tls_session_encrypt(botan_tls_session_t session, botan_rng_t rng, uint8_t key[], size_t* key_len)
   {
#if defined(BOTAN_HAS_TLS)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED; // todo
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_tls_session_decrypt(botan_tls_session_t* session,
                              const uint8_t key[], size_t key_len,
                              const uint8_t blob[], size_t blob_len)
   {
#if defined(BOTAN_HAS_TLS)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED; // todo
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_tls_session_get_version(botan_tls_session_t session, uint16_t* tls_version)
   {
#if defined(BOTAN_HAS_TLS)
   return BOTAN_FFI_DO(Botan::TLS::Session, session, s, { *tls_version = s.version().raw_version(); });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_tls_session_get_ciphersuite(botan_tls_session_t session, uint16_t* ciphersuite)
   {
#if defined(BOTAN_HAS_TLS)
   return BOTAN_FFI_DO(Botan::TLS::Session, session, s, { *ciphersuite = s.ciphersuite_code(); });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_tls_session_get_peer_certs(botan_tls_session_t session, botan_x509_cert_t certs[], size_t* cert_len)
   {
#if defined(BOTAN_HAS_TLS)
   return -1;
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

namespace {

class FFI_TLS_Callbacks : public Botan::TLS::Callbacks
   {
   public:
      FFI_TLS_Callbacks(botan_tls_channel_output_fn output_fn,
                        botan_tls_channel_data_cb data_cb,
                        botan_tls_channel_alert_cb alert_cb,
                        botan_tls_channel_session_established session_cb) :
         m_output_fn(output_fn),
         m_data_cb(data_cb),
         m_alert_cb(alert_cb),
         m_session_cb(session_cb)
         {}

      void tls_emit_data(const uint8_t data[], size_t size) override
         {
         }

       void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override
         {

         }

      void tls_alert(Botan::TLS::Alert alert) override
         {

         }

      bool tls_session_established(const Botan::TLS::Session& session) override
         {

         }

   private:
      botan_tls_channel_output_fn m_output_fn;
      botan_tls_channel_data_cb m_data_cb;
      botan_tls_channel_alert_cb m_alert_cb;
      botan_tls_channel_session_established m_session_cb;
   };

}

int botan_tls_channel_init_client(botan_tls_channel_t* channel,
                                  botan_tls_channel_output_fn output_fn,
                                  botan_tls_channel_data_cb data_cb,
                                  botan_tls_channel_alert_cb alert_cb,
                                  botan_tls_channel_session_established session_cb,
                                  botan_tls_session_manager_t session_manager,
                                  const char* server_name)
   {
#if defined(BOTAN_HAS_TLS)

   if(channel == nullptr ||
      output_fn == nullptr ||
      data_cb == nullptr ||
      alert_cb == nullptr ||
      session_cb == nullptr)
      {
      return BOTAN_FFI_ERROR_NULL_POINTER;
      }

   return ffi_guard_thunk(BOTAN_CURRENT_FUNCTION, [=]() {

      *channel = nullptr;

      std::unique_ptr<Botan::TLS::Callbacks> ffi_cb(
         new FFI_TLS_Callbacks(output_fn, data_cb, alert_cb, session_cb));

      std::unique_ptr<Botan::TLS::Channel> c(new Botan::TLS::Client(*ffi_cb, 
            Channel(Callbacks& callbacks,
              Session_Manager& session_manager,
              RandomNumberGenerator& rng,
              const Policy& policy,
              bool is_datagram,
              size_t io_buf_sz = IO_BUF_DEFAULT_SIZE);


      *bc = new botan_block_cipher_struct(cipher.release());
      return BOTAN_FFI_SUCCESS;
      });

#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_tls_channel_init_server(botan_tls_channel_t* channel,
                                  botan_tls_channel_output_fn output_fn,
                                  botan_tls_channel_data_cb data_cb,
                                  botan_tls_channel_alert_cb alert_cb,
                                  botan_tls_channel_session_established session_cb)
   {
#if defined(BOTAN_HAS_TLS)

#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_tls_channel_received_data(botan_tls_channel_t chan,
                                    const uint8_t input[], size_t len)
   {
#if defined(BOTAN_HAS_TLS)
   BOTAN_FFI_DO(Botan::TLS::Channel, chan, c, { c.received_data(input, len); });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_tls_channel_type(botan_tls_channel_t chan)
   {
#if defined(BOTAN_HAS_TLS)
   BOTAN_FFI_DO(Botan::TLS::Channel, chan, c, {
      return (dynamic_cast<Botan::TLS::Client*>(&c) != nullptr) ? 0 : 1;
      });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_tls_channel_send(botan_tls_channel_t chan,
                           const uint8_t input[], size_t len)
   {
#if defined(BOTAN_HAS_TLS)
   BOTAN_FFI_DO(Botan::TLS::Channel, chan, c, { c.send(input, len); });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_tls_channel_close(botan_tls_channel_t chan)
   {
#if defined(BOTAN_HAS_TLS)
   BOTAN_FFI_DO(Botan::TLS::Channel, chan, c, { c.close(); });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_tls_channel_destroy(botan_tls_channel_t chan)
   {
   return BOTAN_FFI_CHECKED_DELETE(chan);
   }

}
