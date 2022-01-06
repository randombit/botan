/*
* TLS Client - implementation for TLS 1.3
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include <botan/tls_client.h>
#include <botan/tls_messages.h>
#include <botan/internal/tls_client_impl_13.h>
#include <botan/internal/tls_channel_impl_13.h>
#include <botan/internal/tls_client_impl.h>

#include <botan/credentials_manager.h>

namespace Botan {

namespace TLS {

namespace {

class Client_Handshake_State_13 final : public Handshake_State
   {
   public:
      Client_Handshake_State_13(std::unique_ptr<Handshake_IO> io, Callbacks& cb) :
         Handshake_State(std::move(io), cb)
         {}

      const Public_Key& get_server_public_key() const
         {
         BOTAN_ASSERT(server_public_key, "Server sent us a certificate");
         return *server_public_key.get();
         }

      bool is_a_resumption() const { return (resumed_session != nullptr); }

      const secure_vector<uint8_t>& resume_master_secret() const
         {
         BOTAN_STATE_CHECK(is_a_resumption());
         return resumed_session->master_secret();
         }

      const std::vector<X509_Certificate>& resume_peer_certs() const
         {
         BOTAN_STATE_CHECK(is_a_resumption());
         return resumed_session->peer_certs();
         }

      std::unique_ptr<Public_Key> server_public_key;

      // Used during session resumption
      std::unique_ptr<Session> resumed_session;
   };

}

Client_Impl_13::Client_Impl_13(Callbacks& callbacks,
                               Session_Manager& session_manager,
                               Credentials_Manager& creds,
                               const Policy& policy,
                               RandomNumberGenerator& rng,
                               const Server_Information& info,
                               const Protocol_Version& offer_version,
                               const std::vector<std::string>& next_protocols,
                               size_t io_buf_sz) :
   Channel_Impl_13(callbacks, session_manager, rng, policy,
                   false, io_buf_sz),
   Client_Impl(static_cast<Channel_Impl&>(*this)),
   m_creds(creds),
   m_info(info)
   {
   BOTAN_UNUSED(m_creds); // TODO: fixme
   Handshake_State& state = create_handshake_state(offer_version);
   send_client_hello(state, offer_version, next_protocols);
   }

std::vector<X509_Certificate> Client_Impl_13::get_peer_cert_chain(const Handshake_State& state) const
   {
   BOTAN_UNUSED(state);

   return std::vector<X509_Certificate>();
   }

void Client_Impl_13::initiate_handshake(Handshake_State& state,
                                        bool force_full_renegotiation)
   {
   BOTAN_UNUSED(state, force_full_renegotiation);
   }

void Client_Impl_13::process_handshake_msg(const Handshake_State* previous_state,
      Handshake_State& state,
      Handshake_Type type,
      const std::vector<uint8_t>& contents,
      bool epoch0_restart)
   {
   // there cannot be a previous state in TLS 1.3 as renegotiation is not allowed
   BOTAN_ASSERT_NOMSG(previous_state == nullptr);

   // does not apply on client side
   BOTAN_ASSERT_NOMSG(epoch0_restart == false);

   state.confirm_transition_to(type);

   if(type == SERVER_HELLO)
      {
      state.server_hello(new Server_Hello(contents));
      auto sh = state.server_hello();

      if(sh->legacy_version() != Protocol_Version::TLS_V12)
         {
         // RFC 8446 4.1.3:
         //   In TLS 1.3, the TLS server indicates
         //   its version using the "supported_versions" extension
         //   (Section 4.2.1), and the legacy_version field MUST be set to
         //   0x0303, which is the version number for TLS 1.2.
         throw TLS_Exception(Alert::PROTOCOL_VERSION, "legacy_version must be set to 1.2 in TLS 1.3");
         }

      if(auto requested = sh->random_signals_downgrade())
         {
         if(requested.value() == Protocol_Version::TLS_V11)
            { throw TLS_Exception(Alert::PROTOCOL_VERSION, "TLS 1.1 is not supported"); }
         if(requested.value() == Protocol_Version::TLS_V12)
            { throw Not_Implemented("downgrade is nyi"); }
         }

      if(sh->random_signals_hello_retry_request())
         {
         throw Not_Implemented("hello retry is nyi");
         }

      if(!sh->extensions().has<Key_Share>())
         {
           // TODO
         throw Unexpected_Message("keyshare ext not found!");
         }

      BOTAN_ASSERT_NOMSG(state.client_hello()->extensions().has<Key_Share>());
      auto my_keyshare = state.client_hello()->extensions().get<Key_Share>();
      const auto shared_secret = my_keyshare->exchange(sh->extensions().get<Key_Share>(), policy(), callbacks(), rng());

      state.set_expected_next(ENCRYPTED_EXTENSIONS);  // TODO expect CCS (middlebox compat)

      }
   else if(type == ENCRYPTED_EXTENSIONS)
      {
      throw Not_Implemented("client 13 process_handshake_msg is nyi");
      }
   else
      {
      throw Unexpected_Message("unknown handshake message received");
      }
   }

std::unique_ptr<Handshake_State> Client_Impl_13::new_handshake_state(std::unique_ptr<Handshake_IO> io)
   {
   return std::make_unique<Client_Handshake_State_13>(std::move(io), callbacks());
   }

void Client_Impl_13::send_client_hello(Handshake_State& state_base,
                                       Protocol_Version version,
                                       const std::vector<std::string>& next_protocols)
   {
   Client_Handshake_State_13& state = dynamic_cast<Client_Handshake_State_13&>(state_base);

   state.set_expected_next(SERVER_HELLO);

   if(!state.client_hello())
      {
      Client_Hello::Settings client_settings(version, m_info.hostname());
      state.client_hello(new Client_Hello(
                            state.handshake_io(),
                            state.hash(),
                            policy(),
                            callbacks(),
                            rng(),
                            std::vector<uint8_t>(),
                            client_settings,
                            next_protocols));
      }
   }

}

}
