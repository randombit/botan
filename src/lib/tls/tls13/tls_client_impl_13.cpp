/*
* TLS Client - implementation for TLS 1.3
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include <botan/tls_client.h>
#include <botan/hash.h>
#include <botan/tls_messages.h>
#include <botan/internal/tls_client_impl_13.h>
#include <botan/internal/tls_channel_impl_13.h>
#include <botan/internal/tls_client_impl.h>
#include <botan/internal/tls_cipher_state.h>

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

void Client_Impl_13::process_handshake_msg(
   Handshake_State& state,
   Handshake_Type type,
   const std::vector<uint8_t>& contents)
   {
   state.confirm_transition_to(type);

   // TODO: this uses the TLS 1.2 handshake hash structure. Our working hypothesis
   //       from the 31st of January: This will not work as soon as we introduce
   //       Hello Retry Requests or Pre Shared Keys.
   // TODO: handshake_io().format() re-adds the handshake message's header. In a
   //       new solution for "transcript hash" we probably want to hash before this
   //       header is stripped.
   secure_vector<uint8_t> previous_transcript_hash;
   if(type == CERTIFICATE_VERIFY || type == FINISHED)
      {
      // When receiving a finished message, we need the old transcript hash to verify the message.
      previous_transcript_hash = state.hash().final(state.ciphersuite().prf_algo());
      }
   state.hash().update(state.handshake_io().format(contents, type));

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

      if(!state.client_hello()->offered_suite(sh->ciphersuite()))
         {
         throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "Ciphersuite was not offered");
         }

      auto cipher = Ciphersuite::by_id(sh->ciphersuite());
      BOTAN_ASSERT_NOMSG(cipher.has_value());  // should work, since we offered this suite

      m_transcript_hash = HashFunction::create_or_throw(cipher.value().prf_algo());

      if(!sh->extensions().has<Key_Share>())
         {
         // TODO
         throw Unexpected_Message("keyshare ext not found!");
         }

      BOTAN_ASSERT_NOMSG(state.client_hello()->extensions().has<Key_Share>());
      auto my_keyshare = state.client_hello()->extensions().get<Key_Share>();
      auto shared_secret = my_keyshare->exchange(sh->extensions().get<Key_Share>(), policy(), callbacks(), rng());

      m_cipher_state = Cipher_State::init_with_server_hello(m_side,
                       std::move(shared_secret),
                       cipher.value(),
                       state.hash().final(cipher.value().prf_algo()));

      callbacks().tls_examine_extensions(state.server_hello()->extensions(), SERVER);

      state.set_expected_next(ENCRYPTED_EXTENSIONS);  // TODO expect CCS (middlebox compat)
      }
   else if(type == ENCRYPTED_EXTENSIONS)
      {
      // TODO: check all extensions are allowed and expected
      state.encrypted_extensions(new Encrypted_Extensions(contents));

      // Note: As per RFC 6066 3. we can check for an empty SNI extensions to
      // determine if the server used the SNI we sent here.

      callbacks().tls_examine_extensions(state.encrypted_extensions()->extensions(), SERVER);

      // TODO: this is not true if using PSK

      state.set_expected_next(CERTIFICATE_REQUEST);
      state.set_expected_next(CERTIFICATE);
      }
   else if(type == CERTIFICATE_REQUEST)
      {
      state.set_expected_next(CERTIFICATE);
      }
   else if(type == CERTIFICATE)
      {
      state.server_certs(new Certificate_13(contents, policy(), SERVER, state.client_hello()->extensions()));

      const auto& server_certs = state.server_certs_13()->cert_chain();

      // RFC 8446 4.4.2.4
      //    If the server supplies an empty Certificate message, the client
      //    MUST abort the handshake with a "decode_error" alert.
      if(server_certs.empty())
         { throw TLS_Exception(Alert::DECODE_ERROR, "Client: No certificates sent by server"); }

      auto trusted_CAs = m_creds.trusted_certificate_authorities("tls-client", m_info.hostname());

      std::vector<X509_Certificate> certs;
      std::transform(server_certs.cbegin(), server_certs.cend(), std::back_inserter(certs),
      [](const auto& entry) { return entry.certificate; });

      callbacks().tls_verify_cert_chain(certs,
                                        {},  // TODO: Support OCSP stapling via RFC8446 4.4.2.1
                                        trusted_CAs,
                                        Usage_Type::TLS_SERVER_AUTH,
                                        m_info.hostname(),
                                        policy());

      state.set_expected_next(CERTIFICATE_VERIFY);
      }
   else if(type == CERTIFICATE_VERIFY)
      {
      state.server_verify(new Certificate_Verify_13(contents));

      bool sig_valid = state.server_verify_13()->verify(
         state.server_certs_13()->cert_chain().front().certificate,
         state,
         policy(),
         SERVER,
         previous_transcript_hash);

     if(!sig_valid)
         throw TLS_Exception(Alert::DECRYPT_ERROR, "Server certificate verification failed");

      state.set_expected_next(FINISHED);
      }
   else if(type == FINISHED)
      {
      state.server_finished(new Finished(contents));

      // RFC 8446 4.4.4
      //    Recipients of Finished messages MUST verify that the contents are
      //    correct and if incorrect MUST terminate the connection with a
      //    "decrypt_error" alert.
      if(!state.server_finished()->verify(m_cipher_state.get(),
                                          previous_transcript_hash /* before the server finished message was incorporated */))
         { throw TLS_Exception(Alert::DECRYPT_ERROR, "Finished message didn't verify"); }

      // after the server finished message was incorporated
      const auto transcript_hash_server_finished = state.hash().final(state.ciphersuite().prf_algo());

      // send client finished handshake message (still using handshake traffic secrets)
      state.client_finished(new Finished(state.handshake_io(), state, m_cipher_state.get(),
                                         transcript_hash_server_finished));

      // after the client finished message was incorporated
      const auto transcript_hash_client_finished = state.hash().final(state.ciphersuite().prf_algo());

      // derives the application traffic secrets and _replaces_ the handshake traffic secrets
      // Note: this MUST happen AFTER the client finished message was sent!
      m_cipher_state->advance_with_server_finished(transcript_hash_server_finished);
      m_cipher_state->advance_with_client_finished(transcript_hash_client_finished);

      // TODO: save session and invoke tls_session_established callback

      callbacks().tls_session_activated();
      }
   else
      {
      throw Unexpected_Message("unknown handshake message received: " +
                               std::string(handshake_type_to_string(type)));
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

   // TODO: also expect HelloRetryRequest, I guess

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
