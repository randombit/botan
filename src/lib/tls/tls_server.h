/*
* TLS Server
* (C) 2004-2011 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_SERVER_H_
#define BOTAN_TLS_SERVER_H_

#include <botan/tls_channel.h>
#include <botan/tls_policy.h>
#include <botan/credentials_manager.h>
#include <vector>

namespace Botan {

namespace TLS {

class Server_Handshake_State;

class BOTAN_UNSTABLE_API DTLS_Prestate final
   {
   public:
      DTLS_Prestate() = default;

      DTLS_Prestate(bool validity,
                    uint16_t in_message_seq,
                    uint64_t in_record_seq,
                    uint16_t out_message_seq);

      bool cookie_valid() const;

   private:
      bool m_validity = false;
      uint16_t m_in_message_seq = 0;
      uint64_t m_in_record_seq = 0;
      uint16_t m_out_message_seq = 0;

      friend class Channel;
   };

/**
* TLS Server
*/
class BOTAN_PUBLIC_API(2,0) Server final : public Channel
   {
   public:
      typedef std::function<std::string (std::vector<std::string>)> next_protocol_fn;
      typedef std::function<void (const uint8_t[], size_t)> output_fn;

      /**
      * Server initialization
      *
      * @param callbacks contains a set of callback function references
      *        required by the TLS client.
      *
      * @param session_manager manages session state
      *
      * @param creds manages application/user credentials
      *
      * @param policy specifies other connection policy information
      *
      * @param rng a random number generator
      *
      * @param is_datagram set to true if this server should expect DTLS
      *        connections. Otherwise TLS connections are expected.
      *
      * @param reserved_io_buffer_size This many bytes of memory will
      *        be preallocated for the read and write buffers. Smaller
      *        values just mean reallocations and copies are more likely.
      */
      Server(Callbacks& callbacks,
             Session_Manager& session_manager,
             Credentials_Manager& creds,
             const Policy& policy,
             RandomNumberGenerator& rng,
             bool is_datagram = false,
             size_t reserved_io_buffer_size = TLS::Server::IO_BUF_DEFAULT_SIZE
         );

      /**
       * Server initialization with a DTLS prestate, which implies DTLS.
       * It is expected that received_data be called again with
       * the last message that passes pre_verify_cookie.
       */
      Server(Callbacks& callbacks,
             Session_Manager& session_manager,
             Credentials_Manager& creds,
             const Policy& policy,
             RandomNumberGenerator& rng,
             DTLS_Prestate& prestate,
             size_t reserved_io_buffer_size = TLS::Server::IO_BUF_DEFAULT_SIZE
         );

      /**
       * DEPRECATED. This constructor is only provided for backward
       * compatibility and should not be used in new implementations.
       * It will be removed in a future release.
       */
      BOTAN_DEPRECATED("Use TLS::Server(TLS::Callbacks ...)")
      Server(output_fn output,
             data_cb data_cb,
             alert_cb recv_alert_cb,
             handshake_cb hs_cb,
             Session_Manager& session_manager,
             Credentials_Manager& creds,
             const Policy& policy,
             RandomNumberGenerator& rng,
             next_protocol_fn next_proto = next_protocol_fn(),
             bool is_datagram = false,
             size_t reserved_io_buffer_size = TLS::Server::IO_BUF_DEFAULT_SIZE
         );

      /**
       * DEPRECATED. This constructor is only provided for backward
       * compatibility and should not be used in new implementations.
       * It will be removed in a future release.
       */
      BOTAN_DEPRECATED("Use TLS::Server(TLS::Callbacks ...)")
      Server(output_fn output,
             data_cb data_cb,
             alert_cb recv_alert_cb,
             handshake_cb hs_cb,
             handshake_msg_cb hs_msg_cb,
             Session_Manager& session_manager,
             Credentials_Manager& creds,
             const Policy& policy,
             RandomNumberGenerator& rng,
             next_protocol_fn next_proto = next_protocol_fn(),
             bool is_datagram = false
         );

      /**
      * Return the protocol notification set by the client (using the
      * ALPN extension) for this connection, if any. This value is not
      * tied to the session and a later renegotiation of the same
      * session can choose a new protocol.
      */
      std::string next_protocol() const { return m_next_protocol; }

      /**
      * Return the protocol notification set by the client (using the
      * ALPN extension) for this connection, if any. This value is not
      * tied to the session and a later renegotiation of the same
      * session can choose a new protocol.
      */
      std::string application_protocol() const override { return m_next_protocol; }

      /**
      * Verify whether a Client Hello message has a correct session cookie.
      * Returns the prestate associated with the Client Hello.
      * Use DTLS_Prestate::cookie_valid to check the result.
      */
      static DTLS_Prestate pre_verify_cookie(
         Credentials_Manager& creds,
         const Policy& policy,
         const std::string& client_identity,
         const uint8_t input[],
         size_t buf_size,
         output_fn emit_data_fn);

   private:
      std::vector<X509_Certificate>
         get_peer_cert_chain(const Handshake_State& state) const override;

      void initiate_handshake(Handshake_State& state,
                              bool force_full_renegotiation) override;

      void process_handshake_msg(const Handshake_State* active_state,
                                 Handshake_State& pending_state,
                                 Handshake_Type type,
                                 const std::vector<uint8_t>& contents,
                                 bool epoch0_restart) override;

      void process_client_hello_msg(const Handshake_State* active_state,
                                    Server_Handshake_State& pending_state,
                                    const std::vector<uint8_t>& contents,
                                    bool epoch0_restart);

      void process_certificate_msg(Server_Handshake_State& pending_state,
                                   const std::vector<uint8_t>& contents);

      void process_client_key_exchange_msg(Server_Handshake_State& pending_state,
                                           const std::vector<uint8_t>& contents);

      void process_change_cipher_spec_msg(Server_Handshake_State& pending_state);

      void process_certificate_verify_msg(Server_Handshake_State& pending_state,
                                          Handshake_Type type,
                                          const std::vector<uint8_t>& contents);

      void process_finished_msg(Server_Handshake_State& pending_state,
                                Handshake_Type type,
                                const std::vector<uint8_t>& contents);

      void session_resume(Server_Handshake_State& pending_state,
                          bool have_session_ticket_key,
                          Session& session_info);

      void session_create(Server_Handshake_State& pending_state,
                          bool have_session_ticket_key);

      Handshake_State* new_handshake_state(Handshake_IO* io) override;

      Credentials_Manager& m_creds;
      std::string m_next_protocol;

      // Set by deprecated constructor, Server calls both this fn and Callbacks version
      next_protocol_fn m_choose_next_protocol;
   };

}

}

#endif
