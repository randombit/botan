/*
* TLS Server - implementation for TLS 1.2
* (C) 2004-2011 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_SERVER_IMPL_12_H_
#define BOTAN_TLS_SERVER_IMPL_12_H_

#include <botan/credentials_manager.h>
#include <botan/tls_policy.h>
#include <botan/internal/tls_channel_impl_12.h>
#include <vector>

namespace Botan::TLS {

class Server_Handshake_State;

/**
* SSL/TLS Server 1.2 implementation
*/
class Server_Impl_12 : public Channel_Impl_12 {
   public:
      typedef std::function<std::string(std::vector<std::string>)> next_protocol_fn;

      /**
      * Server initialization
      *
      * @param callbacks contains a set of callback function references
      *        required by the TLS server.
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
      explicit Server_Impl_12(const std::shared_ptr<Callbacks>& callbacks,
                              const std::shared_ptr<Session_Manager>& session_manager,
                              const std::shared_ptr<Credentials_Manager>& creds,
                              const std::shared_ptr<const Policy>& policy,
                              const std::shared_ptr<RandomNumberGenerator>& rng,
                              bool is_datagram = false,
                              size_t reserved_io_buffer_size = TLS::Channel::IO_BUF_DEFAULT_SIZE);

      explicit Server_Impl_12(const Channel_Impl::Downgrade_Information& downgrade_info);

   private:
      /**
      * Return the protocol notification set by the client (using the
      * ALPN extension) for this connection, if any. This value is not
      * tied to the session and a later renegotiation of the same
      * session can choose a new protocol.
      */
      std::string application_protocol() const override { return m_next_protocol; }

      std::vector<X509_Certificate> get_peer_cert_chain(const Handshake_State& state) const override;

      void initiate_handshake(Handshake_State& state, bool force_full_renegotiation) override;

      void process_handshake_msg(const Handshake_State* active_state,
                                 Handshake_State& pending_state,
                                 Handshake_Type type,
                                 const std::vector<uint8_t>& contents,
                                 bool epoch0_restart) override;

      void process_client_hello_msg(const Handshake_State* active_state,
                                    Server_Handshake_State& pending_state,
                                    const std::vector<uint8_t>& contents,
                                    bool epoch0_restart);

      void process_certificate_msg(Server_Handshake_State& pending_state, const std::vector<uint8_t>& contents);

      void process_client_key_exchange_msg(Server_Handshake_State& pending_state, const std::vector<uint8_t>& contents);

      void process_change_cipher_spec_msg(Server_Handshake_State& pending_state);

      void process_certificate_verify_msg(Server_Handshake_State& pending_state,
                                          Handshake_Type type,
                                          const std::vector<uint8_t>& contents);

      void process_finished_msg(Server_Handshake_State& pending_state,
                                Handshake_Type type,
                                const std::vector<uint8_t>& contents);

      void session_resume(Server_Handshake_State& pending_state, const Session_with_Handle& session_info);

      void session_create(Server_Handshake_State& pending_state);

      std::unique_ptr<Handshake_State> new_handshake_state(std::unique_ptr<Handshake_IO> io) override;

      std::shared_ptr<Credentials_Manager> m_creds;
      std::string m_next_protocol;
};

}  // namespace Botan::TLS

#endif
