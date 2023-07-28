/*
* TLS Client - implementation for TLS 1.2
* (C) 2004-2011 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CLIENT_IMPL_12_H_
#define BOTAN_TLS_CLIENT_IMPL_12_H_

#include <botan/credentials_manager.h>
#include <botan/tls_channel.h>
#include <botan/tls_policy.h>
#include <botan/internal/tls_channel_impl_12.h>
#include <memory>
#include <vector>

namespace Botan::TLS {

/**
* SSL/TLS Client 1.2 implementation
*/
class Client_Impl_12 : public Channel_Impl_12 {
   public:
      /**
      * Set up a new TLS client session
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
      * @param server_info is identifying information about the TLS server
      *
      * @param datagram specifies whether to use TLS 1.2 or DTLS 1.2
      *
      * @param next_protocols specifies protocols to advertise with ALPN
      *
      * @param reserved_io_buffer_size This many bytes of memory will
      *        be preallocated for the read and write buffers. Smaller
      *        values just mean reallocations and copies are more likely.
      */
      explicit Client_Impl_12(const std::shared_ptr<Callbacks>& callbacks,
                              const std::shared_ptr<Session_Manager>& session_manager,
                              const std::shared_ptr<Credentials_Manager>& creds,
                              const std::shared_ptr<const Policy>& policy,
                              const std::shared_ptr<RandomNumberGenerator>& rng,
                              Server_Information server_info = Server_Information(),
                              bool datagram = false,
                              const std::vector<std::string>& next_protocols = {},
                              size_t reserved_io_buffer_size = TLS::Channel::IO_BUF_DEFAULT_SIZE);

      explicit Client_Impl_12(const Channel_Impl::Downgrade_Information& downgrade_info);

      /**
      * @return network protocol as advertised by the TLS server, if server sent the ALPN extension
      */
      std::string application_protocol() const override { return m_application_protocol; }

   private:
      std::vector<X509_Certificate> get_peer_cert_chain(const Handshake_State& state) const override;

      void initiate_handshake(Handshake_State& state, bool force_full_renegotiation) override;

      void send_client_hello(Handshake_State& state,
                             bool force_full_renegotiation,
                             Protocol_Version version,
                             std::optional<Session_with_Handle> session_and_handle = std::nullopt,
                             const std::vector<std::string>& next_protocols = {});

      void process_handshake_msg(const Handshake_State* active_state,
                                 Handshake_State& pending_state,
                                 Handshake_Type type,
                                 const std::vector<uint8_t>& contents,
                                 bool epoch0_restart) override;

      std::unique_ptr<Handshake_State> new_handshake_state(std::unique_ptr<Handshake_IO> io) override;

      std::shared_ptr<Credentials_Manager> m_creds;
      const Server_Information m_info;
      std::string m_application_protocol;
};

}  // namespace Botan::TLS

#endif
