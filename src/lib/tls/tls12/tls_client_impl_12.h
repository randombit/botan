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
#include <botan/internal/tls_channel_impl_12.h>
#include <memory>
#include <vector>

namespace Botan::TLS {

/**
* SSL/TLS Client 1.2 implementation
*/
class Client_Impl_12 final : public Channel_Impl_12 {
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
      static std::shared_ptr<Client_Impl_12> create(const std::shared_ptr<Callbacks>& callbacks,
                                                    const std::shared_ptr<Session_Manager>& session_manager,
                                                    const std::shared_ptr<Credentials_Manager>& creds,
                                                    const std::shared_ptr<const Policy>& policy,
                                                    const std::shared_ptr<RandomNumberGenerator>& rng,
                                                    Server_Information server_info = Server_Information(),
                                                    bool datagram = false,
                                                    const std::vector<std::string>& next_protocols = {},
                                                    size_t reserved_io_buffer_size = TLS::Channel::IO_BUF_DEFAULT_SIZE);

      Client_Impl_12([[maybe_unused]] Private dont_call_me,
                     const std::shared_ptr<Callbacks>& callbacks,
                     const std::shared_ptr<Session_Manager>& session_manager,
                     const std::shared_ptr<Credentials_Manager>& creds,
                     const std::shared_ptr<const Policy>& policy,
                     const std::shared_ptr<RandomNumberGenerator>& rng,
                     Server_Information server_info,
                     bool datagram,
                     size_t reserved_io_buffer_size) :
            Channel_Impl_12(callbacks, session_manager, rng, policy, false, datagram, reserved_io_buffer_size),
            m_creds(creds),
            m_info(std::move(server_info)) {}

#if defined(BOTAN_HAS_TLS_DOWNGRADE_SUPPORT)

      static std::shared_ptr<Client_Impl_12> create_for_downgrade(Channel_Impl::Downgrade_Information& downgrade_info);

      Client_Impl_12([[maybe_unused]] Private dont_call_me, Channel_Impl::Downgrade_Information& downgrade_info) :
            Channel_Impl_12(downgrade_info.callbacks,
                            downgrade_info.session_manager,
                            downgrade_info.rng,
                            downgrade_info.policy,
                            false /* is_server */,
                            false /* datagram -- not supported by Botan in TLS 1.3 */,
                            downgrade_info.io_buffer_size),
            m_creds(downgrade_info.creds),
            m_info(downgrade_info.server_info) {}

#endif

      /**
      * @return network protocol as advertised by the TLS server, if server sent the ALPN extension
      */
      std::string application_protocol() const override { return m_application_protocol; }

   private:
      void initiate_handshake(Handshake_State& state, bool force_full_renegotiation) override;

      void send_client_hello(Handshake_State& state,
                             bool force_full_renegotiation,
                             Protocol_Version version,
                             std::optional<Session_with_Handle> session_and_handle = std::nullopt,
                             const std::vector<std::string>& next_protocols = {});

      void process_handshake_msg(Handshake_State& pending_state,
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
