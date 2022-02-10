/*
* TLS Client - implementation for TLS 1.3
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CLIENT_IMPL_13_H_
#define BOTAN_TLS_CLIENT_IMPL_13_H_

#include <botan/internal/tls_channel_impl_13.h>
#include <botan/internal/tls_handshake_state_13.h>
#include <botan/internal/tls_handshake_transitions.h>
#include <botan/tls_server_info.h>

namespace Botan {

class Credentials_Manager;
namespace TLS {

/**
* SSL/TLS Client 1.3 implementation
*/
class Client_Impl_13 : public Channel_Impl_13
   {
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
      * @param offer_version specifies which version we will offer
      *        to the TLS server.
      *
      * @param next_protocols specifies protocols to advertise with ALPN
      *
      * @param reserved_io_buffer_size This many bytes of memory will
      *        be preallocated for the read and write buffers. Smaller
      *        values just mean reallocations and copies are more likely.
      */
      explicit Client_Impl_13(Callbacks& callbacks,
                              Session_Manager& session_manager,
                              Credentials_Manager& creds,
                              const Policy& policy,
                              RandomNumberGenerator& rng,
                              const Server_Information& server_info = Server_Information(),
                              const Protocol_Version& offer_version = Protocol_Version::latest_tls_version(),
                              const std::vector<std::string>& next_protocols = {},
                              size_t reserved_io_buffer_size = TLS::Channel::IO_BUF_DEFAULT_SIZE);

      /**
      * @return network protocol as advertised by the TLS server, if server sent the ALPN extension
      */
      std::string application_protocol() const override { return m_application_protocol; }

   private:
      void process_handshake_msg(Handshake_Message_13 msg) override;

      void send_client_hello(const std::vector<std::string>& next_protocols = {});

      void handle(const Server_Hello_13& server_hello_msg);
      void handle(const Encrypted_Extensions& encrypted_extensions_msg);
      void handle(const Certificate_13& certificate_msg);
      void handle(const Certificate_Verify_13& certificate_verify_msg);
      void handle(const Finished_13& finished_msg);
      void handle(const New_Session_Ticket_13& new_session_ticket);

      std::vector<Handshake_Type> expected_post_handshake_messages() const;

   private:
      Credentials_Manager& m_creds;
      const Server_Information m_info;
      std::string m_application_protocol;

      Client_Handshake_State_13 m_handshake_state;
      Handshake_Transitions m_transitions;
   };

}

}

#endif
