/*
* TLS Client - implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
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
      * @param next_protocols specifies protocols to advertise with ALPN
      */
      explicit Client_Impl_13(Callbacks& callbacks,
                              Session_Manager& session_manager,
                              Credentials_Manager& creds,
                              const Policy& policy,
                              RandomNumberGenerator& rng,
                              const Server_Information& server_info = Server_Information(),
                              const std::vector<std::string>& next_protocols = {});

      /**
      * @return network protocol as advertised by the TLS server, if server sent the ALPN extension
      */
      std::string application_protocol() const override;

      /**
      * @return certificate chain of the peer (may be empty)
      */
      std::vector<X509_Certificate> peer_cert_chain() const override;

   private:
      void process_handshake_msg(Handshake_Message_13 msg) override;
      void process_post_handshake_msg(Post_Handshake_Message_13 msg) override;
      void process_dummy_change_cipher_spec() override;

      bool handshake_finished() const override;
      bool prepend_ccs() override;

      void handle(const Server_Hello_12& server_hello_msg);
      void handle(const Server_Hello_13& server_hello_msg);
      void handle(const Hello_Retry_Request& hrr_msg);
      void handle(const Encrypted_Extensions& encrypted_extensions_msg);
      void handle(const Certificate_13& certificate_msg);
      void handle(const Certificate_Verify_13& certificate_verify_msg);
      void handle(const Finished_13& finished_msg);
      void handle(const New_Session_Ticket_13& new_session_ticket);
      void handle(const Key_Update& key_update);

   private:
      const Server_Information m_info;

      Client_Handshake_State_13 m_handshake_state;
      Handshake_Transitions m_transitions;

      bool m_should_send_ccs;
   };

}

}

#endif
