/*
* TLS Client - implementation for TLS 1.3
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CLIENT_IMPL_13_H_
#define BOTAN_TLS_CLIENT_IMPL_13_H_

#include <botan/internal/tls_client_impl.h>
#include <botan/internal/tls_channel_impl_13.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/tls_server_info.h>

namespace Botan {

class Credentials_Manager;
namespace TLS {

namespace {

class Client_Handshake_State final : public Handshake_State
   {
   public:
      Client_Handshake_State(std::unique_ptr<Handshake_IO> io, Callbacks& cb) :
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


/**
* SSL/TLS Client 1.3 implementation
*/
class Client_Impl_13 : public Channel_Impl_13, public Client_Impl
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
      std::vector<X509_Certificate>
         get_peer_cert_chain(const Handshake_State& state) const override;

      void initiate_handshake(Handshake_State& state,
                              bool force_full_renegotiation) override;

      void process_handshake_msg(const Handshake_State* active_state,
                                 Handshake_State& pending_state,
                                 Handshake_Type type,
                                 const std::vector<uint8_t>& contents,
                                 bool epoch0_restart) override;

      std::unique_ptr<Handshake_State> new_handshake_state(std::unique_ptr<Handshake_IO> io) override;

      void send_client_hello(Handshake_State& state,
                             Protocol_Version version,
                             const std::vector<std::string>& next_protocols = {});

   private:
      Credentials_Manager& m_creds;
      const Server_Information m_info;
      std::string m_application_protocol;
   };

}

}

#endif
