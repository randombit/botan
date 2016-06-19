/*
* TLS Client
* (C) 2004-2011 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CLIENT_H__
#define BOTAN_TLS_CLIENT_H__

#include <botan/tls_channel.h>
#include <botan/credentials_manager.h>
#include <vector>

namespace Botan {

namespace TLS {

/**
* SSL/TLS Client
*/
class BOTAN_DLL Client final : public Channel
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
      * @param properties holds server information and protocol related
      *        properties.
      *
      * @param reserved_io_buffer_size This many bytes of memory will
      *        be preallocated for the read and write buffers. Smaller
      *        values just mean reallocations and copies are more likely.
      */

     class Properties
        {
            /**
             * Stores TLS Client properties.
             *
             * @param server_info is identifying information about the TLS server
             *
             * @param protocol_version specifies which version we will offer
             *        to the TLS server.
             *
             * @param next_protocols specifies protocols to advertise with ALPN
             */

            public:
                Properties(const Server_Information& server_info
                              = Server_Information(),
                           const Protocol_Version protocol_version
                              = Protocol_Version::latest_tls_version(),
                           const std::vector<std::string>& next_versions
                              = {})
                    : m_server_info(server_info),
                      m_protocol_version(protocol_version),
                      m_next_protocols(next_versions) {}

                const Server_Information& get_server_info()
                   {
                   return m_server_info;
                   }

                const Protocol_Version& get_protocol_version()
                   {
                   return m_protocol_version;
                   }

                const std::vector<std::string>& get_next_protocols()
                   {
                   return m_next_protocols;
                   }

            private:
                const Server_Information& m_server_info;
                const Protocol_Version m_protocol_version;
                const std::vector<std::string>& m_next_protocols;
        };

      /**
       * DEPRECATED. This constructor is only provided for backward
       * compatibility and should not be used in new implementations.
       */
      BOTAN_DEPRECATED("Use TLS::Client(TLS::Callbacks ...)")
      Client(output_fn out,
             data_cb app_data_cb,
             alert_cb alert_cb,
             handshake_cb hs_cb,
             Session_Manager& session_manager,
             Credentials_Manager& creds,
             const Policy& policy,
             RandomNumberGenerator& rng,
             const Server_Information& server_info = Server_Information(),
             const Protocol_Version& offer_version = Protocol_Version::latest_tls_version(),
             const std::vector<std::string>& next_protocols = {},
             size_t reserved_io_buffer_size = TLS::Client::IO_BUF_DEFAULT_SIZE
         );

      /**
       * DEPRECATED. This constructor is only provided for backward
       * compatibility and should not be used in new implementations.
       */
      BOTAN_DEPRECATED("Use TLS::Client(TLS::Callbacks ...)")
      Client(output_fn out,
             data_cb app_data_cb,
             alert_cb alert_cb,
             handshake_cb hs_cb,
             handshake_msg_cb hs_msg_cb,
             Session_Manager& session_manager,
             Credentials_Manager& creds,
             const Policy& policy,
             RandomNumberGenerator& rng,
             const Server_Information& server_info = Server_Information(),
             const Protocol_Version& offer_version = Protocol_Version::latest_tls_version(),
             const std::vector<std::string>& next_protocols = {}
         );


     Client(const Callbacks& callbacks,
            Session_Manager& session_manager,
            Credentials_Manager& creds,
            const Policy& policy,
            RandomNumberGenerator& rng,
            Properties properties,
            size_t reserved_io_buffer_size = TLS::Client::IO_BUF_DEFAULT_SIZE
         );

      const std::string& application_protocol() const { return m_application_protocol; }
   private:
      void init(const Protocol_Version& protocol_version,
                const std::vector<std::string>& next_protocols);

      std::vector<X509_Certificate>
         get_peer_cert_chain(const Handshake_State& state) const override;

      void initiate_handshake(Handshake_State& state,
                              bool force_full_renegotiation) override;

      void send_client_hello(Handshake_State& state,
                             bool force_full_renegotiation,
                             Protocol_Version version,
                             const std::string& srp_identifier = "",
                             const std::vector<std::string>& next_protocols = {});

      void process_handshake_msg(const Handshake_State* active_state,
                                 Handshake_State& pending_state,
                                 Handshake_Type type,
                                 const std::vector<byte>& contents) override;

      Handshake_State* new_handshake_state(Handshake_IO* io) override;

      Credentials_Manager& m_creds;
      const Server_Information m_info;
      std::string m_application_protocol;
   };

}

}

#endif
