/*
* TLS Server Hello and Server Hello Done
* (C) 2004-2011,2015,2016,2019 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages_12.h>

#include <botan/tls_callbacks.h>
#include <botan/tls_extensions_12.h>
#include <botan/tls_policy.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_messages_internal.h>

namespace Botan::TLS {

// New session case
Server_Hello_12::Server_Hello_12(Handshake_IO& io,
                                 Handshake_Hash& hash,
                                 const Policy& policy,
                                 Callbacks& cb,
                                 RandomNumberGenerator& rng,
                                 const std::vector<uint8_t>& reneg_info,
                                 const Client_Hello_12& client_hello,
                                 const Server_Hello_12::Settings& server_settings,
                                 std::string_view next_protocol) :
      Server_Hello_12(std::make_unique<Server_Hello_Internal>(
         server_settings.protocol_version(),
         server_settings.session_id(),
         make_server_hello_random(rng, server_settings.protocol_version(), cb, policy),
         server_settings.ciphersuite(),
         uint8_t(0))) {
   // NOLINTBEGIN(*-owning-memory)
   if(client_hello.supports_extended_master_secret()) {
      m_data->extensions().add(new Extended_Master_Secret);
   }

   // Sending the extension back does not commit us to sending a stapled response
   if(client_hello.supports_cert_status_message() && policy.support_cert_status_message()) {
      m_data->extensions().add(new Certificate_Status_Request);
   }

   if(!next_protocol.empty() && client_hello.supports_alpn()) {
      m_data->extensions().add(new Application_Layer_Protocol_Notification(next_protocol));
   }

   const auto c = Ciphersuite::by_id(m_data->ciphersuite());

   if(c && c->cbc_ciphersuite() && client_hello.supports_encrypt_then_mac() && policy.negotiate_encrypt_then_mac()) {
      m_data->extensions().add(new Encrypt_then_MAC);
   }

   if(c && c->ecc_ciphersuite() && client_hello.extension_types().contains(Extension_Code::EcPointFormats)) {
      m_data->extensions().add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
   }

   if(client_hello.secure_renegotiation()) {
      m_data->extensions().add(new Renegotiation_Extension(reneg_info));
   }

   if(client_hello.supports_session_ticket() && server_settings.offer_session_ticket()) {
      m_data->extensions().add(new Session_Ticket_Extension());
   }

   if(m_data->legacy_version().is_datagram_protocol()) {
      const std::vector<uint16_t> server_srtp = policy.srtp_profiles();
      const std::vector<uint16_t> client_srtp = client_hello.srtp_profiles();

      if(!server_srtp.empty() && !client_srtp.empty()) {
         uint16_t shared = 0;
         // always using server preferences for now
         for(auto s_srtp : server_srtp) {
            for(auto c_srtp : client_srtp) {
               if(shared == 0 && s_srtp == c_srtp) {
                  shared = s_srtp;
               }
            }
         }

         if(shared != 0) {
            m_data->extensions().add(new SRTP_Protection_Profiles(shared));
         }
      }
   }
   // NOLINTEND(*-owning-memory)

   cb.tls_modify_extensions(m_data->extensions(), Connection_Side::Server, type());

   hash.update(io.send(*this));
}

// Resuming
Server_Hello_12::Server_Hello_12(Handshake_IO& io,
                                 Handshake_Hash& hash,
                                 const Policy& policy,
                                 Callbacks& cb,
                                 RandomNumberGenerator& rng,
                                 const std::vector<uint8_t>& reneg_info,
                                 const Client_Hello_12& client_hello,
                                 const Session& resumed_session,
                                 bool offer_session_ticket,
                                 std::string_view next_protocol) :
      Server_Hello_12(std::make_unique<Server_Hello_Internal>(resumed_session.version(),
                                                              client_hello.session_id(),
                                                              make_hello_random(rng, cb, policy),
                                                              resumed_session.ciphersuite_code(),
                                                              uint8_t(0))) {
   // NOLINTBEGIN(*-owning-memory)
   if(client_hello.supports_extended_master_secret()) {
      m_data->extensions().add(new Extended_Master_Secret);
   }

   if(!next_protocol.empty() && client_hello.supports_alpn()) {
      m_data->extensions().add(new Application_Layer_Protocol_Notification(next_protocol));
   }

   if(client_hello.supports_encrypt_then_mac() && policy.negotiate_encrypt_then_mac()) {
      const Ciphersuite c = resumed_session.ciphersuite();
      if(c.cbc_ciphersuite()) {
         m_data->extensions().add(new Encrypt_then_MAC);
      }
   }

   if(resumed_session.ciphersuite().ecc_ciphersuite() &&
      client_hello.extension_types().contains(Extension_Code::EcPointFormats)) {
      m_data->extensions().add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
   }

   if(client_hello.secure_renegotiation()) {
      m_data->extensions().add(new Renegotiation_Extension(reneg_info));
   }

   if(client_hello.supports_session_ticket() && offer_session_ticket) {
      m_data->extensions().add(new Session_Ticket_Extension());
   }
   // NOLINTEND(*-owning-memory)

   cb.tls_modify_extensions(m_data->extensions(), Connection_Side::Server, type());

   hash.update(io.send(*this));
}

Server_Hello_12::Server_Hello_12(const std::vector<uint8_t>& buf) :
      Server_Hello_12(std::make_unique<Server_Hello_Internal>(buf)) {}

Server_Hello_12::Server_Hello_12(std::unique_ptr<Server_Hello_Internal> data) : Server_Hello_12_Shim(std::move(data)) {}

bool Server_Hello_12::secure_renegotiation() const {
   return m_data->extensions().has<Renegotiation_Extension>();
}

std::vector<uint8_t> Server_Hello_12::renegotiation_info() const {
   if(const Renegotiation_Extension* reneg = m_data->extensions().get<Renegotiation_Extension>()) {
      return reneg->renegotiation_info();
   }
   return std::vector<uint8_t>();
}

bool Server_Hello_12::supports_extended_master_secret() const {
   return m_data->extensions().has<Extended_Master_Secret>();
}

bool Server_Hello_12::supports_encrypt_then_mac() const {
   return m_data->extensions().has<Encrypt_then_MAC>();
}

bool Server_Hello_12::supports_certificate_status_message() const {
   return m_data->extensions().has<Certificate_Status_Request>();
}

bool Server_Hello_12::supports_session_ticket() const {
   return m_data->extensions().has<Session_Ticket_Extension>();
}

uint16_t Server_Hello_12::srtp_profile() const {
   if(auto* srtp = m_data->extensions().get<SRTP_Protection_Profiles>()) {
      auto prof = srtp->profiles();
      if(prof.size() != 1 || prof[0] == 0) {
         throw Decoding_Error("Server sent malformed DTLS-SRTP extension");
      }
      return prof[0];
   }

   return 0;
}

std::string Server_Hello_12::next_protocol() const {
   if(auto* alpn = m_data->extensions().get<Application_Layer_Protocol_Notification>()) {
      return alpn->single_protocol();
   }
   return "";
}

bool Server_Hello_12::prefers_compressed_ec_points() const {
   if(auto* ecc_formats = m_data->extensions().get<Supported_Point_Formats>()) {
      return ecc_formats->prefers_compressed();
   }
   return false;
}

/*
* Create a new Server Hello Done message
*/
Server_Hello_Done::Server_Hello_Done(Handshake_IO& io, Handshake_Hash& hash) {
   hash.update(io.send(*this));
}

/*
* Deserialize a Server Hello Done message
*/
Server_Hello_Done::Server_Hello_Done(const std::vector<uint8_t>& buf) {
   if(!buf.empty()) {
      throw Decoding_Error("Server_Hello_Done: Must be empty, and is not");
   }
}

/*
* Serialize a Server Hello Done message
*/
std::vector<uint8_t> Server_Hello_Done::serialize() const {
   return std::vector<uint8_t>();
}

}  // namespace Botan::TLS
