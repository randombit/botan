/*
* TLS Hello Request and Client Hello Messages
* (C) 2004-2011,2015,2016 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages_12.h>

#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_extensions_12.h>
#include <botan/tls_policy.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_messages_internal.h>

namespace Botan::TLS {

void Client_Hello_12::update_hello_cookie(const Hello_Verify_Request& hello_verify) {
   BOTAN_STATE_CHECK(m_data->legacy_version().is_datagram_protocol());

   m_data->m_hello_cookie = hello_verify.cookie();
}

bool Client_Hello_12::prefers_compressed_ec_points() const {
   if(const Supported_Point_Formats* ecc_formats = m_data->extensions().get<Supported_Point_Formats>()) {
      return ecc_formats->prefers_compressed();
   }
   return false;
}

bool Client_Hello_12::secure_renegotiation() const {
   return m_data->extensions().has<Renegotiation_Extension>();
}

std::vector<uint8_t> Client_Hello_12::renegotiation_info() const {
   if(const Renegotiation_Extension* reneg = m_data->extensions().get<Renegotiation_Extension>()) {
      return reneg->renegotiation_info();
   }
   return {};
}

bool Client_Hello_12::supports_session_ticket() const {
   return m_data->extensions().has<Session_Ticket_Extension>();
}

Session_Ticket Client_Hello_12::session_ticket() const {
   if(auto* ticket = m_data->extensions().get<Session_Ticket_Extension>()) {
      return ticket->contents();
   }
   return {};
}

std::optional<Session_Handle> Client_Hello_12::session_handle() const {
   // RFC 5077 3.4
   //    If a ticket is presented by the client, the server MUST NOT attempt
   //    to use the Session ID in the ClientHello for stateful session
   //    resumption.
   if(auto ticket = session_ticket(); !ticket.empty()) {
      return Session_Handle(ticket);
   } else if(const auto& id = session_id(); !id.empty()) {
      return Session_Handle(id);
   } else {
      return std::nullopt;
   }
}

bool Client_Hello_12::supports_extended_master_secret() const {
   return m_data->extensions().has<Extended_Master_Secret>();
}

bool Client_Hello_12::supports_cert_status_message() const {
   return m_data->extensions().has<Certificate_Status_Request>();
}

bool Client_Hello_12::supports_encrypt_then_mac() const {
   return m_data->extensions().has<Encrypt_then_MAC>();
}

void Client_Hello_12::add_tls12_supported_groups_extensions(const Policy& policy) {
   // RFC 7919 3.
   //    A client that offers a group MUST be able and willing to perform a DH
   //    key exchange using that group.
   //
   // We don't support hybrid key exchange in TLS 1.2

   std::vector<Group_Params> compatible_kex_groups;
   for(const auto& group : policy.key_exchange_groups()) {
      if(!group.is_post_quantum()) {
         compatible_kex_groups.push_back(group);
      }
   }

   auto supported_groups = std::make_unique<Supported_Groups>(std::move(compatible_kex_groups));

   if(!supported_groups->ec_groups().empty()) {
      // NOLINTNEXTLINE(*-owning-memory)
      m_data->extensions().add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
   }

   m_data->extensions().add(std::move(supported_groups));
}

/*
* Create a new Client Hello message
*/
Client_Hello_12::Client_Hello_12(Handshake_IO& io,
                                 Handshake_Hash& hash,
                                 const Policy& policy,
                                 Callbacks& cb,
                                 RandomNumberGenerator& rng,
                                 const std::vector<uint8_t>& reneg_info,
                                 const Client_Hello_12::Settings& client_settings,
                                 const std::vector<std::string>& next_protocols) {
   m_data->m_legacy_version = client_settings.protocol_version();
   m_data->m_random = make_hello_random(rng, cb, policy);
   m_data->m_suites = policy.ciphersuite_list(client_settings.protocol_version());

   if(!policy.acceptable_protocol_version(m_data->legacy_version())) {
      throw Internal_Error("Offering " + m_data->legacy_version().to_string() +
                           " but our own policy does not accept it");
   }

   /*
    * Place all empty extensions in front to avoid a bug in some systems
    * which reject hellos when the last extension in the list is empty.
    */

   // NOLINTBEGIN(*-owning-memory)

   // EMS must always be used with TLS 1.2, regardless of the policy used.

   m_data->extensions().add(new Extended_Master_Secret);

   if(policy.negotiate_encrypt_then_mac()) {
      m_data->extensions().add(new Encrypt_then_MAC);
   }

   m_data->extensions().add(new Session_Ticket_Extension());

   m_data->extensions().add(new Renegotiation_Extension(reneg_info));

   m_data->extensions().add(new Supported_Versions(m_data->legacy_version(), policy));

   if(Server_Name_Indicator::hostname_acceptable_for_sni(client_settings.hostname())) {
      m_data->extensions().add(new Server_Name_Indicator(client_settings.hostname()));
   }

   if(policy.support_cert_status_message()) {
      m_data->extensions().add(new Certificate_Status_Request({}, {}));
   }

   add_tls12_supported_groups_extensions(policy);

   m_data->extensions().add(new Signature_Algorithms(policy.acceptable_signature_schemes()));
   if(auto cert_signing_prefs = policy.acceptable_certificate_signature_schemes()) {
      // RFC 8446 4.2.3
      //    TLS 1.2 implementations SHOULD also process this extension.
      //    Implementations which have the same policy in both cases MAY omit
      //    the "signature_algorithms_cert" extension.
      m_data->extensions().add(new Signature_Algorithms_Cert(std::move(cert_signing_prefs.value())));
   }

   if(reneg_info.empty() && !next_protocols.empty()) {
      m_data->extensions().add(new Application_Layer_Protocol_Notification(next_protocols));
   }

   if(m_data->legacy_version().is_datagram_protocol()) {
      m_data->extensions().add(new SRTP_Protection_Profiles(policy.srtp_profiles()));
   }

   // NOLINTEND(*-owning-memory)

   cb.tls_modify_extensions(m_data->extensions(), Connection_Side::Client, type());

   hash.update(io.send(*this));
}

/*
* Create a new Client Hello message (session resumption case)
*/
Client_Hello_12::Client_Hello_12(Handshake_IO& io,
                                 Handshake_Hash& hash,
                                 const Policy& policy,
                                 Callbacks& cb,
                                 RandomNumberGenerator& rng,
                                 const std::vector<uint8_t>& reneg_info,
                                 const Session_with_Handle& session,
                                 const std::vector<std::string>& next_protocols) {
   m_data->m_legacy_version = session.session.version();
   m_data->m_random = make_hello_random(rng, cb, policy);

   // RFC 5077 3.4
   //    When presenting a ticket, the client MAY generate and include a
   //    Session ID in the TLS ClientHello. [...] If a ticket is presented by
   //    the client, the server MUST NOT attempt to use the Session ID in the
   //    ClientHello for stateful session resumption.
   m_data->m_session_id = session.handle.id().value_or(Session_ID(make_hello_random(rng, cb, policy)));
   m_data->m_suites = policy.ciphersuite_list(m_data->legacy_version());

   if(!policy.acceptable_protocol_version(session.session.version())) {
      throw Internal_Error("Offering " + m_data->legacy_version().to_string() +
                           " but our own policy does not accept it");
   }

   if(!value_exists(m_data->ciphersuites(), session.session.ciphersuite_code())) {
      m_data->m_suites.push_back(session.session.ciphersuite_code());
   }

   /*
    * As EMS must always be used with TLS 1.2, add it even if it wasn't used
    * in the original session. If the server understands it and follows the
    * RFC it should reject our resume attempt and upgrade us to a new session
    * with the EMS protection.
    */
   // NOLINTBEGIN(*-owning-memory)
   m_data->extensions().add(new Extended_Master_Secret);

   if(session.session.supports_encrypt_then_mac()) {
      m_data->extensions().add(new Encrypt_then_MAC);
   }

   if(session.handle.is_ticket()) {
      m_data->extensions().add(new Session_Ticket_Extension(session.handle.ticket().value()));
   }

   m_data->extensions().add(new Renegotiation_Extension(reneg_info));

   const std::string hostname = session.session.server_info().hostname();

   if(Server_Name_Indicator::hostname_acceptable_for_sni(hostname)) {
      m_data->extensions().add(new Server_Name_Indicator(hostname));
   }

   if(policy.support_cert_status_message()) {
      m_data->extensions().add(new Certificate_Status_Request({}, {}));
   }

   add_tls12_supported_groups_extensions(policy);

   m_data->extensions().add(new Signature_Algorithms(policy.acceptable_signature_schemes()));
   if(auto cert_signing_prefs = policy.acceptable_certificate_signature_schemes()) {
      // RFC 8446 4.2.3
      //    TLS 1.2 implementations SHOULD also process this extension.
      //    Implementations which have the same policy in both cases MAY omit
      //    the "signature_algorithms_cert" extension.
      m_data->extensions().add(new Signature_Algorithms_Cert(std::move(cert_signing_prefs.value())));
   }

   if(reneg_info.empty() && !next_protocols.empty()) {
      m_data->extensions().add(new Application_Layer_Protocol_Notification(next_protocols));
   }
   // NOLINTEND(*-owning-memory)

   cb.tls_modify_extensions(m_data->extensions(), Connection_Side::Client, type());

   hash.update(io.send(*this));
}

Client_Hello_12::Client_Hello_12(const std::vector<uint8_t>& buf) :
      Client_Hello_12(std::make_unique<Client_Hello_Internal>(buf)) {}

Client_Hello_12::Client_Hello_12(std::unique_ptr<Client_Hello_Internal> data) : Client_Hello_12_Shim(std::move(data)) {
   const uint16_t TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF;

   if(offered_suite(static_cast<uint16_t>(TLS_EMPTY_RENEGOTIATION_INFO_SCSV))) {
      if(const Renegotiation_Extension* reneg = m_data->extensions().get<Renegotiation_Extension>()) {
         if(!reneg->renegotiation_info().empty()) {
            throw TLS_Exception(Alert::HandshakeFailure, "Client sent renegotiation SCSV and non-empty extension");
         }
      } else {
         // add fake extension
         m_data->extensions().add(new Renegotiation_Extension());  // NOLINT(*-owning-memory)
      }
   }
}

Hello_Request::Hello_Request(Handshake_IO& io) {
   io.send(*this);
}

Hello_Request::Hello_Request(const std::vector<uint8_t>& buf) {
   if(!buf.empty()) {
      throw Decoding_Error("Bad Hello_Request, has non-zero size");
   }
}

std::vector<uint8_t> Hello_Request::serialize() const {
   return std::vector<uint8_t>();
}

}  // namespace Botan::TLS
