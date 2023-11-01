/*
* TLS Hello Request and Client Hello Messages
* (C) 2022 Jack Lloyd
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>

#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/internal/tls_reader.h>

namespace Botan::TLS {

Encrypted_Extensions::Encrypted_Extensions(const Client_Hello_13& client_hello, const Policy& policy, Callbacks& cb) {
   const auto& exts = client_hello.extensions();

   // RFC 8446 4.2.7
   //    As of TLS 1.3, servers are permitted to send the "supported_groups"
   //    extension to the client.  Clients [...] MAY use the information
   //    learned from a successfully completed handshake to change what groups
   //    they use in their "key_share" extension in subsequent connections.
   if(exts.has<Supported_Groups>()) {
      m_extensions.add(new Supported_Groups(policy.key_exchange_groups()));
   }

   const auto record_size_limit = policy.record_size_limit();
   const auto max_record_size = MAX_PLAINTEXT_SIZE + 1 /* encrypted content type byte */;
   if(exts.has<Record_Size_Limit>()) {
      // RFC 8449 4
      //    Endpoints SHOULD advertise the "record_size_limit" extension, even
      //    if they have no need to limit the size of records. [...]  For
      //    servers, this allows clients to know that their limit will be
      //    respected.
      m_extensions.add(new Record_Size_Limit(record_size_limit.value_or(max_record_size)));
   } else if(record_size_limit.has_value() && record_size_limit.value() < max_record_size) {
      // RFC 8449 4
      //    Endpoints SHOULD advertise the "record_size_limit" extension, even if
      //    they have no need to limit the size of records. For clients, this
      //    allows servers to advertise a limit at their discretion.
      throw TLS_Exception(Alert::MissingExtension,
                          "Server cannot enforce record size limit without the client supporting it");
   }

   // RFC 7250 4.2
   //    If the TLS server wants to request a certificate from the client
   //    (via the certificate_request message), it MUST include the
   //    client_certificate_type extension in the server hello.
   //    [...]
   //    If the server does not send a certificate_request payload [...],
   //    then the client_certificate_type payload in the server hello MUST be
   //    omitted.
   if(auto ch_client_cert_types = exts.get<Client_Certificate_Type>();
      ch_client_cert_types && policy.request_client_certificate_authentication()) {
      m_extensions.add(new Client_Certificate_Type(*ch_client_cert_types, policy));
   }

   // RFC 7250 4.2
   //    The server_certificate_type extension in the client hello indicates the
   //    types of certificates the client is able to process when provided by
   //    the server in a subsequent certificate payload. [...] With the
   //    server_certificate_type extension in the server hello, the TLS server
   //    indicates the certificate type carried in the Certificate payload.
   if(auto ch_server_cert_types = exts.get<Server_Certificate_Type>()) {
      m_extensions.add(new Server_Certificate_Type(*ch_server_cert_types, policy));
   }

   // RFC 6066 3
   //    A server that receives a client hello containing the "server_name"
   //    extension [...] SHALL include an extension of type "server_name" in the
   //    (extended) server hello. The "extension_data" field of this extension
   //    SHALL be empty.
   if(exts.has<Server_Name_Indicator>()) {
      m_extensions.add(new Server_Name_Indicator(""));
   }

   if(auto alpn_ext = exts.get<Application_Layer_Protocol_Notification>()) {
      const auto next_protocol = cb.tls_server_choose_app_protocol(alpn_ext->protocols());
      if(!next_protocol.empty()) {
         m_extensions.add(new Application_Layer_Protocol_Notification(next_protocol));
      }
   }

   // TODO: Implement handling for (at least)
   //       * SRTP

   cb.tls_modify_extensions(m_extensions, Connection_Side::Server, type());
}

Encrypted_Extensions::Encrypted_Extensions(const std::vector<uint8_t>& buf) {
   TLS_Data_Reader reader("encrypted extensions reader", buf);

   // Encrypted Extensions contains a list of extensions. This list may legally
   // be empty. However, in that case we should at least see a two-byte length
   // field that reads 0x00 0x00.
   if(buf.size() < 2) {
      throw TLS_Exception(Alert::DecodeError, "Server sent an empty Encrypted Extensions message");
   }

   m_extensions.deserialize(reader, Connection_Side::Server, type());

   // RFC 8446 4.2
   //    If an implementation receives an extension which it recognizes and
   //    which is not specified for the message in which it appears, it MUST
   //    abort the handshake with an "illegal_parameter" alert.
   //
   // Note that we cannot encounter any extensions that we don't recognize here,
   // since only extensions we previously offered are allowed in EE.
   const auto allowed_exts = std::set<Extension_Code>{
      // Allowed extensions listed in RFC 8446 and implemented in Botan
      Extension_Code::ServerNameIndication,
      // MAX_FRAGMENT_LENGTH
      Extension_Code::SupportedGroups,
      Extension_Code::UseSrtp,
      // HEARTBEAT
      Extension_Code::ApplicationLayerProtocolNegotiation,
      // RFC 7250
      Extension_Code::ClientCertificateType,
      Extension_Code::ServerCertificateType,
      // EARLY_DATA

      // Allowed extensions not listed in RFC 8446 but acceptable as Botan implements them
      Extension_Code::RecordSizeLimit,
   };
   if(m_extensions.contains_implemented_extensions_other_than(allowed_exts)) {
      throw TLS_Exception(Alert::IllegalParameter, "Encrypted Extensions contained an extension that is not allowed");
   }
}

std::vector<uint8_t> Encrypted_Extensions::serialize() const {
   return m_extensions.serialize(Connection_Side::Server);
}

}  // namespace Botan::TLS
