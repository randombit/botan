/*
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>

#include <botan/credentials_manager.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/internal/tls_reader.h>

namespace Botan::TLS {

Handshake_Type Certificate_Request_13::type() const {
   return TLS::Handshake_Type::CertificateRequest;
}

Certificate_Request_13::Certificate_Request_13(const std::vector<uint8_t>& buf, const Connection_Side side) {
   TLS_Data_Reader reader("Certificate_Request_13", buf);

   // RFC 8446 4.3.2
   //    A server which is authenticating with a certificate MAY optionally
   //    request a certificate from the client.
   if(side != Connection_Side::Server) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Received a Certificate_Request message from a client");
   }

   m_context = reader.get_tls_length_value(1);
   m_extensions.deserialize(reader, side, type());

   // RFC 8446 4.3.2
   //    The "signature_algorithms" extension MUST be specified, and other
   //    extensions may optionally be included if defined for this message.
   //    Clients MUST ignore unrecognized extensions.

   if(!m_extensions.has<Signature_Algorithms>()) {
      throw TLS_Exception(Alert::MissingExtension,
                          "Certificate_Request message did not provide a signature_algorithms extension");
   }

   // RFC 8446 4.2.
   //    The table below indicates the messages where a given extension may
   //    appear [...].  If an implementation receives an extension which it
   //    recognizes and which is not specified for the message in which it
   //    appears, it MUST abort the handshake with an "illegal_parameter" alert.
   //
   // For Certificate Request said table states:
   //    "status_request", "signature_algorithms", "signed_certificate_timestamp",
   //     "certificate_authorities", "oid_filters", "signature_algorithms_cert",
   std::set<Extension_Code> allowed_extensions = {
      Extension_Code::CertificateStatusRequest,
      Extension_Code::SignatureAlgorithms,
      // Extension_Code::SignedCertificateTimestamp,  // NYI
      Extension_Code::CertificateAuthorities,
      // Extension_Code::OidFilters,                   // NYI
      Extension_Code::CertSignatureAlgorithms,
   };

   if(m_extensions.contains_implemented_extensions_other_than(allowed_extensions)) {
      throw TLS_Exception(Alert::IllegalParameter, "Certificate Request contained an extension that is not allowed");
   }
}

Certificate_Request_13::Certificate_Request_13(std::vector<X509_DN> acceptable_CAs,
                                               const Policy& policy,
                                               Callbacks& callbacks) {
   // RFC 8446 4.3.2
   //    The certificate_request_context [here: m_context] MUST be unique within
   //    the scope of this connection (thus preventing replay of client
   //    CertificateVerify messages).  This field SHALL be zero length unless
   //    used for the post-handshake authentication exchanges described in
   //    Section 4.6.2.
   //
   // TODO: Post-Handshake auth must fill m_context in an unpredictable way

   // RFC 8446 4.3.2
   //    [Supported signature algorithms are] expressed by sending the
   //    "signature_algorithms" and optionally "signature_algorithms_cert"
   //    extensions. [A list of certificate authorities which the server would
   //    accept] is expressed by sending the "certificate_authorities" extension.
   //
   //    The "signature_algorithms" extension MUST be specified, and other
   //    extensions may optionally be included if defined for this message.
   m_extensions.add(std::make_unique<Signature_Algorithms>(policy.acceptable_signature_schemes()));
   if(auto cert_signing_prefs = policy.acceptable_certificate_signature_schemes()) {
      // RFC 8446 4.2.3
      //    Implementations which have the same policy in both cases MAY omit
      //    the "signature_algorithms_cert" extension.
      m_extensions.add(std::make_unique<Signature_Algorithms_Cert>(std::move(cert_signing_prefs.value())));
   }

   if(!acceptable_CAs.empty()) {
      m_extensions.add(std::make_unique<Certificate_Authorities>(std::move(acceptable_CAs)));
   }

   // TODO: Support cert_status_request for OCSP stapling

   callbacks.tls_modify_extensions(m_extensions, Connection_Side::Server, type());
}

std::optional<Certificate_Request_13> Certificate_Request_13::maybe_create(const Client_Hello_13& client_hello,
                                                                           Credentials_Manager& cred_mgr,
                                                                           Callbacks& callbacks,
                                                                           const Policy& policy) {
   const auto trusted_CAs = cred_mgr.trusted_certificate_authorities("tls-server", client_hello.sni_hostname());

   std::vector<X509_DN> client_auth_CAs;
   for(const auto store : trusted_CAs) {
      const auto subjects = store->all_subjects();
      client_auth_CAs.insert(client_auth_CAs.end(), subjects.begin(), subjects.end());
   }

   if(client_auth_CAs.empty() && !policy.request_client_certificate_authentication()) {
      return std::nullopt;
   }

   return Certificate_Request_13(std::move(client_auth_CAs), policy, callbacks);
}

std::vector<X509_DN> Certificate_Request_13::acceptable_CAs() const {
   if(m_extensions.has<Certificate_Authorities>()) {
      return m_extensions.get<Certificate_Authorities>()->distinguished_names();
   }
   return {};
}

const std::vector<Signature_Scheme>& Certificate_Request_13::signature_schemes() const {
   // RFC 8446 4.3.2
   //    The "signature_algorithms" extension MUST be specified
   BOTAN_ASSERT_NOMSG(m_extensions.has<Signature_Algorithms>());

   return m_extensions.get<Signature_Algorithms>()->supported_schemes();
}

const std::vector<Signature_Scheme>& Certificate_Request_13::certificate_signature_schemes() const {
   // RFC 8446 4.2.3
   //   If no "signature_algorithms_cert" extension is present, then the
   //   "signature_algorithms" extension also applies to signatures appearing
   //   in certificates.
   if(auto sig_schemes_cert = m_extensions.get<Signature_Algorithms_Cert>()) {
      return sig_schemes_cert->supported_schemes();
   } else {
      return signature_schemes();
   }
}

std::vector<uint8_t> Certificate_Request_13::serialize() const {
   std::vector<uint8_t> buf;
   append_tls_length_value(buf, m_context, 1);
   buf += m_extensions.serialize(Connection_Side::Server);
   return buf;
}

}  // namespace Botan::TLS
