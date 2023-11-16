/*
* Certificate Message
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*     2023 René Meusel, Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>

#include <botan/credentials_manager.h>
#include <botan/data_src.h>
#include <botan/ocsp.h>
#include <botan/tls_alert.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_extensions.h>
#include <botan/x509_key.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_reader.h>

#include <iterator>
#include <memory>

namespace Botan::TLS {

namespace {

bool certificate_allows_signing(const X509_Certificate& cert) {
   const auto constraints = cert.constraints();
   if(constraints.empty()) {
      return true;
   }

   return constraints.includes_any(Key_Constraints::DigitalSignature, Key_Constraints::NonRepudiation);
}

std::vector<std::string> filter_signature_schemes(const std::vector<Signature_Scheme>& peer_scheme_preference) {
   std::vector<std::string> compatible_schemes;
   for(const auto& scheme : peer_scheme_preference) {
      if(scheme.is_available() && scheme.is_compatible_with(Protocol_Version::TLS_V13)) {
         compatible_schemes.push_back(scheme.algorithm_name());
      }
   }

   if(compatible_schemes.empty()) {
      throw TLS_Exception(Alert::HandshakeFailure, "Failed to agree on any signature algorithm");
   }

   return compatible_schemes;
}

}  // namespace

bool Certificate_13::has_certificate_chain() const {
   return !empty() && m_entries.front().has_certificate();
}

bool Certificate_13::is_raw_public_key() const {
   return !empty() && !has_certificate_chain();
}

std::vector<X509_Certificate> Certificate_13::cert_chain() const {
   BOTAN_STATE_CHECK(has_certificate_chain());
   std::vector<X509_Certificate> result;
   std::transform(m_entries.cbegin(), m_entries.cend(), std::back_inserter(result), [](const auto& cert_entry) {
      return cert_entry.certificate();
   });
   return result;
}

void Certificate_13::validate_extensions(const std::set<Extension_Code>& requested_extensions, Callbacks& cb) const {
   // RFC 8446 4.4.2
   //    Extensions in the Certificate message from the server MUST
   //    correspond to ones from the ClientHello message.  Extensions in
   //    the Certificate message from the client MUST correspond to
   //    extensions in the CertificateRequest message from the server.
   for(const auto& entry : m_entries) {
      if(entry.extensions().contains_other_than(requested_extensions)) {
         throw TLS_Exception(Alert::IllegalParameter, "Certificate Entry contained an extension that was not offered");
      }

      cb.tls_examine_extensions(entry.extensions(), m_side, type());
   }
}

std::shared_ptr<const Public_Key> Certificate_13::public_key() const {
   BOTAN_STATE_CHECK(!empty());
   return m_entries.front().public_key();
}

const X509_Certificate& Certificate_13::leaf() const {
   BOTAN_STATE_CHECK(!empty());
   return m_entries.front().certificate();
}

void Certificate_13::verify(Callbacks& callbacks,
                            const Policy& policy,
                            Credentials_Manager& creds,
                            std::string_view hostname,
                            bool use_ocsp) const {
   const auto usage = (m_side == Connection_Side::Client) ? Usage_Type::TLS_CLIENT_AUTH : Usage_Type::TLS_SERVER_AUTH;

   if(is_raw_public_key()) {
      callbacks.tls_verify_raw_public_key(*public_key(), usage, hostname, policy);
   } else {
      verify_certificate_chain(callbacks, policy, creds, hostname, use_ocsp, usage);
   }
}

void Certificate_13::verify_certificate_chain(Callbacks& callbacks,
                                              const Policy& policy,
                                              Credentials_Manager& creds,
                                              std::string_view hostname,
                                              bool use_ocsp,
                                              Usage_Type usage_type) const {
   std::vector<X509_Certificate> certs;
   std::vector<std::optional<OCSP::Response>> ocsp_responses;
   for(const auto& entry : m_entries) {
      certs.push_back(entry.certificate());
      if(use_ocsp) {
         if(entry.extensions().has<Certificate_Status_Request>()) {
            ocsp_responses.push_back(callbacks.tls_parse_ocsp_response(
               entry.extensions().get<Certificate_Status_Request>()->get_ocsp_response()));
         } else {
            ocsp_responses.emplace_back();
         }
      }
   }

   const auto& server_cert = m_entries.front().certificate();
   if(!certificate_allows_signing(server_cert)) {
      throw TLS_Exception(Alert::BadCertificate, "Certificate usage constraints do not allow signing");
   }

   // Note that m_side represents the sender, so the usages here are swapped
   const auto trusted_CAs = creds.trusted_certificate_authorities(
      m_side == Connection_Side::Client ? "tls-server" : "tls-client", std::string(hostname));

   callbacks.tls_verify_cert_chain(certs, ocsp_responses, trusted_CAs, usage_type, hostname, policy);
}

void Certificate_13::setup_entries(std::vector<X509_Certificate> cert_chain,
                                   const Certificate_Status_Request* csr,
                                   Callbacks& callbacks) {
   // RFC 8446 4.4.2.1
   //    A server MAY request that a client present an OCSP response with its
   //    certificate by sending an empty "status_request" extension in its
   //    CertificateRequest message.
   const auto ocsp_responses = (csr != nullptr) ? callbacks.tls_provide_cert_chain_status(cert_chain, *csr)
                                                : std::vector<std::vector<uint8_t>>(cert_chain.size());

   if(ocsp_responses.size() != cert_chain.size()) {
      throw TLS_Exception(Alert::InternalError, "Application didn't provide the correct number of OCSP responses");
   }

   for(size_t i = 0; i < cert_chain.size(); ++i) {
      auto& entry = m_entries.emplace_back(cert_chain[i]);
      if(!ocsp_responses[i].empty()) {
         entry.extensions().add(new Certificate_Status_Request(ocsp_responses[i]));
      }

      // This will call the modification callback multiple times. Once for
      // each certificate in the `cert_chain`. Users that want to add an
      // extension to a specific Certificate Entry might have a hard time
      // to distinguish them.
      //
      // TODO: Callbacks::tls_modify_extensions() might need even more
      //       context depending on the message whose extensions should be
      //       manipulatable.
      callbacks.tls_modify_extensions(entry.extensions(), m_side, type());
   }
}

void Certificate_13::setup_entry(std::shared_ptr<Public_Key> raw_public_key, Callbacks& callbacks) {
   BOTAN_ASSERT_NONNULL(raw_public_key);
   auto& entry = m_entries.emplace_back(std::move(raw_public_key));
   callbacks.tls_modify_extensions(entry.extensions(), m_side, type());
}

/**
 * Create a Client Certificate message
 */
Certificate_13::Certificate_13(const Certificate_Request_13& cert_request,
                               std::string_view hostname,
                               Credentials_Manager& credentials_manager,
                               Callbacks& callbacks,
                               Certificate_Type cert_type) :
      m_request_context(cert_request.context()), m_side(Connection_Side::Client) {
   const auto key_types = filter_signature_schemes(cert_request.signature_schemes());
   const auto op_type = "tls-client";

   if(cert_type == Certificate_Type::X509) {
      setup_entries(
         credentials_manager.find_cert_chain(key_types,
                                             to_algorithm_identifiers(cert_request.certificate_signature_schemes()),
                                             cert_request.acceptable_CAs(),
                                             op_type,
                                             std::string(hostname)),
         cert_request.extensions().get<Certificate_Status_Request>(),
         callbacks);
   } else if(cert_type == Certificate_Type::RawPublicKey) {
      auto raw_public_key = credentials_manager.find_raw_public_key(key_types, op_type, std::string(hostname));

      // RFC 8446 4.4.2
      //     If the RawPublicKey certificate type was negotiated, then the
      //     certificate_list MUST contain no more than one CertificateEntry
      //     [...].
      //     A client will send an empty certificate_list if it does not have
      //     an appropriate certificate to send in response to the server's
      //     authentication request.
      if(raw_public_key) {
         setup_entry(std::move(raw_public_key), callbacks);
      }
   }
}

/**
 * Create a Server Certificate message
 */
Certificate_13::Certificate_13(const Client_Hello_13& client_hello,
                               Credentials_Manager& credentials_manager,
                               Callbacks& callbacks,
                               Certificate_Type cert_type) :
      // RFC 8446 4.4.2:
      //    [In the case of server authentication], this field
      //    SHALL be zero length
      m_request_context(), m_side(Connection_Side::Server) {
   BOTAN_ASSERT_NOMSG(client_hello.extensions().has<Signature_Algorithms>());

   const auto key_types = filter_signature_schemes(client_hello.signature_schemes());
   const auto op_type = "tls-server";
   const auto context = client_hello.sni_hostname();

   if(cert_type == Certificate_Type::X509) {
      auto cert_chain = credentials_manager.find_cert_chain(
         key_types, to_algorithm_identifiers(client_hello.certificate_signature_schemes()), {}, op_type, context);

      // RFC 8446 4.4.2
      //    The server's certificate_list MUST always be non-empty.
      if(cert_chain.empty()) {
         throw TLS_Exception(Alert::HandshakeFailure, "No sufficient server certificate available");
      }

      setup_entries(std::move(cert_chain), client_hello.extensions().get<Certificate_Status_Request>(), callbacks);
   } else if(cert_type == Certificate_Type::RawPublicKey) {
      auto raw_public_key = credentials_manager.find_raw_public_key(key_types, op_type, context);

      // RFC 8446 4.4.2
      //     If the RawPublicKey certificate type was negotiated, then the
      //     certificate_list MUST contain no more than one CertificateEntry
      //     [...].
      //     The server's certificate_list MUST always be non-empty
      if(!raw_public_key) {
         throw TLS_Exception(Alert::HandshakeFailure, "No sufficient server raw public key available");
      }

      setup_entry(std::move(raw_public_key), callbacks);
   }
}

Certificate_13::Certificate_Entry::Certificate_Entry(TLS_Data_Reader& reader,
                                                     const Connection_Side side,
                                                     const Certificate_Type cert_type) {
   switch(cert_type) {
      case Certificate_Type::X509:
         // RFC 8446 4.2.2
         //    [...] each CertificateEntry contains a DER-encoded X.509
         //    certificate.
         m_certificate = X509_Certificate(reader.get_tls_length_value(3));
         m_raw_public_key = m_certificate->subject_public_key();
         break;
      case Certificate_Type::RawPublicKey:
         // RFC 7250 3.
         //    This specification uses raw public keys whereby the already
         //    available encoding used in a PKIX certificate in the form of a
         //    SubjectPublicKeyInfo structure is reused.
         m_raw_public_key = X509::load_key(reader.get_tls_length_value(3));
         break;
      default:
         throw TLS_Exception(Alert::InternalError, "Unknown certificate type");
   }

   // Extensions are simply tacked at the end of the certificate entry. This
   // is a departure from the typical "tag-length-value" in a sense that the
   // Extensions deserializer needs the length value of the extensions.
   const auto extensions_length = reader.peek_uint16_t();
   const auto exts_buf = reader.get_fixed<uint8_t>(extensions_length + 2);
   TLS_Data_Reader exts_reader("extensions reader", exts_buf);
   m_extensions.deserialize(exts_reader, side, Handshake_Type::Certificate);

   if(cert_type == Certificate_Type::X509) {
      // RFC 8446 4.4.2
      //    Valid extensions for server certificates at present include the
      //    OCSP Status extension [RFC6066] and the SignedCertificateTimestamp
      //    extension [RFC6962]; future extensions may be defined for this
      //    message as well.
      //
      // RFC 8446 4.4.2.1
      //    A server MAY request that a client present an OCSP response with its
      //    certificate by sending an empty "status_request" extension in its
      //    CertificateRequest message.
      if(m_extensions.contains_implemented_extensions_other_than({
            Extension_Code::CertificateStatusRequest,
            // Extension_Code::SignedCertificateTimestamp
         })) {
         throw TLS_Exception(Alert::IllegalParameter, "Certificate Entry contained an extension that is not allowed");
      }
   } else if(m_extensions.contains_implemented_extensions_other_than({})) {
      throw TLS_Exception(
         Alert::IllegalParameter,
         "Certificate Entry holding something else than a certificate contained unexpected extensions");
   }
}

Certificate_13::Certificate_Entry::Certificate_Entry(X509_Certificate cert) :
      m_certificate(std::move(cert)), m_raw_public_key(m_certificate->subject_public_key()) {}

Certificate_13::Certificate_Entry::Certificate_Entry(std::shared_ptr<Public_Key> raw_public_key) :
      m_certificate(std::nullopt), m_raw_public_key(std::move(raw_public_key)) {
   BOTAN_ASSERT_NONNULL(m_raw_public_key);
}

const X509_Certificate& Certificate_13::Certificate_Entry::certificate() const {
   BOTAN_STATE_CHECK(has_certificate());
   return m_certificate.value();
}

std::shared_ptr<const Public_Key> Certificate_13::Certificate_Entry::public_key() const {
   BOTAN_ASSERT_NONNULL(m_raw_public_key);
   return m_raw_public_key;
}

std::vector<uint8_t> Certificate_13::Certificate_Entry::serialize() const {
   return (has_certificate()) ? m_certificate->BER_encode() : X509::BER_encode(*m_raw_public_key);
}

/**
* Deserialize a Certificate message
*/
Certificate_13::Certificate_13(const std::vector<uint8_t>& buf,
                               const Policy& policy,
                               Connection_Side side,
                               Certificate_Type cert_type) :
      m_side(side) {
   TLS_Data_Reader reader("cert message reader", buf);

   m_request_context = reader.get_range<uint8_t>(1, 0, 255);

   // RFC 8446 4.4.2
   //    [...] in the case of server authentication, this field SHALL be zero length.
   if(m_side == Connection_Side::Server && !m_request_context.empty()) {
      throw TLS_Exception(Alert::IllegalParameter, "Server Certificate message must not contain a request context");
   }

   const auto cert_entries_len = reader.get_uint24_t();

   if(reader.remaining_bytes() != cert_entries_len) {
      throw TLS_Exception(Alert::DecodeError, "Certificate: Message malformed");
   }

   const size_t max_size = policy.maximum_certificate_chain_size();
   if(max_size > 0 && cert_entries_len > max_size) {
      throw Decoding_Error("Certificate chain exceeds policy specified maximum size");
   }

   while(reader.has_remaining()) {
      m_entries.emplace_back(reader, side, cert_type);
   }

   // RFC 8446 4.4.2
   //    The server's certificate_list MUST always be non-empty.  A client
   //    will send an empty certificate_list if it does not have an
   //    appropriate certificate to send in response to the server's
   //    authentication request.
   if(m_entries.empty()) {
      // RFC 8446 4.4.2.4
      //    If the server supplies an empty Certificate message, the client MUST
      //    abort the handshake with a "decode_error" alert.
      if(m_side == Connection_Side::Server) {
         throw TLS_Exception(Alert::DecodeError, "No certificates sent by server");
      }

      return;
   }

   BOTAN_ASSERT_NOMSG(!m_entries.empty());

   // RFC 8446 4.4.2.2
   //    The certificate type MUST be X.509v3 [RFC5280], unless explicitly
   //    negotiated otherwise (e.g., [RFC7250]).
   //
   // TLS 1.0 through 1.3 all seem to require that the certificate be
   // precisely a v3 certificate. In fact the strict wording would seem
   // to require that every certificate in the chain be v3. But often
   // the intermediates are outside of the control of the server.
   // But, require that the leaf certificate be v3.
   if(cert_type == Certificate_Type::X509 && m_entries.front().certificate().x509_version() != 3) {
      throw TLS_Exception(Alert::BadCertificate, "The leaf certificate must be v3");
   }

   // RFC 8446 4.4.2
   //    If the RawPublicKey certificate type was negotiated, then the
   //    certificate_list MUST contain no more than one CertificateEntry.
   if(cert_type == Certificate_Type::RawPublicKey && m_entries.size() != 1) {
      throw TLS_Exception(Alert::IllegalParameter, "Certificate message contained more than one RawPublicKey");
   }

   // Validate the provided (certificate) public key against our policy
   auto pubkey = public_key();
   policy.check_peer_key_acceptable(*pubkey);

   if(!policy.allowed_signature_method(pubkey->algo_name())) {
      throw TLS_Exception(Alert::HandshakeFailure, "Rejecting " + pubkey->algo_name() + " signature");
   }
}

/**
* Serialize a Certificate message
*/
std::vector<uint8_t> Certificate_13::serialize() const {
   std::vector<uint8_t> buf;

   append_tls_length_value(buf, m_request_context, 1);

   std::vector<uint8_t> entries;
   for(const auto& entry : m_entries) {
      append_tls_length_value(entries, entry.serialize(), 3);

      // Extensions are tacked at the end of certificate entries. Note that
      // Extensions::serialize() usually emits the required length field,
      // except when no extensions are added at all, then it  returns an
      // empty buffer.
      //
      // TODO: look into this issue more generally when overhauling the
      //       message marshalling.
      auto extensions = entry.extensions().serialize(m_side);
      entries += (!extensions.empty()) ? extensions : std::vector<uint8_t>{0, 0};
   }

   append_tls_length_value(buf, entries, 3);

   return buf;
}

}  // namespace Botan::TLS
