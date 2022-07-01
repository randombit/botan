/*
* Certificate Message
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>

#include <botan/credentials_manager.h>
#include <botan/ocsp.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_extensions.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_alert.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/loadstor.h>
#include <botan/data_src.h>

namespace Botan::TLS {

namespace {

bool certificate_allows_signing(const X509_Certificate& cert)
   {
   const auto constraints = cert.constraints();
   if(constraints == NO_CONSTRAINTS)
      return true;

   return constraints & DIGITAL_SIGNATURE || constraints & NON_REPUDIATION;
   }

}

void Certificate_13::validate_extensions(const std::set<Handshake_Extension_Type>& requested_extensions) const
   {
   // RFC 8446 4.4.2
   //    Extensions in the Certificate message from the server MUST
   //    correspond to ones from the ClientHello message.  Extensions in
   //    the Certificate message from the client MUST correspond to
   //    extensions in the CertificateRequest message from the server.
   for(const auto& entry : m_entries)
      {
      if(entry.extensions.contains_other_than(requested_extensions))
         { throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "Certificate Entry contained an extension that was not offered"); }
      }
   }

void Certificate_13::verify(Callbacks& callbacks,
                            const Policy& policy,
                            Credentials_Manager& creds,
                            const std::string& hostname,
                            bool use_ocsp) const
   {
   // RFC 8446 4.4.2.4
   //    If the server supplies an empty Certificate message, the client
   //    MUST abort the handshake with a "decode_error" alert.
   if(m_entries.empty())
      { throw TLS_Exception(Alert::DECODE_ERROR, "Client: No certificates sent by server"); }

   auto trusted_CAs = creds.trusted_certificate_authorities("tls-client", hostname);

   std::vector<X509_Certificate> certs;
   std::vector<std::optional<OCSP::Response>> ocsp_responses;
   for(const auto& entry : m_entries)
      {
      certs.push_back(entry.certificate);
      if(use_ocsp)
         {
         if(entry.extensions.has<Certificate_Status_Request>())
            {
            ocsp_responses.push_back(
               callbacks.tls_parse_ocsp_response(
                  entry.extensions.get<Certificate_Status_Request>()->get_ocsp_response()));
            }
         else
            {
            // Note: The make_optional instead of simply nullopt is necessary to work around a GCC <= 10.0 bug
            //       see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=80635
            ocsp_responses.push_back(std::make_optional<OCSP::Response>());
            }
         }
      }

   const auto& server_cert = m_entries.front().certificate;
   if(!certificate_allows_signing(server_cert))
      {
      throw TLS_Exception(Alert::BAD_CERTIFICATE,
         "Certificate usage constraints do not allow signing");
      }

   const auto usage = (m_side == CLIENT) ? Usage_Type::TLS_CLIENT_AUTH : Usage_Type::TLS_SERVER_AUTH;
   callbacks.tls_verify_cert_chain(certs, ocsp_responses, trusted_CAs, usage, hostname, policy);
   }

/**
* Deserialize a Certificate message
*/
Certificate_13::Certificate_13(const std::vector<uint8_t>& buf,
                               const Policy& policy,
                               const Connection_Side side)
   : m_side(side)
   {
   TLS_Data_Reader reader("cert message reader", buf);

   m_request_context = reader.get_range<uint8_t>(1, 0, 255);

   // RFC 8446 4.4.2
   //    [...] in the case of server authentication, this field SHALL be zero length.
   if(m_side == Connection_Side::SERVER && !m_request_context.empty())
      {
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER,
                          "Server Certificate message must not contain a request context");
      }

   const auto cert_entries_len = reader.get_uint24_t();

   if(reader.remaining_bytes() != cert_entries_len)
      {
      throw TLS_Exception(Alert::DECODE_ERROR, "Certificate: Message malformed");
      }

   const size_t max_size = policy.maximum_certificate_chain_size();
   if(max_size > 0 && cert_entries_len > max_size)
      { throw Decoding_Error("Certificate chain exceeds policy specified maximum size"); }

   while(reader.has_remaining())
      {
      Certificate_Entry entry;
      entry.certificate = X509_Certificate(reader.get_tls_length_value(3));

      // RFC 8446 4.4.2.2
      //    The certificate type MUST be X.509v3 [RFC5280], unless explicitly
      //    negotiated otherwise (e.g., [RFC7250]).
      //
      // TLS 1.0 through 1.3 all seem to require that the certificate be
      // precisely a v3 certificate. In fact the strict wording would seem
      // to require that every certificate in the chain be v3. But often
      // the intermediates are outside of the control of the server.
      // But, require that the leaf certificate be v3.
      if(m_entries.empty() && entry.certificate.x509_version() != 3)
         {
         throw TLS_Exception(Alert::BAD_CERTIFICATE, "The leaf certificate must be v3");
         }

      // Extensions are simply tacked at the end of the certificate entry. This
      // is a departure from the typical "tag-length-value" in a sense that the
      // Extensions deserializer needs the length value of the extensions.
      const auto extensions_length = reader.peek_uint16_t();
      const auto exts_buf = reader.get_fixed<uint8_t>(extensions_length + 2);
      TLS_Data_Reader exts_reader("extensions reader", exts_buf);
      entry.extensions.deserialize(exts_reader, m_side, type());

      // RFC 8446 4.4.2
      //    Valid extensions for server certificates at present include the
      //    OCSP Status extension [RFC6066] and the SignedCertificateTimestamp
      //    extension [RFC6962]; future extensions may be defined for this
      //    message as well.
      if(entry.extensions.contains_implemented_extensions_other_than({
            TLSEXT_CERT_STATUS_REQUEST,
            // SIGNED_CERTIFICATE_TIMESTAMP
         }))
         {
         throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "Certificate Entry contained an extension that is not allowed");
         }

      m_entries.push_back(std::move(entry));
      }

   // RFC 8446 4.4.2
   //    The server's certificate_list MUST always be non-empty.  A client
   //    will send an empty certificate_list if it does not have an
   //    appropriate certificate to send in response to the server's
   //    authentication request.
   if(m_entries.empty())
      {
      if(m_side == SERVER)
         {
         throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "No certificates sent by server");
         }
      }
   else
      {
      /* validation of provided certificate public key */
      auto key = m_entries.front().certificate.load_subject_public_key();

      policy.check_peer_key_acceptable(*key);

      if(!policy.allowed_signature_method(key->algo_name()))
         {
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Rejecting " + key->algo_name() + " signature");
         }
      }
   }

/**
* Serialize a Certificate message
*/
std::vector<uint8_t> Certificate_13::serialize() const
   {
   // Needed only for server implementation or client authentication
   throw Not_Implemented("NYI");
   }

}
