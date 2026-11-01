/*
* TLS Extension Certificate_Status_Request
* (C) 2011,2012,2015,2016,2022 Jack Lloyd
*     2016 Juraj Somorovsky
*     2021 Elektrobit Automotive GmbH
*     2022 Hannes Rantzsch, René Meusel, neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_extensions.h>

#include <botan/tls_exceptn.h>
#include <botan/tls_messages.h>
#include <botan/internal/tls_reader.h>

namespace Botan::TLS {

namespace {
class RFC6066_Empty_Certificate_Status_Request {
   public:
      RFC6066_Empty_Certificate_Status_Request() = default;

      explicit RFC6066_Empty_Certificate_Status_Request(uint16_t extension_size) {
         if(extension_size != 0) {
            throw Decoding_Error("Received an unexpectedly non-empty Certificate_Status_Request");
         }
      }

      std::vector<uint8_t> serialize() const { return {}; }
};

class RFC6066_Certificate_Status_Request {
   public:
      explicit RFC6066_Certificate_Status_Request(std::vector<uint8_t> names) : ocsp_names(std::move(names)) {
         BOTAN_ARG_CHECK(ocsp_names.size() <= 0xFFFF, "OCSP responder_id_list is too long");
      }

      RFC6066_Certificate_Status_Request(TLS_Data_Reader& reader, uint16_t extension_size) {
         if(extension_size == 0) {
            throw Decoding_Error("Received an unexpectedly empty Certificate_Status_Request");
         }

         const uint8_t type = reader.get_byte();
         if(type == 1 /* ocsp */) {
            // RFC 6066 Section 8: OCSP CertificateStatusRequest is
            //    ResponderID responder_id_list<0..2^16-1>;
            //    Extensions  request_extensions;
            //
            // for a total wire size of 1 (status_type) + 2 (resp_id_list len)
            //   + len_resp_id_list + 2 (request_ext len) + len_requ_ext.
            if(extension_size < 5) {
               throw Decoding_Error("Truncated OCSP CertificateStatusRequest");
            }
            const size_t len_resp_id_list = reader.get_uint16_t();
            if(len_resp_id_list > static_cast<size_t>(extension_size) - 5) {
               throw Decoding_Error("Inconsistent length in OCSP CertificateStatusRequest");
            }
            ocsp_names = reader.get_fixed<uint8_t>(len_resp_id_list);
            const size_t len_requ_ext = reader.get_uint16_t();
            if(len_resp_id_list + len_requ_ext + 5 != extension_size) {
               throw Decoding_Error("Inconsistent length in OCSP CertificateStatusRequest");
            }
            extension_bytes = reader.get_fixed<uint8_t>(len_requ_ext);
         } else {
            // Other status types are filtered out by make_extension()
            throw Decoding_Error("Unexpected status_type in Certificate_Status_Request");
         }
      }

      std::vector<uint8_t> serialize() const {
         std::vector<uint8_t> buf;
         buf.push_back(1);  // status_type = ocsp
         append_tls_length_value(buf, ocsp_names, 2);
         append_tls_length_value(buf, extension_bytes, 2);
         return buf;
      }

      std::vector<uint8_t> ocsp_names;       // NOLINT(*-non-private-member-variable*)
      std::vector<uint8_t> extension_bytes;  // NOLINT(*-non-private-member-variable*)
};

}  // namespace

class Certificate_Status_Request_Internal {
   private:
      using Contents =
         std::variant<RFC6066_Empty_Certificate_Status_Request, RFC6066_Certificate_Status_Request, Certificate_Status>;

   public:
      explicit Certificate_Status_Request_Internal(Contents c) : content(std::move(c)) {}

      Contents content;  // NOLINT(*-non-private-member-variable*)
};

Certificate_Status_Request::Certificate_Status_Request(TLS_Data_Reader& reader,
                                                       uint16_t extension_size,
                                                       Handshake_Type message_type,
                                                       Connection_Side from) {
   // This parser needs to take TLS 1.2 and TLS 1.3 into account. The
   // extension's content and structure is dependent on the context it
   // was sent in (i.e. the enclosing handshake message). Below is a list
   // of handshake messages this can appear in.
   //
   // TLS 1.2
   //  * Client Hello
   //  * Server Hello
   //
   // TLS 1.3
   //  * Client Hello
   //  * Certificate Request
   //  * Certificate (Entry)

   // RFC 6066 8.
   //    In order to indicate their desire to receive certificate status
   //    information, clients MAY include an extension of type "status_request"
   //    in the (extended) client hello.
   if(message_type == Handshake_Type::ClientHello) {
      m_impl = std::make_unique<Certificate_Status_Request_Internal>(
         RFC6066_Certificate_Status_Request(reader, extension_size));
   }

   // RFC 6066 8.
   //    If a server returns a "CertificateStatus" message, then the server MUST
   //    have included an extension of type "status_request" with empty
   //    "extension_data" in the extended server hello.
   //
   // RFC 8446 4.4.2.1
   //    A server MAY request that a client present an OCSP response with its
   //    certificate by sending an empty "status_request" extension in its
   //    CertificateRequest message.
   else if(message_type == Handshake_Type::ServerHello || message_type == Handshake_Type::CertificateRequest) {
      m_impl = std::make_unique<Certificate_Status_Request_Internal>(
         RFC6066_Empty_Certificate_Status_Request(extension_size));
   }

   // RFC 8446 4.4.2.1
   //    In TLS 1.3, the server's OCSP information is carried in an extension
   //    in the CertificateEntry [in a Certificate handshake message] [...].
   //    Specifically, the body of the "status_request" extension from the
   //    server MUST be a CertificateStatus structure as defined in [RFC6066]
   //    [...].
   //
   // RFC 8446 4.4.2.1
   //    If the client opts to send an OCSP response, the body of its
   //    "status_request" extension MUST be a CertificateStatus structure as
   //    defined in [RFC6066].
   else if(message_type == Handshake_Type::Certificate) {
      m_impl = std::make_unique<Certificate_Status_Request_Internal>(
         Certificate_Status(reader.get_fixed<uint8_t>(extension_size), from));
   }

   // all other contexts are not allowed for this extension
   else {
      throw TLS_Exception(Alert::UnsupportedExtension,
                          "Server sent a Certificate_Status_Request extension in an unsupported context");
   }
}

Certificate_Status_Request::Certificate_Status_Request() :
      m_impl(std::make_unique<Certificate_Status_Request_Internal>(RFC6066_Empty_Certificate_Status_Request())) {}

// The public signature takes ocsp_key_ids by value
// NOLINTBEGIN(performance-unnecessary-value-param)
Certificate_Status_Request::Certificate_Status_Request(std::vector<uint8_t> ocsp_responder_ids,
                                                       std::vector<std::vector<uint8_t>> ocsp_key_ids) :
      m_impl(std::make_unique<Certificate_Status_Request_Internal>(
         RFC6066_Certificate_Status_Request(std::move(ocsp_responder_ids)))) {
   // The OCSPStatusRequest structure has no place to carry these
   BOTAN_ARG_CHECK(ocsp_key_ids.empty(), "Certificate_Status_Request does not support OCSP key IDs");
}

// NOLINTEND(performance-unnecessary-value-param)

Certificate_Status_Request::Certificate_Status_Request(std::vector<uint8_t> response) :
      m_impl(std::make_unique<Certificate_Status_Request_Internal>(Certificate_Status(std::move(response)))) {}

Certificate_Status_Request::~Certificate_Status_Request() = default;

const std::vector<uint8_t>& Certificate_Status_Request::get_responder_id_list() const {
   BOTAN_ASSERT_NONNULL(m_impl);
   BOTAN_STATE_CHECK(std::holds_alternative<RFC6066_Certificate_Status_Request>(m_impl->content));
   return std::get<RFC6066_Certificate_Status_Request>(m_impl->content).ocsp_names;
}

const std::vector<uint8_t>& Certificate_Status_Request::get_request_extensions() const {
   BOTAN_ASSERT_NONNULL(m_impl);
   BOTAN_STATE_CHECK(std::holds_alternative<RFC6066_Certificate_Status_Request>(m_impl->content));
   return std::get<RFC6066_Certificate_Status_Request>(m_impl->content).extension_bytes;
}

const std::vector<uint8_t>& Certificate_Status_Request::get_ocsp_response() const {
   BOTAN_ASSERT_NONNULL(m_impl);
   BOTAN_STATE_CHECK(std::holds_alternative<Certificate_Status>(m_impl->content));
   return std::get<Certificate_Status>(m_impl->content).response();
}

std::vector<uint8_t> Certificate_Status_Request::serialize(Connection_Side /*side*/) const {
   BOTAN_ASSERT_NONNULL(m_impl);
   return std::visit([](const auto& c) { return c.serialize(); }, m_impl->content);
}

}  // namespace Botan::TLS
