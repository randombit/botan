/*
* TLS Extensions
* (C) 2011,2012,2015,2016 Jack Lloyd
*     2016 Juraj Somorovsky
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_extensions.h>
#include <botan/internal/tls_reader.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>

#include <iterator>

namespace Botan::TLS {

namespace {

std::unique_ptr<Extension> make_extension(TLS_Data_Reader& reader,
                                          const uint16_t code,
                                          const uint16_t size,
                                          const Connection_Side from,
                                          const Handshake_Type message_type)
   {
   switch(code)
      {
      case TLSEXT_SERVER_NAME_INDICATION:
         return std::make_unique<Server_Name_Indicator>(reader, size);

      case TLSEXT_SUPPORTED_GROUPS:
         return std::make_unique<Supported_Groups>(reader, size);

      case TLSEXT_CERT_STATUS_REQUEST:
         return std::make_unique<Certificate_Status_Request>(reader, size, from, message_type);

      case TLSEXT_EC_POINT_FORMATS:
         return std::make_unique<Supported_Point_Formats>(reader, size);

      case TLSEXT_SAFE_RENEGOTIATION:
         return std::make_unique<Renegotiation_Extension>(reader, size);

      case TLSEXT_SIGNATURE_ALGORITHMS:
         return std::make_unique<Signature_Algorithms>(reader, size);

      case TLSEXT_USE_SRTP:
         return std::make_unique<SRTP_Protection_Profiles>(reader, size);

      case TLSEXT_ALPN:
         return std::make_unique<Application_Layer_Protocol_Notification>(reader, size, from);

      case TLSEXT_EXTENDED_MASTER_SECRET:
         return std::make_unique<Extended_Master_Secret>(reader, size);

      case TLSEXT_RECORD_SIZE_LIMIT:
         return std::make_unique<Record_Size_Limit>(reader, size, from);

      case TLSEXT_ENCRYPT_THEN_MAC:
         return std::make_unique<Encrypt_then_MAC>(reader, size);

      case TLSEXT_SESSION_TICKET:
         return std::make_unique<Session_Ticket>(reader, size);

      case TLSEXT_SUPPORTED_VERSIONS:
         return std::make_unique<Supported_Versions>(reader, size, from);

#if defined(BOTAN_HAS_TLS_13)
      case TLSEXT_COOKIE:
         return std::make_unique<Cookie>(reader, size);

      case TLSEXT_PSK_KEY_EXCHANGE_MODES:
         return std::make_unique<PSK_Key_Exchange_Modes>(reader, size);

      case TLSEXT_SIGNATURE_ALGORITHMS_CERT:
         return std::make_unique<Signature_Algorithms_Cert>(reader, size);

      case TLSEXT_KEY_SHARE:
         return std::make_unique<Key_Share>(reader, size, message_type);
#endif
      }

   return std::make_unique<Unknown_Extension>(static_cast<Handshake_Extension_Type>(code),
                                              reader, size);;
   }

}

void Extensions::add(std::unique_ptr<Extension> extn)
   {
   if (has(extn->type()))
      {
      throw Invalid_Argument("cannot add the same extension twice: " + std::to_string(extn->type()));
      }

   m_extensions.emplace_back(extn.release());
   }

void Extensions::deserialize(TLS_Data_Reader& reader,
                             const Connection_Side from,
                             const Handshake_Type message_type)
   {
   if(reader.has_remaining())
      {
      const uint16_t all_extn_size = reader.get_uint16_t();

      if(reader.remaining_bytes() != all_extn_size)
         throw Decoding_Error("Bad extension size");

      while(reader.has_remaining())
         {
         const uint16_t extension_code = reader.get_uint16_t();
         const uint16_t extension_size = reader.get_uint16_t();

         const auto type = static_cast<Handshake_Extension_Type>(extension_code);

         if(has(type))
            throw TLS_Exception(TLS::Alert::DECODE_ERROR,
                                "Peer sent duplicated extensions");

         this->add(make_extension(reader, extension_code, extension_size, from, message_type));
         }
      }
   }

bool Extensions::contains_other_than(const std::set<Handshake_Extension_Type>& allowed_extensions,
                                     const bool allow_unknown_extensions) const
   {
   const auto found = extension_types();

   std::vector<Handshake_Extension_Type> diff;
   std::set_difference(found.cbegin(), found.end(),
                       allowed_extensions.cbegin(), allowed_extensions.cend(),
                       std::back_inserter(diff));

   if(allow_unknown_extensions)
      {
      // Go through the found unexpected extensions whether any of those
      // is known to this TLS implementation.
      const auto itr = std::find_if(diff.cbegin(), diff.cend(),
                                    [this](const auto ext_type)
         {
         const auto ext = get(ext_type);
         return ext && ext->is_implemented();
         });

      // ... if yes, `contains_other_than` is true
      return itr != diff.cend();
      }

   return !diff.empty();
   }

std::unique_ptr<Extension> Extensions::take(Handshake_Extension_Type type)
   {
   const auto i = std::find_if(m_extensions.begin(), m_extensions.end(),
                               [type](const auto &ext) {
                                  return ext->type() == type;
                               });

   std::unique_ptr<Extension> result;
   if (i != m_extensions.end())
      {
      std::swap(result, *i);
      m_extensions.erase(i);
      }

   return result;
   }

std::vector<uint8_t> Extensions::serialize(Connection_Side whoami) const
   {
   std::vector<uint8_t> buf(2); // 2 bytes for length field

   for(const auto& extn : m_extensions)
      {
      if(extn->empty())
         continue;

      const uint16_t extn_code = static_cast<uint16_t>(extn->type());

      const std::vector<uint8_t> extn_val = extn->serialize(whoami);

      buf.push_back(get_byte<0>(extn_code));
      buf.push_back(get_byte<1>(extn_code));

      buf.push_back(get_byte<0>(static_cast<uint16_t>(extn_val.size())));
      buf.push_back(get_byte<1>(static_cast<uint16_t>(extn_val.size())));

      buf += extn_val;
      }

   const uint16_t extn_size = static_cast<uint16_t>(buf.size() - 2);

   buf[0] = get_byte<0>(extn_size);
   buf[1] = get_byte<1>(extn_size);

   // avoid sending a completely empty extensions block
   if(buf.size() == 2)
      return std::vector<uint8_t>();

   return buf;
   }

std::set<Handshake_Extension_Type> Extensions::extension_types() const
   {
   std::set<Handshake_Extension_Type> offers;
   std::transform(m_extensions.cbegin(), m_extensions.cend(),
                  std::inserter(offers, offers.begin()), [] (const auto &ext) {
                     return ext->type();
                  });
   return offers;
   }

Unknown_Extension::Unknown_Extension(Handshake_Extension_Type type,
                                     TLS_Data_Reader& reader,
                                     uint16_t extension_size) :
   m_type(type),
   m_value(reader.get_fixed<uint8_t>(extension_size))
   {
   }

std::vector<uint8_t> Unknown_Extension::serialize(Connection_Side /*whoami*/) const
   {
   throw Invalid_State("Cannot encode an unknown TLS extension");
   }

Server_Name_Indicator::Server_Name_Indicator(TLS_Data_Reader& reader,
                                             uint16_t extension_size)
   {
   /*
   * This is used by the server to confirm that it knew the name
   */
   if(extension_size == 0)
      return;

   uint16_t name_bytes = reader.get_uint16_t();

   if(name_bytes + 2 != extension_size)
      throw Decoding_Error("Bad encoding of SNI extension");

   while(name_bytes)
      {
      uint8_t name_type = reader.get_byte();
      name_bytes--;

      if(name_type == 0) // DNS
         {
         m_sni_host_name = reader.get_string(2, 1, 65535);
         name_bytes -= static_cast<uint16_t>(2 + m_sni_host_name.size());
         }
      else // some other unknown name type
         {
         reader.discard_next(name_bytes);
         name_bytes = 0;
         }
      }
   }

std::vector<uint8_t> Server_Name_Indicator::serialize(Connection_Side /*whoami*/) const
   {
   std::vector<uint8_t> buf;

   size_t name_len = m_sni_host_name.size();

   buf.push_back(get_byte<0>(static_cast<uint16_t>(name_len+3)));
   buf.push_back(get_byte<1>(static_cast<uint16_t>(name_len+3)));
   buf.push_back(0); // DNS

   buf.push_back(get_byte<0>(static_cast<uint16_t>(name_len)));
   buf.push_back(get_byte<1>(static_cast<uint16_t>(name_len)));

   buf += std::make_pair(
      cast_char_ptr_to_uint8(m_sni_host_name.data()),
      m_sni_host_name.size());

   return buf;
   }

Renegotiation_Extension::Renegotiation_Extension(TLS_Data_Reader& reader,
                                                 uint16_t extension_size) : m_reneg_data(reader.get_range<uint8_t>(1, 0, 255))
   {
   if(m_reneg_data.size() + 1 != extension_size)
      throw Decoding_Error("Bad encoding for secure renegotiation extn");
   }

std::vector<uint8_t> Renegotiation_Extension::serialize(Connection_Side /*whoami*/) const
   {
   std::vector<uint8_t> buf;
   append_tls_length_value(buf, m_reneg_data, 1);
   return buf;
   }

Application_Layer_Protocol_Notification::Application_Layer_Protocol_Notification(TLS_Data_Reader& reader,
                                                                                 uint16_t extension_size,
                                                                                 Connection_Side from)
   {
   if(extension_size == 0)
      return; // empty extension

   const uint16_t name_bytes = reader.get_uint16_t();

   size_t bytes_remaining = extension_size - 2;

   if(name_bytes != bytes_remaining)
      throw Decoding_Error("Bad encoding of ALPN extension, bad length field");

   while(bytes_remaining)
      {
      const std::string p = reader.get_string(1, 0, 255);

      if(bytes_remaining < p.size() + 1)
         throw Decoding_Error("Bad encoding of ALPN, length field too long");

      if(p.empty())
         throw Decoding_Error("Empty ALPN protocol not allowed");

      bytes_remaining -= (p.size() + 1);

      m_protocols.push_back(p);
      }

   // RFC 7301 3.1
   //    The "extension_data" field of the [...] extension is structured the
   //    same as described above for the client "extension_data", except that
   //    the "ProtocolNameList" MUST contain exactly one "ProtocolName".
   if(from == Connection_Side::SERVER && m_protocols.size() != 1)
      {
      throw TLS_Exception(Alert::DECODE_ERROR,
                          "Server sent " + std::to_string(m_protocols.size()) +
                          " protocols in ALPN extension response");
      }
   }

const std::string& Application_Layer_Protocol_Notification::single_protocol() const
   {
   BOTAN_STATE_CHECK(m_protocols.size() == 1);
   return m_protocols.front();
   }

std::vector<uint8_t> Application_Layer_Protocol_Notification::serialize(Connection_Side /*whoami*/) const
   {
   std::vector<uint8_t> buf(2);

   for(auto&& p: m_protocols)
      {
      if(p.length() >= 256)
         throw TLS_Exception(Alert::INTERNAL_ERROR, "ALPN name too long");
      if(!p.empty())
         append_tls_length_value(buf,
                                 cast_char_ptr_to_uint8(p.data()),
                                 p.size(),
                                 1);
      }

   buf[0] = get_byte<0>(static_cast<uint16_t>(buf.size()-2));
   buf[1] = get_byte<1>(static_cast<uint16_t>(buf.size()-2));

   return buf;
   }

Supported_Groups::Supported_Groups(const std::vector<Group_Params>& groups) : m_groups(groups)
   {
   }

const std::vector<Group_Params>& Supported_Groups::groups() const
   {
   return m_groups;
   }

std::vector<Group_Params> Supported_Groups::ec_groups() const
   {
   std::vector<Group_Params> ec;
   for(auto g : m_groups)
      {
      if(group_param_is_dh(g) == false)
         ec.push_back(g);
      }
   return ec;
   }

std::vector<Group_Params> Supported_Groups::dh_groups() const
   {
   std::vector<Group_Params> dh;
   for(auto g : m_groups)
      {
      if(group_param_is_dh(g) == true)
         dh.push_back(g);
      }
   return dh;
   }

std::vector<uint8_t> Supported_Groups::serialize(Connection_Side /*whoami*/) const
   {
   std::vector<uint8_t> buf(2);

   for(auto g : m_groups)
      {
      const uint16_t id = static_cast<uint16_t>(g);

      if(id > 0)
         {
         buf.push_back(get_byte<0>(id));
         buf.push_back(get_byte<1>(id));
         }
      }

   buf[0] = get_byte<0>(static_cast<uint16_t>(buf.size()-2));
   buf[1] = get_byte<1>(static_cast<uint16_t>(buf.size()-2));

   return buf;
   }

Supported_Groups::Supported_Groups(TLS_Data_Reader& reader,
                                   uint16_t extension_size)
   {
   const uint16_t len = reader.get_uint16_t();

   if(len + 2 != extension_size)
      throw Decoding_Error("Inconsistent length field in supported groups list");

   if(len % 2 == 1)
      throw Decoding_Error("Supported groups list of strange size");

   const size_t elems = len / 2;

   for(size_t i = 0; i != elems; ++i)
      {
      const uint16_t id = reader.get_uint16_t();
      m_groups.push_back(static_cast<Group_Params>(id));
      }
   }

std::vector<uint8_t> Supported_Point_Formats::serialize(Connection_Side /*whoami*/) const
   {
   // if this extension is sent, it MUST include uncompressed (RFC 4492, section 5.1)
   if(m_prefers_compressed)
      {
      return std::vector<uint8_t>{2, ANSIX962_COMPRESSED_PRIME, UNCOMPRESSED};
      }
   else
      {
      return std::vector<uint8_t>{1, UNCOMPRESSED};
      }
   }

Supported_Point_Formats::Supported_Point_Formats(TLS_Data_Reader& reader,
                                                 uint16_t extension_size)
   {
   uint8_t len = reader.get_byte();

   if(len + 1 != extension_size)
      throw Decoding_Error("Inconsistent length field in supported point formats list");

   for(size_t i = 0; i != len; ++i)
      {
      uint8_t format = reader.get_byte();

      if(static_cast<ECPointFormat>(format) == UNCOMPRESSED)
         {
         m_prefers_compressed = false;
         reader.discard_next(len-i-1);
         return;
         }
      else if(static_cast<ECPointFormat>(format) == ANSIX962_COMPRESSED_PRIME)
         {
         m_prefers_compressed = true;
         reader.discard_next(len-i-1);
         return;
         }

      // ignore ANSIX962_COMPRESSED_CHAR2, we don't support these curves
      }
   }

std::vector<uint8_t> Signature_Algorithms::serialize(Connection_Side /*whoami*/) const
   {
   BOTAN_ASSERT(m_schemes.size() < 256, "Too many signature schemes");

   std::vector<uint8_t> buf;

   const uint16_t len = static_cast<uint16_t>(m_schemes.size() * 2);

   buf.push_back(get_byte<0>(len));
   buf.push_back(get_byte<1>(len));

   for(Signature_Scheme scheme : m_schemes)
      {
      buf.push_back(get_byte<0>(scheme.wire_code()));
      buf.push_back(get_byte<1>(scheme.wire_code()));
      }

   return buf;
   }

Signature_Algorithms::Signature_Algorithms(TLS_Data_Reader& reader,
                                           uint16_t extension_size)
   {
   uint16_t len = reader.get_uint16_t();

   if(len + 2 != extension_size || len % 2 == 1 || len == 0)
      {
      throw Decoding_Error("Bad encoding on signature algorithms extension");
      }

   while(len)
      {
      m_schemes.emplace_back(reader.get_uint16_t());
      len -= 2;
      }
   }

Session_Ticket::Session_Ticket(TLS_Data_Reader& reader,
                               uint16_t extension_size) : m_ticket(reader.get_elem<uint8_t, std::vector<uint8_t>>(extension_size))
   {}

SRTP_Protection_Profiles::SRTP_Protection_Profiles(TLS_Data_Reader& reader,
                                                   uint16_t extension_size) : m_pp(reader.get_range<uint16_t>(2, 0, 65535))
   {
   const std::vector<uint8_t> mki = reader.get_range<uint8_t>(1, 0, 255);

   if(m_pp.size() * 2 + mki.size() + 3 != extension_size)
      throw Decoding_Error("Bad encoding for SRTP protection extension");

   if(!mki.empty())
      throw Decoding_Error("Unhandled non-empty MKI for SRTP protection extension");
   }

std::vector<uint8_t> SRTP_Protection_Profiles::serialize(Connection_Side /*whoami*/) const
   {
   std::vector<uint8_t> buf;

   const uint16_t pp_len = static_cast<uint16_t>(m_pp.size() * 2);
   buf.push_back(get_byte<0>(pp_len));
   buf.push_back(get_byte<1>(pp_len));

   for(uint16_t pp : m_pp)
      {
      buf.push_back(get_byte<0>(pp));
      buf.push_back(get_byte<1>(pp));
      }

   buf.push_back(0); // srtp_mki, always empty here

   return buf;
   }

Extended_Master_Secret::Extended_Master_Secret(TLS_Data_Reader& /*unused*/,
                                               uint16_t extension_size)
   {
   if(extension_size != 0)
      throw Decoding_Error("Invalid extended_master_secret extension");
   }

std::vector<uint8_t> Extended_Master_Secret::serialize(Connection_Side /*whoami*/) const
   {
   return std::vector<uint8_t>();
   }

Encrypt_then_MAC::Encrypt_then_MAC(TLS_Data_Reader& /*unused*/,
                                   uint16_t extension_size)
   {
   if(extension_size != 0)
      throw Decoding_Error("Invalid encrypt_then_mac extension");
   }

std::vector<uint8_t> Encrypt_then_MAC::serialize(Connection_Side /*whoami*/) const
   {
   return std::vector<uint8_t>();
   }

std::vector<uint8_t> Supported_Versions::serialize(Connection_Side whoami) const
   {
   std::vector<uint8_t> buf;

   if(whoami == Connection_Side::SERVER)
      {
      BOTAN_ASSERT_NOMSG(m_versions.size() == 1);
      buf.push_back(m_versions[0].major_version());
      buf.push_back(m_versions[0].minor_version());
      }
   else
      {
      BOTAN_ASSERT_NOMSG(!m_versions.empty());
      const uint8_t len = static_cast<uint8_t>(m_versions.size() * 2);

      buf.push_back(len);

      for(Protocol_Version version : m_versions)
         {
         buf.push_back(version.major_version());
         buf.push_back(version.minor_version());
         }
      }

   return buf;
   }


Supported_Versions::Supported_Versions(Protocol_Version offer, const Policy& policy)
   {
   if(offer.is_datagram_protocol())
      {
#if defined(BOTAN_HAS_TLS_12)
      if(offer >= Protocol_Version::DTLS_V12 && policy.allow_dtls12())
         m_versions.push_back(Protocol_Version::DTLS_V12);
#endif
      }
   else
      {
#if defined(BOTAN_HAS_TLS_13)
      if(offer >= Protocol_Version::TLS_V13 && policy.allow_tls13())
         m_versions.push_back(Protocol_Version::TLS_V13);
#endif
#if defined(BOTAN_HAS_TLS_12)
      if(offer >= Protocol_Version::TLS_V12 && policy.allow_tls12())
         m_versions.push_back(Protocol_Version::TLS_V12);
#endif
      }
   }

Supported_Versions::Supported_Versions(TLS_Data_Reader& reader,
                                       uint16_t extension_size,
                                       Connection_Side from)
   {
   if(from == Connection_Side::SERVER)
      {
      if(extension_size != 2)
         throw Decoding_Error("Server sent invalid supported_versions extension");
      m_versions.push_back(Protocol_Version(reader.get_uint16_t()));
      }
   else
      {
      auto versions = reader.get_range<uint16_t>(1, 1, 127);

      for(auto v : versions)
         m_versions.push_back(Protocol_Version(v));

      if(extension_size != 1+2*versions.size())
         throw Decoding_Error("Client sent invalid supported_versions extension");
      }
   }

bool Supported_Versions::supports(Protocol_Version version) const
   {
   for(auto v : m_versions)
      if(version == v)
         return true;
   return false;
   }


Record_Size_Limit::Record_Size_Limit(const uint16_t limit)
   : m_limit(limit)
   {
   BOTAN_ASSERT(limit >= 64,
                "RFC 8449 does not allow record size limits smaller than 64 bytes");
   BOTAN_ASSERT(limit <= MAX_PLAINTEXT_SIZE + 1 /* encrypted content type byte */,
                "RFC 8449 does not allow record size limits larger than 2^14+1");
   }

Record_Size_Limit::Record_Size_Limit(TLS_Data_Reader& reader,
                                     uint16_t extension_size,
                                     Connection_Side from)
   {
   if(extension_size != 2)
      {
      throw TLS_Exception(Alert::DECODE_ERROR, "invalid record_size_limit extension");
      }

   m_limit = reader.get_uint16_t();

   // RFC 8449 4.
   //    This value is the length of the plaintext of a protected record.
   //    The value includes the content type and padding added in TLS 1.3 (that
   //    is, the complete length of TLSInnerPlaintext).
   //
   //    A server MUST NOT enforce this restriction; a client might advertise
   //    a higher limit that is enabled by an extension or version the server
   //    does not understand. A client MAY abort the handshake with an
   //    "illegal_parameter" alert.
   //
   // Note: We are currently supporting this extension in TLS 1.3 only, hence
   //       we check for the TLS 1.3 limit. The TLS 1.2 limit would not include
   //       the "content type byte" and hence be one byte less!
   if(m_limit > MAX_PLAINTEXT_SIZE + 1 /* encrypted content type byte */ && from == SERVER)
      {
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER,
                          "Server requested a record size limit larger than the protocol's maximum");
      }

   // RFC 8449 4.
   //    Endpoints MUST NOT send a "record_size_limit" extension with a value
   //    smaller than 64.  An endpoint MUST treat receipt of a smaller value
   //    as a fatal error and generate an "illegal_parameter" alert.
   if(m_limit < 64)
      {
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER,
                          "Received a record size limit smaller than 64 bytes");
      }
   }

std::vector<uint8_t> Record_Size_Limit::serialize(Connection_Side) const
   {
   std::vector<uint8_t> buf;

   buf.push_back(get_byte<0>(m_limit));
   buf.push_back(get_byte<1>(m_limit));

   return buf;
   }


#if defined(BOTAN_HAS_TLS_13)
Cookie::Cookie(const std::vector<uint8_t>& cookie) :
   m_cookie(cookie)
   {
   }

Cookie::Cookie(TLS_Data_Reader& reader,
               uint16_t extension_size)
   {
   if (extension_size == 0)
      {
      return;
      }

   const uint16_t len = reader.get_uint16_t();

   if (len == 0)
      {
      // Based on RFC 8446 4.2.2, len of the Cookie buffer must be at least 1
      throw Decoding_Error("Cookie length must be at least 1 byte");
      }

   if (len > reader.remaining_bytes())
      {
      throw Decoding_Error("Not enough bytes in the buffer to decode Cookie");
      }

   for (auto i = 0u; i < len; ++i)
      {
      m_cookie.push_back(reader.get_byte());
      }
   }

std::vector<uint8_t> Cookie::serialize(Connection_Side /*whoami*/) const
   {
   std::vector<uint8_t> buf;

   const uint16_t len = static_cast<uint16_t>(m_cookie.size());

   buf.push_back(get_byte<0>(len));
   buf.push_back(get_byte<1>(len));

   for (const auto& cookie_byte : m_cookie)
      {
      buf.push_back(cookie_byte);
      }

   return buf;
   }


std::vector<uint8_t> PSK_Key_Exchange_Modes::serialize(Connection_Side) const
   {
   std::vector<uint8_t> buf;

   BOTAN_ASSERT_NOMSG(m_modes.size() < 256);
   buf.push_back(static_cast<uint8_t>(m_modes.size()));
   for (const auto& mode : m_modes)
      {
      buf.push_back(static_cast<uint8_t>(mode));
      }

   return buf;
   }

PSK_Key_Exchange_Modes::PSK_Key_Exchange_Modes(TLS_Data_Reader& reader, uint16_t extension_size)
   {
   if (extension_size < 2)
      {
      throw Decoding_Error("Empty psk_key_exchange_modes extension is illegal");
      }

   const auto mode_count = reader.get_byte();
   for(uint16_t i = 0; i < mode_count; ++i)
      {
      const uint8_t mode = reader.get_byte();
      if (mode != 0 && mode != 1)
         {
         throw Decoding_Error("Unexpected PSK mode: " + std::to_string(mode));
         }

      m_modes.push_back(PSK_Key_Exchange_Mode(mode));
      }
   }

Signature_Algorithms_Cert::Signature_Algorithms_Cert(const std::vector<Signature_Scheme>& schemes)
      : m_siganture_algorithms(schemes)
   {
   }

Signature_Algorithms_Cert::Signature_Algorithms_Cert(TLS_Data_Reader& reader, uint16_t extension_size)
   : m_siganture_algorithms(reader, extension_size)
   {
   }

std::vector<uint8_t> Signature_Algorithms_Cert::serialize(Connection_Side whoami) const
   {
      return m_siganture_algorithms.serialize(whoami);
   }

#endif
}
