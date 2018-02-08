/*
* TLS Extensions
* (C) 2011,2012,2015,2016 Jack Lloyd
*     2016 Juraj Somorovsky
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_extensions.h>
#include <botan/internal/tls_reader.h>
#include <botan/tls_exceptn.h>

namespace Botan {

namespace TLS {

namespace {

Extension* make_extension(TLS_Data_Reader& reader, uint16_t code, uint16_t size)
   {
   switch(code)
      {
      case TLSEXT_SERVER_NAME_INDICATION:
         return new Server_Name_Indicator(reader, size);

#if defined(BOTAN_HAS_SRP6)
      case TLSEXT_SRP_IDENTIFIER:
         return new SRP_Identifier(reader, size);
#endif

      case TLSEXT_SUPPORTED_GROUPS:
         return new Supported_Groups(reader, size);

      case TLSEXT_CERT_STATUS_REQUEST:
         return new Certificate_Status_Request(reader, size);

      case TLSEXT_EC_POINT_FORMATS:
         return new Supported_Point_Formats(reader, size);

      case TLSEXT_SAFE_RENEGOTIATION:
         return new Renegotiation_Extension(reader, size);

      case TLSEXT_SIGNATURE_ALGORITHMS:
         return new Signature_Algorithms(reader, size);

      case TLSEXT_USE_SRTP:
          return new SRTP_Protection_Profiles(reader, size);

      case TLSEXT_ALPN:
         return new Application_Layer_Protocol_Notification(reader, size);

      case TLSEXT_EXTENDED_MASTER_SECRET:
         return new Extended_Master_Secret(reader, size);

      case TLSEXT_ENCRYPT_THEN_MAC:
         return new Encrypt_then_MAC(reader, size);

      case TLSEXT_SESSION_TICKET:
         return new Session_Ticket(reader, size);
      }

   return new Unknown_Extension(static_cast<Handshake_Extension_Type>(code),
                                reader, size);
   }

}

void Extensions::deserialize(TLS_Data_Reader& reader)
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

         Extension* extn = make_extension(reader,
                                          extension_code,
                                          extension_size);

         this->add(extn);
         }
      }
   }

std::vector<uint8_t> Extensions::serialize() const
   {
   std::vector<uint8_t> buf(2); // 2 bytes for length field

   for(auto& extn : m_extensions)
      {
      if(extn.second->empty())
         continue;

      const uint16_t extn_code = extn.second->type();

      std::vector<uint8_t> extn_val = extn.second->serialize();

      buf.push_back(get_byte(0, extn_code));
      buf.push_back(get_byte(1, extn_code));

      buf.push_back(get_byte(0, static_cast<uint16_t>(extn_val.size())));
      buf.push_back(get_byte(1, static_cast<uint16_t>(extn_val.size())));

      buf += extn_val;
      }

   const uint16_t extn_size = static_cast<uint16_t>(buf.size() - 2);

   buf[0] = get_byte(0, extn_size);
   buf[1] = get_byte(1, extn_size);

   // avoid sending a completely empty extensions block
   if(buf.size() == 2)
      return std::vector<uint8_t>();

   return buf;
   }

bool Extensions::remove_extension(Handshake_Extension_Type typ)
   {
   auto i = m_extensions.find(typ);
   if(i == m_extensions.end())
      return false;
   m_extensions.erase(i);
   return true;
   }

std::set<Handshake_Extension_Type> Extensions::extension_types() const
   {
   std::set<Handshake_Extension_Type> offers;
   for(auto i = m_extensions.begin(); i != m_extensions.end(); ++i)
      offers.insert(i->first);
   return offers;
   }

Unknown_Extension::Unknown_Extension(Handshake_Extension_Type type,
                                     TLS_Data_Reader& reader,
                                     uint16_t extension_size) :
   m_type(type),
   m_value(reader.get_fixed<uint8_t>(extension_size))
   {
   }

std::vector<uint8_t> Unknown_Extension::serialize() const
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

std::vector<uint8_t> Server_Name_Indicator::serialize() const
   {
   std::vector<uint8_t> buf;

   size_t name_len = m_sni_host_name.size();

   buf.push_back(get_byte(0, static_cast<uint16_t>(name_len+3)));
   buf.push_back(get_byte(1, static_cast<uint16_t>(name_len+3)));
   buf.push_back(0); // DNS

   buf.push_back(get_byte(0, static_cast<uint16_t>(name_len)));
   buf.push_back(get_byte(1, static_cast<uint16_t>(name_len)));

   buf += std::make_pair(
      cast_char_ptr_to_uint8(m_sni_host_name.data()),
      m_sni_host_name.size());

   return buf;
   }

#if defined(BOTAN_HAS_SRP6)

SRP_Identifier::SRP_Identifier(TLS_Data_Reader& reader,
                               uint16_t extension_size) : m_srp_identifier(reader.get_string(1, 1, 255))
   {
   if(m_srp_identifier.size() + 1 != extension_size)
      throw Decoding_Error("Bad encoding for SRP identifier extension");
   }

std::vector<uint8_t> SRP_Identifier::serialize() const
   {
   std::vector<uint8_t> buf;

   const uint8_t* srp_bytes = cast_char_ptr_to_uint8(m_srp_identifier.data());
   append_tls_length_value(buf, srp_bytes, m_srp_identifier.size(), 1);

   return buf;
   }

#endif

Renegotiation_Extension::Renegotiation_Extension(TLS_Data_Reader& reader,
                                                 uint16_t extension_size) : m_reneg_data(reader.get_range<uint8_t>(1, 0, 255))
   {
   if(m_reneg_data.size() + 1 != extension_size)
      throw Decoding_Error("Bad encoding for secure renegotiation extn");
   }

std::vector<uint8_t> Renegotiation_Extension::serialize() const
   {
   std::vector<uint8_t> buf;
   append_tls_length_value(buf, m_reneg_data, 1);
   return buf;
   }

Application_Layer_Protocol_Notification::Application_Layer_Protocol_Notification(TLS_Data_Reader& reader,
                                                                                 uint16_t extension_size)
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

      bytes_remaining -= (p.size() + 1);

      m_protocols.push_back(p);
      }
   }

const std::string& Application_Layer_Protocol_Notification::single_protocol() const
   {
   if(m_protocols.size() != 1)
      throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                          "Server sent " + std::to_string(m_protocols.size()) +
                          " protocols in ALPN extension response");
   return m_protocols[0];
   }

std::vector<uint8_t> Application_Layer_Protocol_Notification::serialize() const
   {
   std::vector<uint8_t> buf(2);

   for(auto&& p: m_protocols)
      {
      if(p.length() >= 256)
         throw TLS_Exception(Alert::INTERNAL_ERROR, "ALPN name too long");
      if(p != "")
         append_tls_length_value(buf,
                                 cast_char_ptr_to_uint8(p.data()),
                                 p.size(),
                                 1);
      }

   buf[0] = get_byte(0, static_cast<uint16_t>(buf.size()-2));
   buf[1] = get_byte(1, static_cast<uint16_t>(buf.size()-2));

   return buf;
   }

Supported_Groups::Supported_Groups(const std::vector<Group_Params>& groups) : m_groups(groups)
   {
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

std::vector<uint8_t> Supported_Groups::serialize() const
   {
   std::vector<uint8_t> buf(2);

   for(auto g : m_groups)
      {
      const uint16_t id = static_cast<uint16_t>(g);

      if(id > 0)
         {
         buf.push_back(get_byte(0, id));
         buf.push_back(get_byte(1, id));
         }
      }

   buf[0] = get_byte(0, static_cast<uint16_t>(buf.size()-2));
   buf[1] = get_byte(1, static_cast<uint16_t>(buf.size()-2));

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

   for(size_t i = 0; i != len / 2; ++i)
      {
      const uint16_t id = reader.get_uint16_t();
      m_groups.push_back(static_cast<Group_Params>(id));
      }
   }

std::vector<uint8_t> Supported_Point_Formats::serialize() const
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

std::vector<uint8_t> Signature_Algorithms::serialize() const
   {
   std::vector<uint8_t> buf;

   const uint16_t len = m_schemes.size() * 2;

   buf.push_back(get_byte(0, len));
   buf.push_back(get_byte(1, len));

   for(Signature_Scheme scheme : m_schemes)
      {
      const uint16_t scheme_code = static_cast<uint16_t>(scheme);

      buf.push_back(get_byte(0, scheme_code));
      buf.push_back(get_byte(1, scheme_code));
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
      const uint16_t scheme_code = reader.get_uint16_t();
      m_schemes.push_back(static_cast<Signature_Scheme>(scheme_code));
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

std::vector<uint8_t> SRTP_Protection_Profiles::serialize() const
   {
   std::vector<uint8_t> buf;

   const uint16_t pp_len = static_cast<uint16_t>(m_pp.size() * 2);
   buf.push_back(get_byte(0, pp_len));
   buf.push_back(get_byte(1, pp_len));

   for(uint16_t pp : m_pp)
      {
      buf.push_back(get_byte(0, pp));
      buf.push_back(get_byte(1, pp));
      }

   buf.push_back(0); // srtp_mki, always empty here

   return buf;
   }

Extended_Master_Secret::Extended_Master_Secret(TLS_Data_Reader&,
                                               uint16_t extension_size)
   {
   if(extension_size != 0)
      throw Decoding_Error("Invalid extended_master_secret extension");
   }

std::vector<uint8_t> Extended_Master_Secret::serialize() const
   {
   return std::vector<uint8_t>();
   }

Encrypt_then_MAC::Encrypt_then_MAC(TLS_Data_Reader&,
                                   uint16_t extension_size)
   {
   if(extension_size != 0)
      throw Decoding_Error("Invalid encrypt_then_mac extension");
   }

std::vector<uint8_t> Encrypt_then_MAC::serialize() const
   {
   return std::vector<uint8_t>();
   }

std::vector<uint8_t> Certificate_Status_Request::serialize() const
   {
   std::vector<uint8_t> buf;

   if(m_server_side)
      return buf; // server reply is empty

   /*
   opaque ResponderID<1..2^16-1>;
   opaque Extensions<0..2^16-1>;

   CertificateStatusType status_type = ocsp(1)
   ResponderID responder_id_list<0..2^16-1>
   Extensions  request_extensions;
   */

   buf.push_back(1); // CertificateStatusType ocsp

   buf.push_back(0);
   buf.push_back(0);
   buf.push_back(0);
   buf.push_back(0);

   return buf;
   }

Certificate_Status_Request::Certificate_Status_Request(TLS_Data_Reader& reader,
                                                       uint16_t extension_size) :
   m_server_side(false)
   {
   if(extension_size > 0)
      {
      const uint8_t type = reader.get_byte();
      if(type == 1)
         {
         reader.discard_next(extension_size - 1); // fixme
         }
      else
         {
         reader.discard_next(extension_size - 1);
         }
      }
   }

Certificate_Status_Request::Certificate_Status_Request(const std::vector<X509_DN>& ocsp_responder_ids,
                                                       const std::vector<std::vector<uint8_t>>& ocsp_key_ids) :
   m_ocsp_names(ocsp_responder_ids),
   m_ocsp_keys(ocsp_key_ids),
   m_server_side(false)
   {

   }

Certificate_Status_Request::Certificate_Status_Request() : m_server_side(true)
   {

   }

}

}
