/*
* TLS Extensions
* (C) 2011,2012,2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_extensions.h>
#include <botan/internal/tls_reader.h>
#include <botan/tls_exceptn.h>

namespace Botan {

namespace TLS {

namespace {

Extension* make_extension(TLS_Data_Reader& reader,
                          u16bit code,
                          u16bit size)
   {
   switch(code)
      {
      case TLSEXT_SERVER_NAME_INDICATION:
         return new Server_Name_Indicator(reader, size);

#if defined(BOTAN_HAS_SRP6)
      case TLSEXT_SRP_IDENTIFIER:
         return new SRP_Identifier(reader, size);
#endif

      case TLSEXT_USABLE_ELLIPTIC_CURVES:
         return new Supported_Elliptic_Curves(reader, size);

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

      case TLSEXT_SESSION_TICKET:
         return new Session_Ticket(reader, size);

      default:
         return nullptr; // not known
      }
   }

}

void Extensions::deserialize(TLS_Data_Reader& reader)
   {
   if(reader.has_remaining())
      {
      const u16bit all_extn_size = reader.get_u16bit();

      if(reader.remaining_bytes() != all_extn_size)
         throw Decoding_Error("Bad extension size");

      while(reader.has_remaining())
         {
         const u16bit extension_code = reader.get_u16bit();
         const u16bit extension_size = reader.get_u16bit();

         Extension* extn = make_extension(reader,
                                          extension_code,
                                          extension_size);

         if(extn)
            this->add(extn);
         else // unknown/unhandled extension
            reader.discard_next(extension_size);
         }
      }
   }

std::vector<byte> Extensions::serialize() const
   {
   std::vector<byte> buf(2); // 2 bytes for length field

   for(auto& extn : m_extensions)
      {
      if(extn.second->empty())
         continue;

      const u16bit extn_code = extn.second->type();

      std::vector<byte> extn_val = extn.second->serialize();

      buf.push_back(get_byte(0, extn_code));
      buf.push_back(get_byte(1, extn_code));

      buf.push_back(get_byte(0, static_cast<u16bit>(extn_val.size())));
      buf.push_back(get_byte(1, static_cast<u16bit>(extn_val.size())));

      buf += extn_val;
      }

   const u16bit extn_size = static_cast<u16bit>(buf.size() - 2);

   buf[0] = get_byte(0, extn_size);
   buf[1] = get_byte(1, extn_size);

   // avoid sending a completely empty extensions block
   if(buf.size() == 2)
      return std::vector<byte>();

   return buf;
   }

std::set<Handshake_Extension_Type> Extensions::extension_types() const
   {
   std::set<Handshake_Extension_Type> offers;
   for(auto i = m_extensions.begin(); i != m_extensions.end(); ++i)
      offers.insert(i->first);
   return offers;
   }

Server_Name_Indicator::Server_Name_Indicator(TLS_Data_Reader& reader,
                                             u16bit extension_size)
   {
   /*
   * This is used by the server to confirm that it knew the name
   */
   if(extension_size == 0)
      return;

   u16bit name_bytes = reader.get_u16bit();

   if(name_bytes + 2 != extension_size)
      throw Decoding_Error("Bad encoding of SNI extension");

   while(name_bytes)
      {
      byte name_type = reader.get_byte();
      name_bytes--;

      if(name_type == 0) // DNS
         {
         m_sni_host_name = reader.get_string(2, 1, 65535);
         name_bytes -= static_cast<u16bit>(2 + m_sni_host_name.size());
         }
      else // some other unknown name type
         {
         reader.discard_next(name_bytes);
         name_bytes = 0;
         }
      }
   }

std::vector<byte> Server_Name_Indicator::serialize() const
   {
   std::vector<byte> buf;

   size_t name_len = m_sni_host_name.size();

   buf.push_back(get_byte(0, static_cast<u16bit>(name_len+3)));
   buf.push_back(get_byte(1, static_cast<u16bit>(name_len+3)));
   buf.push_back(0); // DNS

   buf.push_back(get_byte(0, static_cast<u16bit>(name_len)));
   buf.push_back(get_byte(1, static_cast<u16bit>(name_len)));

   buf += std::make_pair(
      reinterpret_cast<const byte*>(m_sni_host_name.data()),
      m_sni_host_name.size());

   return buf;
   }

#if defined(BOTAN_HAS_SRP6)

SRP_Identifier::SRP_Identifier(TLS_Data_Reader& reader,
                               u16bit extension_size) : m_srp_identifier(reader.get_string(1, 1, 255))
   {
   if(m_srp_identifier.size() + 1 != extension_size)
      throw Decoding_Error("Bad encoding for SRP identifier extension");
   }

std::vector<byte> SRP_Identifier::serialize() const
   {
   std::vector<byte> buf;

   const byte* srp_bytes =
      reinterpret_cast<const byte*>(m_srp_identifier.data());

   append_tls_length_value(buf, srp_bytes, m_srp_identifier.size(), 1);

   return buf;
   }

#endif

Renegotiation_Extension::Renegotiation_Extension(TLS_Data_Reader& reader,
                                                 u16bit extension_size) : m_reneg_data(reader.get_range<byte>(1, 0, 255))
   {
   if(m_reneg_data.size() + 1 != extension_size)
      throw Decoding_Error("Bad encoding for secure renegotiation extn");
   }

std::vector<byte> Renegotiation_Extension::serialize() const
   {
   std::vector<byte> buf;
   append_tls_length_value(buf, m_reneg_data, 1);
   return buf;
   }

Application_Layer_Protocol_Notification::Application_Layer_Protocol_Notification(TLS_Data_Reader& reader,
                                                                                 u16bit extension_size)
   {
   if(extension_size == 0)
      return; // empty extension

   const u16bit name_bytes = reader.get_u16bit();

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

std::vector<byte> Application_Layer_Protocol_Notification::serialize() const
   {
   std::vector<byte> buf(2);

   for(auto&& p: m_protocols)
      {
      if(p.length() >= 256)
         throw TLS_Exception(Alert::INTERNAL_ERROR, "ALPN name too long");
      if(p != "")
         append_tls_length_value(buf,
                                 reinterpret_cast<const byte*>(p.data()),
                                 p.size(),
                                 1);
      }

   buf[0] = get_byte(0, static_cast<u16bit>(buf.size()-2));
   buf[1] = get_byte(1, static_cast<u16bit>(buf.size()-2));

   return buf;
   }

std::string Supported_Elliptic_Curves::curve_id_to_name(u16bit id)
   {
   switch(id)
      {
      case 23:
         return "secp256r1";
      case 24:
         return "secp384r1";
      case 25:
         return "secp521r1";
      case 26:
         return "brainpool256r1";
      case 27:
         return "brainpool384r1";
      case 28:
         return "brainpool512r1";
      default:
         return ""; // something we don't know or support
      }
   }

u16bit Supported_Elliptic_Curves::name_to_curve_id(const std::string& name)
   {
   if(name == "secp256r1")
      return 23;
   if(name == "secp384r1")
      return 24;
   if(name == "secp521r1")
      return 25;
   if(name == "brainpool256r1")
      return 26;
   if(name == "brainpool384r1")
      return 27;
   if(name == "brainpool512r1")
      return 28;

   throw Invalid_Argument("name_to_curve_id unknown name " + name);
   }

std::vector<byte> Supported_Elliptic_Curves::serialize() const
   {
   std::vector<byte> buf(2);

   for(size_t i = 0; i != m_curves.size(); ++i)
      {
      const u16bit id = name_to_curve_id(m_curves[i]);
      buf.push_back(get_byte(0, id));
      buf.push_back(get_byte(1, id));
      }

   buf[0] = get_byte(0, static_cast<u16bit>(buf.size()-2));
   buf[1] = get_byte(1, static_cast<u16bit>(buf.size()-2));

   return buf;
   }

Supported_Elliptic_Curves::Supported_Elliptic_Curves(TLS_Data_Reader& reader,
                                                     u16bit extension_size)
   {
   u16bit len = reader.get_u16bit();

   if(len + 2 != extension_size)
      throw Decoding_Error("Inconsistent length field in elliptic curve list");

   if(len % 2 == 1)
      throw Decoding_Error("Elliptic curve list of strange size");

   len /= 2;

   for(size_t i = 0; i != len; ++i)
      {
      const u16bit id = reader.get_u16bit();
      const std::string name = curve_id_to_name(id);

      if(!name.empty())
         m_curves.push_back(name);
      }
   }

std::string Signature_Algorithms::hash_algo_name(byte code)
   {
   switch(code)
      {
      // code 1 is MD5 - ignore it

      case 2:
         return "SHA-1";

      // code 3 is SHA-224

      case 4:
         return "SHA-256";
      case 5:
         return "SHA-384";
      case 6:
         return "SHA-512";
      default:
         return "";
      }
   }

byte Signature_Algorithms::hash_algo_code(const std::string& name)
   {
   if(name == "SHA-1")
      return 2;

   if(name == "SHA-256")
      return 4;

   if(name == "SHA-384")
      return 5;

   if(name == "SHA-512")
      return 6;

   throw Internal_Error("Unknown hash ID " + name + " for signature_algorithms");
   }

std::string Signature_Algorithms::sig_algo_name(byte code)
   {
   switch(code)
      {
      case 1:
         return "RSA";
      case 2:
         return "DSA";
      case 3:
         return "ECDSA";
      default:
         return "";
      }
   }

byte Signature_Algorithms::sig_algo_code(const std::string& name)
   {
   if(name == "RSA")
      return 1;

   if(name == "DSA")
      return 2;

   if(name == "ECDSA")
      return 3;

   throw Internal_Error("Unknown sig ID " + name + " for signature_algorithms");
   }

std::vector<byte> Signature_Algorithms::serialize() const
   {
   std::vector<byte> buf(2);

   for(size_t i = 0; i != m_supported_algos.size(); ++i)
      {
      try
         {
         const byte hash_code = hash_algo_code(m_supported_algos[i].first);
         const byte sig_code = sig_algo_code(m_supported_algos[i].second);

         buf.push_back(hash_code);
         buf.push_back(sig_code);
         }
      catch(...)
         {}
      }

   buf[0] = get_byte(0, static_cast<u16bit>(buf.size()-2));
   buf[1] = get_byte(1, static_cast<u16bit>(buf.size()-2));

   return buf;
   }

Signature_Algorithms::Signature_Algorithms(const std::vector<std::string>& hashes,
                                           const std::vector<std::string>& sigs)
   {
   for(size_t i = 0; i != hashes.size(); ++i)
      for(size_t j = 0; j != sigs.size(); ++j)
         m_supported_algos.push_back(std::make_pair(hashes[i], sigs[j]));
   }

Signature_Algorithms::Signature_Algorithms(TLS_Data_Reader& reader,
                                           u16bit extension_size)
   {
   u16bit len = reader.get_u16bit();

   if(len + 2 != extension_size)
      throw Decoding_Error("Bad encoding on signature algorithms extension");

   while(len)
      {
      const std::string hash_code = hash_algo_name(reader.get_byte());
      const std::string sig_code = sig_algo_name(reader.get_byte());

      len -= 2;

      // If not something we know, ignore it completely
      if(hash_code.empty() || sig_code.empty())
         continue;

      m_supported_algos.push_back(std::make_pair(hash_code, sig_code));
      }
   }

Session_Ticket::Session_Ticket(TLS_Data_Reader& reader,
                               u16bit extension_size) : m_ticket(reader.get_elem<byte, std::vector<byte>>(extension_size))
   {}

SRTP_Protection_Profiles::SRTP_Protection_Profiles(TLS_Data_Reader& reader,
                                                   u16bit extension_size) : m_pp(reader.get_range<u16bit>(2, 0, 65535))
   {
   const std::vector<byte> mki = reader.get_range<byte>(1, 0, 255);

   if(m_pp.size() * 2 + mki.size() + 3 != extension_size)
      throw Decoding_Error("Bad encoding for SRTP protection extension");

   if(!mki.empty())
      throw Decoding_Error("Unhandled non-empty MKI for SRTP protection extension");
   }

std::vector<byte> SRTP_Protection_Profiles::serialize() const
   {
   std::vector<byte> buf;

   const u16bit pp_len = static_cast<u16bit>(m_pp.size() * 2);
   buf.push_back(get_byte(0, pp_len));
   buf.push_back(get_byte(1, pp_len));

   for(u16bit pp : m_pp)
      {
      buf.push_back(get_byte(0, pp));
      buf.push_back(get_byte(1, pp));
      }

   buf.push_back(0); // srtp_mki, always empty here

   return buf;
   }

Extended_Master_Secret::Extended_Master_Secret(TLS_Data_Reader&,
                                               u16bit extension_size)
   {
   if(extension_size != 0)
      throw Decoding_Error("Invalid extended_master_secret extension");
   }

std::vector<byte> Extended_Master_Secret::serialize() const
   {
   return std::vector<byte>();
   }

}

}
