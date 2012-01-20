/*
* TLS Extensions
* (C) 2011,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_extensions.h>
#include <botan/internal/tls_reader.h>
#include <botan/tls_exceptn.h>

namespace Botan {

namespace {

TLS_Extension* make_extension(TLS_Data_Reader& reader,
                              u16bit code,
                              u16bit size)
   {
   if(code == TLSEXT_SERVER_NAME_INDICATION)
      return new Server_Name_Indicator(reader, size);
   else if(code == TLSEXT_MAX_FRAGMENT_LENGTH)
      return new Maximum_Fragment_Length(reader, size);
   else if(code == TLSEXT_SRP_IDENTIFIER)
      return new SRP_Identifier(reader, size);
   else if(code == TLSEXT_SAFE_RENEGOTIATION)
      return new Renegotation_Extension(reader, size);
   else if(code == TLSEXT_SIGNATURE_ALGORITHMS)
      return new Signature_Algorithms(reader, size);
   else if(code == TLSEXT_NEXT_PROTOCOL)
      return new Next_Protocol_Notification(reader, size);
   else
      return 0; // not known
   }

}

TLS_Extensions::TLS_Extensions(TLS_Data_Reader& reader)
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

         TLS_Extension* extn = make_extension(reader,
                                              extension_code,
                                              extension_size);

         if(extn)
            this->add(extn);
         else // unknown/unhandled extension
            reader.discard_next(extension_size);
         }
      }
   }

MemoryVector<byte> TLS_Extensions::serialize() const
   {
   MemoryVector<byte> buf(2); // 2 bytes for length field

   for(std::map<TLS_Handshake_Extension_Type, TLS_Extension*>::const_iterator i = extensions.begin();
       i != extensions.end(); ++i)
      {
      if(i->second->empty())
         continue;

      const u16bit extn_code = i->second->type();

      MemoryVector<byte> extn_val = i->second->serialize();

      buf.push_back(get_byte(0, extn_code));
      buf.push_back(get_byte(1, extn_code));

      buf.push_back(get_byte<u16bit>(0, extn_val.size()));
      buf.push_back(get_byte<u16bit>(1, extn_val.size()));

      buf += extn_val;
      }

   const u16bit extn_size = buf.size() - 2;

   buf[0] = get_byte(0, extn_size);
   buf[1] = get_byte(1, extn_size);

   // avoid sending a completely empty extensions block
   if(buf.size() == 2)
      return MemoryVector<byte>();

   return buf;
   }

TLS_Extensions::~TLS_Extensions()
   {
   for(std::map<TLS_Handshake_Extension_Type, TLS_Extension*>::const_iterator i = extensions.begin();
       i != extensions.end(); ++i)
      {
      delete i->second;
      }

   extensions.clear();
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
         sni_host_name = reader.get_string(2, 1, 65535);
         name_bytes -= (2 + sni_host_name.size());
         }
      else // some other unknown name type
         {
         reader.discard_next(name_bytes);
         name_bytes = 0;
         }
      }
   }

MemoryVector<byte> Server_Name_Indicator::serialize() const
   {
   MemoryVector<byte> buf;

   size_t name_len = sni_host_name.size();

   buf.push_back(get_byte<u16bit>(0, name_len+3));
   buf.push_back(get_byte<u16bit>(1, name_len+3));
   buf.push_back(0); // DNS

   buf.push_back(get_byte<u16bit>(0, name_len));
   buf.push_back(get_byte<u16bit>(1, name_len));

   buf += std::make_pair(
      reinterpret_cast<const byte*>(sni_host_name.data()),
      sni_host_name.size());

   return buf;
   }

SRP_Identifier::SRP_Identifier(TLS_Data_Reader& reader,
                               u16bit extension_size)
   {
   srp_identifier = reader.get_string(1, 1, 255);

   if(srp_identifier.size() + 1 != extension_size)
      throw Decoding_Error("Bad encoding for SRP identifier extension");
   }

MemoryVector<byte> SRP_Identifier::serialize() const
   {
   MemoryVector<byte> buf;

   const byte* srp_bytes =
      reinterpret_cast<const byte*>(srp_identifier.data());

   append_tls_length_value(buf, srp_bytes, srp_identifier.size(), 1);

   return buf;
   }

Renegotation_Extension::Renegotation_Extension(TLS_Data_Reader& reader,
                                               u16bit extension_size)
   {
   reneg_data = reader.get_range<byte>(1, 0, 255);

   if(reneg_data.size() + 1 != extension_size)
      throw Decoding_Error("Bad encoding for secure renegotiation extn");
   }

MemoryVector<byte> Renegotation_Extension::serialize() const
   {
   MemoryVector<byte> buf;
   append_tls_length_value(buf, reneg_data, 1);
   return buf;
   }

size_t Maximum_Fragment_Length::fragment_size() const
   {
   switch(val)
      {
      case 1:
         return 512;
      case 2:
         return 1024;
      case 3:
         return 2048;
      case 4:
         return 4096;
      default:
         throw TLS_Exception(ILLEGAL_PARAMETER,
                             "Bad value in maximum fragment extension");
      }
   }

Maximum_Fragment_Length::Maximum_Fragment_Length(size_t max_fragment)
   {
   if(max_fragment == 512)
      val = 1;
   else if(max_fragment == 1024)
      val = 2;
   else if(max_fragment == 2048)
      val = 3;
   else if(max_fragment == 4096)
      val = 4;
   else
      throw std::invalid_argument("Bad setting " + to_string(max_fragment) +
                                  " for maximum fragment size");
   }

Maximum_Fragment_Length::Maximum_Fragment_Length(TLS_Data_Reader& reader,
                                                 u16bit extension_size)
   {
   if(extension_size != 1)
      throw Decoding_Error("Bad size for maximum fragment extension");
   val = reader.get_byte();
   }

Next_Protocol_Notification::Next_Protocol_Notification(TLS_Data_Reader& reader,
                                                       u16bit extension_size)
   {
   if(extension_size == 0)
      return; // empty extension

   size_t bytes_remaining = extension_size;

   while(bytes_remaining)
      {
      const std::string p = reader.get_string(1, 0, 255);

      if(bytes_remaining < p.size() + 1)
         throw Decoding_Error("Bad encoding for next protocol extension");

      bytes_remaining -= (p.size() + 1);

      m_protocols.push_back(p);
      }
   }

MemoryVector<byte> Next_Protocol_Notification::serialize() const
   {
   MemoryVector<byte> buf;

   for(size_t i = 0; i != m_protocols.size(); ++i)
      {
      const std::string p = m_protocols[i];

      if(p != "")
         append_tls_length_value(buf,
                                 reinterpret_cast<const byte*>(p.data()),
                                 p.size(),
                                 1);
      }

   return buf;
   }

std::string Signature_Algorithms::hash_algo_name(byte code)
   {
   switch(code)
      {
      // code 1 is MD5 - ignore it

      case 2:
         return "SHA-1";
      case 3:
         return "SHA-224";
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

   if(name == "SHA-224")
      return 3;

   if(name == "SHA-256")
      return 4;

   if(name == "SHA-384")
      return 5;

   if(name == "SHA-512")
      return 6;

   throw Algorithm_Not_Found("Unknown hash ID for signature_algorithms");
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

   throw Algorithm_Not_Found("Unknown sig ID for signature_algorithms");
   }

MemoryVector<byte> Signature_Algorithms::serialize() const
   {
   MemoryVector<byte> buf(2);

   for(size_t i = 0; i != m_supported_algos.size(); ++i)
      {
      buf.push_back(hash_algo_code(m_supported_algos[i].first));
      buf.push_back(sig_algo_code(m_supported_algos[i].second));
      }

   buf[0] = get_byte<u16bit>(0, buf.size()-2);
   buf[1] = get_byte<u16bit>(1, buf.size()-2);

   return buf;
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

      // If not something we know, ignore it completely
      if(hash_code == "" || sig_code == "")
         continue;

      m_supported_algos.push_back(std::make_pair(hash_code, sig_code));

      len -= 2;
      }
   }

}
