/*
* TLS Extensions
* (C) 2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_extensions.h>
#include <botan/internal/tls_reader.h>

#include <stdio.h>

namespace Botan {

TLS_Extensions::TLS_Extensions(class TLS_Data_Reader& reader)
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

         if(extension_code == TLSEXT_SERVER_NAME_INDICATION)
            extensions.push_back(new Server_Name_Indicator(reader));
         else if(extension_code == TLSEXT_SRP_IDENTIFIER)
            extensions.push_back(new SRP_Identifier(reader));
         else // unknown/unhandled extension
            {
            printf("Unknown extension code %d\n", extension_code);
            reader.discard_next(extension_size);
            }
         }
      }
   }

MemoryVector<byte> TLS_Extensions::serialize() const
   {
   MemoryVector<byte> buf(2); // allocate length

   for(size_t i = 0; i != extensions.size(); ++i)
      {
      if(extensions[i]->empty())
         continue;

      const u16bit extn_code = extensions[i]->type();

      MemoryVector<byte> extn_val = extensions[i]->serialize();

      printf("serializing extn %d of %d bytes\n", extn_code, extn_val.size());

      buf.push_back(get_byte(0, extn_code));
      buf.push_back(get_byte(1, extn_code));

      buf.push_back(get_byte<u16bit>(0, extn_val.size()));
      buf.push_back(get_byte<u16bit>(1, extn_val.size()));

      buf += extn_val;
      }

   const u16bit extn_size = buf.size() - 2;

   buf[0] = get_byte(0, extn_size);
   buf[1] = get_byte(1, extn_size);

   printf("%d bytes of extensions\n", buf.size());

   // avoid sending an empty extensions block
   if(buf.size() == 2)
      return MemoryVector<byte>();

   return buf;
   }

TLS_Extensions::~TLS_Extensions()
   {
   for(size_t i = 0; i != extensions.size(); ++i)
      delete extensions[i];
   extensions.clear();
   }

Server_Name_Indicator::Server_Name_Indicator(TLS_Data_Reader& reader)
   {
   u16bit name_bytes = reader.get_u16bit();

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

   printf("serializing %d bytes %s\n", buf.size(),
          sni_host_name.c_str());
   return buf;
   }

SRP_Identifier::SRP_Identifier(TLS_Data_Reader& reader)
   {
   srp_identifier = reader.get_string(1, 1, 255);
   }

MemoryVector<byte> SRP_Identifier::serialize() const
   {
   MemoryVector<byte> buf;

   const byte* srp_bytes =
      reinterpret_cast<const byte*>(srp_identifier.data());

   append_tls_length_value(buf, srp_bytes, srp_identifier.size(), 1);

   return buf;
   }


}
