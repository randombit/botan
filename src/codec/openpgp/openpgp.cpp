/*
* OpenPGP
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/openpgp.h>
#include <botan/filters.h>
#include <botan/charset.h>
#include <botan/crc24.h>

namespace Botan {

namespace OpenPGP {

/*
* OpenPGP Base64 encoding
*/
std::string encode(const byte input[], u32bit length,
                   const std::string& label,
                   const std::map<std::string, std::string>& headers)
   {
   const std::string PGP_HEADER = "-----BEGIN PGP " + label + "-----\n";
   const std::string PGP_TRAILER = "-----END PGP " + label + "-----\n";
   const u32bit PGP_WIDTH = 64;

   std::string pgp_encoded = PGP_HEADER;

   if(headers.find("Version") != headers.end())
      pgp_encoded += "Version: " + headers.find("Version")->second + '\n';

   std::map<std::string, std::string>::const_iterator i = headers.begin();
   while(i != headers.end())
      {
      if(i->first != "Version")
         pgp_encoded += i->first + ": " + i->second + '\n';
      ++i;
      }
   pgp_encoded += '\n';

   Pipe pipe(new Fork(
                new Base64_Encoder(true, PGP_WIDTH),
                new Chain(new Hash_Filter(new CRC24), new Base64_Encoder)
                )
      );

   pipe.process_msg(input, length);

   pgp_encoded += pipe.read_all_as_string(0);
   pgp_encoded += '=' + pipe.read_all_as_string(1) + '\n';
   pgp_encoded += PGP_TRAILER;

   return pgp_encoded;
   }

/*
* OpenPGP Base64 encoding
*/
std::string encode(const byte input[], u32bit length,
                   const std::string& type)
   {
   std::map<std::string, std::string> empty;
   return encode(input, length, type, empty);
   }

/*
* OpenPGP Base64 decoding
*/
SecureVector<byte> decode(DataSource& source, std::string& label,
                          std::map<std::string, std::string>& headers)
   {
   const u32bit RANDOM_CHAR_LIMIT = 5;

   const std::string PGP_HEADER1 = "-----BEGIN PGP ";
   const std::string PGP_HEADER2 = "-----";
   u32bit position = 0;

   while(position != PGP_HEADER1.length())
      {
      byte b;
      if(!source.read_byte(b))
         throw Decoding_Error("PGP: No PGP header found");
      if(b == PGP_HEADER1[position])
         ++position;
      else if(position >= RANDOM_CHAR_LIMIT)
         throw Decoding_Error("PGP: Malformed PGP header");
      else
         position = 0;
      }
   position = 0;
   while(position != PGP_HEADER2.length())
      {
      byte b;
      if(!source.read_byte(b))
         throw Decoding_Error("PGP: No PGP header found");
      if(b == PGP_HEADER2[position])
         ++position;
      else if(position)
         throw Decoding_Error("PGP: Malformed PGP header");

      if(position == 0)
         label += static_cast<char>(b);
      }

   headers.clear();
   bool end_of_headers = false;
   while(!end_of_headers)
      {
      std::string this_header;
      byte b = 0;
      while(b != '\n')
         {
         if(!source.read_byte(b))
            throw Decoding_Error("PGP: Bad armor header");
         if(b != '\n')
            this_header += static_cast<char>(b);
         }

      end_of_headers = true;
      for(u32bit j = 0; j != this_header.length(); ++j)
         if(!Charset::is_space(this_header[j]))
            end_of_headers = false;

      if(!end_of_headers)
         {
         std::string::size_type pos = this_header.find(": ");
         if(pos == std::string::npos)
            throw Decoding_Error("OpenPGP: Bad headers");

         std::string key = this_header.substr(0, pos);
         std::string value = this_header.substr(pos + 2, std::string::npos);
         headers[key] = value;
         }
      }

   Pipe base64(new Base64_Decoder,
               new Fork(0,
                        new Chain(new Hash_Filter(new CRC24),
                                  new Base64_Encoder)
                  )
      );
   base64.start_msg();

   const std::string PGP_TRAILER = "-----END PGP " + label + "-----";
   position = 0;
   bool newline_seen = 0;
   std::string crc;
   while(position != PGP_TRAILER.length())
      {
      byte b;
      if(!source.read_byte(b))
         throw Decoding_Error("PGP: No PGP trailer found");
      if(b == PGP_TRAILER[position])
         ++position;
      else if(position)
         throw Decoding_Error("PGP: Malformed PGP trailer");

      if(b == '=' && newline_seen)
         {
         while(b != '\n')
            {
            if(!source.read_byte(b))
               throw Decoding_Error("PGP: Bad CRC tail");
            if(b != '\n')
               crc += static_cast<char>(b);
            }
         }
      else if(b == '\n')
         newline_seen = true;
      else if(position == 0)
         {
         base64.write(b);
         newline_seen = false;
         }
      }
   base64.end_msg();

   if(crc != "" && crc != base64.read_all_as_string(1))
      throw Decoding_Error("PGP: Corrupt CRC");

   return base64.read_all();
   }

/*
* OpenPGP Base64 decoding
*/
SecureVector<byte> decode(DataSource& source, std::string& label)
   {
   std::map<std::string, std::string> ignored;
   return decode(source, label, ignored);
   }

}

}

