/*************************************************
* PEM Encoding/Decoding Source File              *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/pem.h>
#include <botan/config.h>
#include <botan/filters.h>
#include <botan/parsing.h>

namespace Botan {

namespace PEM_Code {

/*************************************************
* PEM encode BER/DER-encoded objects             *
*************************************************/
std::string encode(const byte der[], u32bit length, const std::string& label)
   {
   const u32bit PEM_WIDTH = global_config().option_as_u32bit("pem/width");

   if(PEM_WIDTH < 50 || PEM_WIDTH > 76)
      throw Encoding_Error("PEM: Invalid line width " + to_string(PEM_WIDTH));

   const std::string PEM_HEADER = "-----BEGIN " + label + "-----\n";
   const std::string PEM_TRAILER = "-----END " + label + "-----\n";

   Pipe pipe(new Base64_Encoder(true, PEM_WIDTH));
   pipe.process_msg(der, length);
   return (PEM_HEADER + pipe.read_all_as_string() + PEM_TRAILER);
   }

/*************************************************
* PEM encode BER/DER-encoded objects             *
*************************************************/
std::string encode(const MemoryRegion<byte>& data, const std::string& label)
   {
   return encode(data, data.size(), label);
   }

/*************************************************
* Decode PEM down to raw BER/DER                 *
*************************************************/
SecureVector<byte> decode_check_label(DataSource& source,
                                      const std::string& label_want)
   {
   std::string label_got;
   SecureVector<byte> ber = decode(source, label_got);
   if(label_got != label_want)
      throw Decoding_Error("PEM: Label mismatch, wanted " + label_want +
                           ", got " + label_got);
   return ber;
   }

/*************************************************
* Decode PEM down to raw BER/DER                 *
*************************************************/
SecureVector<byte> decode(DataSource& source, std::string& label)
   {
   const u32bit RANDOM_CHAR_LIMIT =
      global_config().option_as_u32bit("pem/forgive");

   const std::string PEM_HEADER1 = "-----BEGIN ";
   const std::string PEM_HEADER2 = "-----";
   u32bit position = 0;

   while(position != PEM_HEADER1.length())
      {
      byte b;
      if(!source.read_byte(b))
         throw Decoding_Error("PEM: No PEM header found");
      if(b == PEM_HEADER1[position])
         ++position;
      else if(position >= RANDOM_CHAR_LIMIT)
         throw Decoding_Error("PEM: Malformed PEM header");
      else
         position = 0;
      }
   position = 0;
   while(position != PEM_HEADER2.length())
      {
      byte b;
      if(!source.read_byte(b))
         throw Decoding_Error("PEM: No PEM header found");
      if(b == PEM_HEADER2[position])
         ++position;
      else if(position)
         throw Decoding_Error("PEM: Malformed PEM header");

      if(position == 0)
         label += static_cast<char>(b);
      }

   Pipe base64(new Base64_Decoder);
   base64.start_msg();

   const std::string PEM_TRAILER = "-----END " + label + "-----";
   position = 0;
   while(position != PEM_TRAILER.length())
      {
      byte b;
      if(!source.read_byte(b))
         throw Decoding_Error("PEM: No PEM trailer found");
      if(b == PEM_TRAILER[position])
         ++position;
      else if(position)
         throw Decoding_Error("PEM: Malformed PEM trailer");

      if(position == 0)
         base64.write(b);
      }
   base64.end_msg();
   return base64.read_all();
   }

/*************************************************
* Search for a PEM signature                     *
*************************************************/
bool matches(DataSource& source, const std::string& extra)
   {
   const u32bit PEM_SEARCH_RANGE =
      global_config().option_as_u32bit("pem/search");

   const std::string PEM_HEADER = "-----BEGIN " + extra;

   SecureVector<byte> search_buf(PEM_SEARCH_RANGE);
   u32bit got = source.peek(search_buf, search_buf.size(), 0);

   if(got < PEM_HEADER.length())
      return false;

   u32bit index = 0;

   for(u32bit j = 0; j != got; ++j)
      {
      if(search_buf[j] == PEM_HEADER[index])
         ++index;
      else
         index = 0;
      if(index == PEM_HEADER.size())
         return true;
      }
   return false;
   }

}

}
