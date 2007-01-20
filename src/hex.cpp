/*************************************************
* Hex Encoder/Decoder Source File                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/hex.h>
#include <botan/bit_ops.h>
#include <botan/parsing.h>
#include <botan/charset.h>
#include <algorithm>

namespace Botan {

/*************************************************
* Hex_Encoder Constructor                        *
*************************************************/
Hex_Encoder::Hex_Encoder(bool breaks, u32bit length, Case c) :
   casing(c), line_length(breaks ? length : 0)
   {
   in.create(64);
   out.create(2*in.size());
   counter = position = 0;
   }

/*************************************************
* Hex_Encoder Constructor                        *
*************************************************/
Hex_Encoder::Hex_Encoder(Case c) : casing(c), line_length(0)
   {
   in.create(64);
   out.create(2*in.size());
   counter = position = 0;
   }

/*************************************************
* Hex Encoding Operation                         *
*************************************************/
void Hex_Encoder::encode(byte in, byte out[2], Hex_Encoder::Case casing)
   {
   const byte* BIN_TO_HEX = ((casing == Uppercase) ? BIN_TO_HEX_UPPER :
                                                     BIN_TO_HEX_LOWER);

   out[0] = BIN_TO_HEX[((in >> 4) & 0x0F)];
   out[1] = BIN_TO_HEX[((in     ) & 0x0F)];
   }

/*************************************************
* Encode and send a block                        *
*************************************************/
void Hex_Encoder::encode_and_send(const byte block[], u32bit length)
   {
   for(u32bit j = 0; j != length; ++j)
      encode(block[j], out + 2*j, casing);

   if(line_length == 0)
      send(out, 2*length);
   else
      {
      u32bit remaining = 2*length, offset = 0;
      while(remaining)
         {
         u32bit sent = std::min(line_length - counter, remaining);
         send(out + offset, sent);
         counter += sent;
         remaining -= sent;
         offset += sent;
         if(counter == line_length)
            {
            send('\n');
            counter = 0;
            }
         }
      }
   }

/*************************************************
* Convert some data into hex format              *
*************************************************/
void Hex_Encoder::write(const byte input[], u32bit length)
   {
   in.copy(position, input, length);
   if(position + length >= in.size())
      {
      encode_and_send(in, in.size());
      input += (in.size() - position);
      length -= (in.size() - position);
      while(length >= in.size())
         {
         encode_and_send(input, in.size());
         input += in.size();
         length -= in.size();
         }
      in.copy(input, length);
      position = 0;
      }
   position += length;
   }

/*************************************************
* Flush buffers                                  *
*************************************************/
void Hex_Encoder::end_msg()
   {
   encode_and_send(in, position);
   if(counter && line_length)
      send('\n');
   counter = position = 0;
   }

/*************************************************
* Hex_Decoder Constructor                        *
*************************************************/
Hex_Decoder::Hex_Decoder(Decoder_Checking c) : checking(c)
   {
   in.create(64);
   out.create(in.size() / 2);
   position = 0;
   }

/*************************************************
* Check if a character is a valid hex char       *
*************************************************/
bool Hex_Decoder::is_valid(byte in)
   {
   return (HEX_TO_BIN[in] != 0x80);
   }

/*************************************************
* Handle processing an invalid character         *
*************************************************/
void Hex_Decoder::handle_bad_char(byte c)
   {
   if(checking == NONE)
      return;

   if((checking == IGNORE_WS) && Charset::is_space(c))
      return;

   throw Decoding_Error("Hex_Decoder: Invalid hex character: " +
                        to_string(c));
   }

/*************************************************
* Hex Decoding Operation                         *
*************************************************/
byte Hex_Decoder::decode(const byte hex[2])
   {
   return (byte)((HEX_TO_BIN[hex[0]] << 4) | HEX_TO_BIN[hex[1]]);
   }

/*************************************************
* Decode and send a block                        *
*************************************************/
void Hex_Decoder::decode_and_send(const byte block[], u32bit length)
   {
   for(u32bit j = 0; j != length / 2; ++j)
      out[j] = decode(block + 2*j);
   send(out, length / 2);
   }

/*************************************************
* Convert some data from hex format              *
*************************************************/
void Hex_Decoder::write(const byte input[], u32bit length)
   {
   for(u32bit j = 0; j != length; ++j)
      {
      if(is_valid(input[j]))
         in[position++] = input[j];
      else
         handle_bad_char(input[j]);
      if(position == in.size())
         {
         decode_and_send(in, in.size());
         position = 0;
         }
      }
   }

/*************************************************
* Flush buffers                                  *
*************************************************/
void Hex_Decoder::end_msg()
   {
   decode_and_send(in, position);
   position = 0;
   }

}
