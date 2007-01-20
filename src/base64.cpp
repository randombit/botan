/*************************************************
* Base64 Encoder/Decoder Source File             *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/base64.h>
#include <botan/charset.h>
#include <algorithm>

namespace Botan {

/*************************************************
* Base64_Encoder Constructor                     *
*************************************************/
Base64_Encoder::Base64_Encoder(bool breaks, u32bit length, bool t_n) :
   line_length(breaks ? length : 0), trailing_newline(t_n)
   {
   in.create(48);
   out.create(4);

   counter = position = 0;
   }

/*************************************************
* Base64 Encoding Operation                      *
*************************************************/
void Base64_Encoder::encode(const byte in[3], byte out[4])
   {
   out[0] = BIN_TO_BASE64[((in[0] & 0xFC) >> 2)];
   out[1] = BIN_TO_BASE64[((in[0] & 0x03) << 4) | (in[1] >> 4)];
   out[2] = BIN_TO_BASE64[((in[1] & 0x0F) << 2) | (in[2] >> 6)];
   out[3] = BIN_TO_BASE64[((in[2] & 0x3F)     )];
   }

/*************************************************
* Encode and send a block                        *
*************************************************/
void Base64_Encoder::encode_and_send(const byte block[], u32bit length)
   {
   for(u32bit j = 0; j != length; j += 3)
      {
      encode(block + j, out);
      do_output(out, 4);
      }
   }

/*************************************************
* Handle the output                              *
*************************************************/
void Base64_Encoder::do_output(const byte input[], u32bit length)
   {
   if(line_length == 0)
      send(input, length);
   else
      {
      u32bit remaining = length, offset = 0;
      while(remaining)
         {
         u32bit sent = std::min(line_length - counter, remaining);
         send(input + offset, sent);
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
* Convert some data into Base64                  *
*************************************************/
void Base64_Encoder::write(const byte input[], u32bit length)
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
void Base64_Encoder::end_msg()
   {
   u32bit start_of_last_block = 3 * (position / 3),
          left_over = position % 3;
   encode_and_send(in, start_of_last_block);

   if(left_over)
      {
      SecureBuffer<byte, 3> remainder(in + start_of_last_block, left_over);

      encode(remainder, out);

      u32bit empty_bits = 8 * (3 - left_over), index = 4 - 1;
      while(empty_bits >= 8)
         {
         out[index--] = '=';
         empty_bits -= 6;
         }

      do_output(out, 4);
      }

   if(trailing_newline || (counter && line_length))
      send('\n');

   counter = position = 0;
   }

/*************************************************
* Base64_Decoder Constructor                     *
*************************************************/
Base64_Decoder::Base64_Decoder(Decoder_Checking c) : checking(c)
   {
   in.create(48);
   out.create(3);
   position = 0;
   }

/*************************************************
* Check if a character is a valid Base64 char    *
*************************************************/
bool Base64_Decoder::is_valid(byte in)
   {
   return (BASE64_TO_BIN[in] != 0x80);
   }

/*************************************************
* Base64 Decoding Operation                      *
*************************************************/
void Base64_Decoder::decode(const byte in[4], byte out[3])
   {
   out[0] = (byte)((BASE64_TO_BIN[in[0]] << 2) | (BASE64_TO_BIN[in[1]] >> 4));
   out[1] = (byte)((BASE64_TO_BIN[in[1]] << 4) | (BASE64_TO_BIN[in[2]] >> 2));
   out[2] = (byte)((BASE64_TO_BIN[in[2]] << 6) | (BASE64_TO_BIN[in[3]]));
   }

/*************************************************
* Decode and send a block                        *
*************************************************/
void Base64_Decoder::decode_and_send(const byte block[], u32bit length)
   {
   for(u32bit j = 0; j != length; j += 4)
      {
      decode(block + j, out);
      send(out, 3);
      }
   }

/*************************************************
* Handle processing an invalid character         *
*************************************************/
void Base64_Decoder::handle_bad_char(byte c)
   {
   if(c == '=' || checking == NONE)
      return;

   if((checking == IGNORE_WS) && Charset::is_space(c))
      return;

   throw Decoding_Error(
      std::string("Base64_Decoder: Invalid base64 character '") + (char)c + "'"
      );
   }

/*************************************************
* Convert some data from Base64                  *
*************************************************/
void Base64_Decoder::write(const byte input[], u32bit length)
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
void Base64_Decoder::end_msg()
   {
   if(position != 0)
      {
      u32bit start_of_last_block = 4 * (position / 4),
             left_over = position % 4;
      decode_and_send(in, start_of_last_block);

      if(left_over)
         {
         SecureBuffer<byte, 4> remainder(in + start_of_last_block, left_over);
         decode(remainder, out);
         send(out, ((left_over == 1) ? (1) : (left_over - 1)));
         }
      }
   position = 0;
   }

}
