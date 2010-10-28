/*
* Base64 Encoder/Decoder
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/b64_filt.h>
#include <botan/base64.h>
#include <botan/charset.h>
#include <botan/exceptn.h>
#include <algorithm>

namespace Botan {

/*
* Base64 Decoder Lookup Table
* Warning: assumes ASCII encodings
*/
static const byte BASE64_TO_BIN[256] = {
0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
0x80, 0x80, 0x80, 0x80, 0x3E, 0x80, 0x80, 0x80, 0x3F, 0x34, 0x35, 0x36, 0x37,
0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 };

/*
* Base64_Encoder Constructor
*/
Base64_Encoder::Base64_Encoder(bool breaks, size_t length, bool t_n) :
   line_length(breaks ? length : 0),
   trailing_newline(t_n && breaks),
   in(48),
   out(64),
   position(0),
   out_position(0)
   {
   }

/*
* Encode and send a block
*/
void Base64_Encoder::encode_and_send(const byte input[], size_t length)
   {
   while(length)
      {
      const size_t proc = std::min(length, in.size());

      size_t consumed = 0;
      size_t produced = base64_encode(reinterpret_cast<char*>(&out[0]), input,
                                      proc, consumed, false);

      do_output(&out[0], produced);

      input += proc;
      length -= proc;
      }
   }

/*
* Handle the output
*/
void Base64_Encoder::do_output(const byte input[], size_t length)
   {
   if(line_length == 0)
      send(input, length);
   else
      {
      size_t remaining = length, offset = 0;
      while(remaining)
         {
         size_t sent = std::min(line_length - out_position, remaining);
         send(input + offset, sent);
         out_position += sent;
         remaining -= sent;
         offset += sent;
         if(out_position == line_length)
            {
            send('\n');
            out_position = 0;
            }
         }
      }
   }

/*
* Convert some data into Base64
*/
void Base64_Encoder::write(const byte input[], size_t length)
   {
   in.copy(position, input, length);
   if(position + length >= in.size())
      {
      encode_and_send(&in[0], in.size());
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

/*
* Flush buffers
*/
void Base64_Encoder::end_msg()
   {
   size_t start_of_last_block = 3 * (position / 3),
          left_over = position % 3;
   encode_and_send(&in[0], start_of_last_block);

   if(left_over)
      {
      SecureVector<byte> remainder(3);
      copy_mem(&remainder[0], &in[start_of_last_block], left_over);

      size_t consumed;
      base64_encode(reinterpret_cast<char*>(&out[0]), &remainder[0], 3, consumed, false);

      size_t empty_bits = 8 * (3 - left_over), index = 4 - 1;
      while(empty_bits >= 8)
         {
         out[index--] = '=';
         empty_bits -= 6;
         }

      do_output(&out[0], 4);
      }

   if(trailing_newline || (out_position && line_length))
      send('\n');

   out_position = position = 0;
   }

/*
* Base64_Decoder Constructor
*/
Base64_Decoder::Base64_Decoder(Decoder_Checking c) : checking(c)
   {
   in.resize(48);
   out.resize(3);
   position = 0;
   }

/*
* Check if a character is a valid Base64 char
*/
bool Base64_Decoder::is_valid(byte in)
   {
   return (BASE64_TO_BIN[in] != 0x80);
   }

/*
* Base64 Decoding Operation
*/
void Base64_Decoder::decode(const byte in[4], byte out[3])
   {
   out[0] = ((BASE64_TO_BIN[in[0]] << 2) | (BASE64_TO_BIN[in[1]] >> 4));
   out[1] = ((BASE64_TO_BIN[in[1]] << 4) | (BASE64_TO_BIN[in[2]] >> 2));
   out[2] = ((BASE64_TO_BIN[in[2]] << 6) | (BASE64_TO_BIN[in[3]]));
   }

/*
* Decode and send a block
*/
void Base64_Decoder::decode_and_send(const byte block[], size_t length)
   {
   for(size_t i = 0; i != length; i += 4)
      {
      decode(block + i, &out[0]);
      send(out, 3);
      }
   }

/*
* Handle processing an invalid character
*/
void Base64_Decoder::handle_bad_char(byte c)
   {
   if(c == '=' || checking == NONE)
      return;

   if((checking == IGNORE_WS) && Charset::is_space(c))
      return;

   throw Decoding_Error(
      std::string("Base64_Decoder: Invalid base64 character '") +
      static_cast<char>(c) + "'"
      );
   }

/*
* Convert some data from Base64
*/
void Base64_Decoder::write(const byte input[], size_t length)
   {
   for(size_t i = 0; i != length; ++i)
      {
      if(is_valid(input[i]))
         in[position++] = input[i];
      else
         handle_bad_char(input[i]);

      if(position == in.size())
         {
         decode_and_send(&in[0], in.size());
         position = 0;
         }
      }
   }

/*
* Flush buffers
*/
void Base64_Decoder::end_msg()
   {
   if(position != 0)
      {
      size_t start_of_last_block = 4 * (position / 4),
             left_over = position % 4;
      decode_and_send(&in[0], start_of_last_block);

      if(left_over)
         {
         SecureVector<byte> remainder(4);
         copy_mem(&remainder[0], &in[start_of_last_block], left_over);
         decode(&remainder[0], &out[0]);
         send(out, ((left_over == 1) ? (1) : (left_over - 1)));
         }
      }
   position = 0;
   }

}
