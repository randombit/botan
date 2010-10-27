/*
* Base64 Encoder/Decoder
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/b64_filt.h>
#include <botan/charset.h>
#include <botan/exceptn.h>
#include <algorithm>

namespace Botan {

/*
* Base64 Encoder Lookup Table
*/
const byte Base64_Encoder::BIN_TO_BASE64[64] = {
0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A,
0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D,
0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A,
0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x2B, 0x2F };

/*
* Base64 Decoder Lookup Table
*/
const byte Base64_Decoder::BASE64_TO_BIN[256] = {
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
   line_length(breaks ? length : 0), trailing_newline(t_n)
   {
   in.resize(48);
   out.resize(4);

   counter = position = 0;
   }

/*
* Base64 Encoding Operation
*/
void Base64_Encoder::encode(const byte in[3], byte out[4])
   {
   out[0] = BIN_TO_BASE64[((in[0] & 0xFC) >> 2)];
   out[1] = BIN_TO_BASE64[((in[0] & 0x03) << 4) | (in[1] >> 4)];
   out[2] = BIN_TO_BASE64[((in[1] & 0x0F) << 2) | (in[2] >> 6)];
   out[3] = BIN_TO_BASE64[((in[2] & 0x3F)     )];
   }

/*
* Encode and send a block
*/
void Base64_Encoder::encode_and_send(const byte block[], size_t length)
   {
   for(size_t j = 0; j != length; j += 3)
      {
      encode(block + j, &out[0]);
      do_output(&out[0], 4);
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
         size_t sent = std::min(line_length - counter, remaining);
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

      encode(&remainder[0], &out[0]);

      size_t empty_bits = 8 * (3 - left_over), index = 4 - 1;
      while(empty_bits >= 8)
         {
         out[index--] = '=';
         empty_bits -= 6;
         }

      do_output(&out[0], 4);
      }

   if(trailing_newline || (counter && line_length))
      send('\n');

   counter = position = 0;
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
   for(size_t j = 0; j != length; j += 4)
      {
      decode(block + j, &out[0]);
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
   for(size_t j = 0; j != length; ++j)
      {
      if(is_valid(input[j]))
         in[position++] = input[j];
      else
         handle_bad_char(input[j]);

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
