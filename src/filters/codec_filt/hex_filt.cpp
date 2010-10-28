/*
* Hex Encoder/Decoder
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/hex_filt.h>
#include <botan/hex.h>
#include <botan/parsing.h>
#include <botan/charset.h>
#include <botan/exceptn.h>
#include <algorithm>

namespace Botan {

/**
* Size used for internal buffer in hex encoder/decoder
*/
const size_t HEX_CODEC_BUFFER_SIZE = 256;

/*
* Hex_Encoder Constructor
*/
Hex_Encoder::Hex_Encoder(bool breaks, size_t length, Case c) :
   casing(c), line_length(breaks ? length : 0)
   {
   in.resize(HEX_CODEC_BUFFER_SIZE);
   out.resize(2*in.size());
   counter = position = 0;
   }

/*
* Hex_Encoder Constructor
*/
Hex_Encoder::Hex_Encoder(Case c) : casing(c), line_length(0)
   {
   in.resize(HEX_CODEC_BUFFER_SIZE);
   out.resize(2*in.size());
   counter = position = 0;
   }

/*
* Encode and send a block
*/
void Hex_Encoder::encode_and_send(const byte block[], size_t length)
   {
   hex_encode(reinterpret_cast<char*>(&out[0]),
              block, length,
              casing == Uppercase);

   if(line_length == 0)
      send(out, 2*length);
   else
      {
      size_t remaining = 2*length, offset = 0;
      while(remaining)
         {
         size_t sent = std::min(line_length - counter, remaining);
         send(&out[offset], sent);
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
* Convert some data into hex format
*/
void Hex_Encoder::write(const byte input[], size_t length)
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
void Hex_Encoder::end_msg()
   {
   encode_and_send(&in[0], position);
   if(counter && line_length)
      send('\n');
   counter = position = 0;
   }

/*
* Hex_Decoder Constructor
*/
Hex_Decoder::Hex_Decoder(Decoder_Checking c) : checking(c)
   {
   in.resize(HEX_CODEC_BUFFER_SIZE);
   out.resize(in.size() / 2);
   position = 0;
   }

/*
* Convert some data from hex format
*/
void Hex_Decoder::write(const byte input[], size_t length)
   {
   while(length)
      {
      size_t to_copy = std::min<size_t>(length, in.size() - position);
      copy_mem(&in[position], input, to_copy);
      position += to_copy;

      size_t consumed = 0;
      size_t written = hex_decode(&out[0],
                                  reinterpret_cast<const char*>(&in[0]),
                                  position,
                                  consumed,
                                  checking != FULL_CHECK);

      send(out, written);

      if(consumed != position)
         {
         copy_mem(&in[0], &in[consumed], position - consumed);
         position = position - consumed;
         }
      else
         position = 0;

      length -= to_copy;
      input += to_copy;
      }
   }

/*
* Flush buffers
*/
void Hex_Decoder::end_msg()
   {
   size_t consumed = 0;
   size_t written = hex_decode(&out[0],
                               reinterpret_cast<const char*>(&in[0]),
                               position,
                               consumed,
                               checking != FULL_CHECK);

   send(out, written);

   const bool not_full_bytes = consumed != position;

   position = 0;

   if(not_full_bytes)
      throw std::invalid_argument("Hex_Decoder: Input not full bytes");
   }

}
