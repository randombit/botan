/*
* Base64 Encoder/Decoder
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/b64_filt.h>
#include <botan/base64.h>
#include <botan/charset.h>
#include <botan/exceptn.h>
#include <algorithm>

namespace Botan {

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
void Base64_Encoder::encode_and_send(const byte input[], size_t length,
                                     bool final_inputs)
   {
   while(length)
      {
      const size_t proc = std::min(length, in.size());

      size_t consumed = 0;
      size_t produced = base64_encode(reinterpret_cast<char*>(out.data()), input,
                                      proc, consumed, final_inputs);

      do_output(out.data(), produced);

      // FIXME: s/proc/consumed/?
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
   buffer_insert(in, position, input, length);
   if(position + length >= in.size())
      {
      encode_and_send(in.data(), in.size());
      input += (in.size() - position);
      length -= (in.size() - position);
      while(length >= in.size())
         {
         encode_and_send(input, in.size());
         input += in.size();
         length -= in.size();
         }
      copy_mem(in.data(), input, length);
      position = 0;
      }
   position += length;
   }

/*
* Flush buffers
*/
void Base64_Encoder::end_msg()
   {
   encode_and_send(in.data(), position, true);

   if(trailing_newline || (out_position && line_length))
      send('\n');

   out_position = position = 0;
   }

/*
* Base64_Decoder Constructor
*/
Base64_Decoder::Base64_Decoder(Decoder_Checking c) :
   checking(c), in(64), out(48), position(0)
   {
   }

/*
* Convert some data from Base64
*/
void Base64_Decoder::write(const byte input[], size_t length)
   {
   while(length)
      {
      size_t to_copy = std::min<size_t>(length, in.size() - position);
      copy_mem(&in[position], input, to_copy);
      position += to_copy;

      size_t consumed = 0;
      size_t written = base64_decode(out.data(),
                                     reinterpret_cast<const char*>(in.data()),
                                     position,
                                     consumed,
                                     false,
                                     checking != FULL_CHECK);

      send(out, written);

      if(consumed != position)
         {
         copy_mem(in.data(), &in[consumed], position - consumed);
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
void Base64_Decoder::end_msg()
   {
   size_t consumed = 0;
   size_t written = base64_decode(out.data(),
                                  reinterpret_cast<const char*>(in.data()),
                                  position,
                                  consumed,
                                  true,
                                  checking != FULL_CHECK);

   send(out, written);

   const bool not_full_bytes = consumed != position;

   position = 0;

   if(not_full_bytes)
      throw std::invalid_argument("Base64_Decoder: Input not full bytes");
   }

}
