/*
* Base64 Encoder/Decoder
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/filters.h>

#include <botan/base64.h>
#include <botan/exceptn.h>
#include <algorithm>

namespace Botan {

/*
* Base64_Encoder Constructor
*/
Base64_Encoder::Base64_Encoder(bool line_breaks, size_t line_length, bool trailing_newline) :
      m_line_length(line_breaks ? line_length : 0),
      m_trailing_newline(trailing_newline && line_breaks),
      m_in(48),
      m_out(64),
      m_position(0),
      m_out_position(0) {}

/*
* Encode and send a block
*/
void Base64_Encoder::encode_and_send(const uint8_t input[], size_t length, bool final_inputs) {
   while(length) {
      const size_t proc = std::min(length, m_in.size());

      size_t consumed = 0;
      size_t produced = base64_encode(cast_uint8_ptr_to_char(m_out.data()), input, proc, consumed, final_inputs);

      do_output(m_out.data(), produced);

      // FIXME: s/proc/consumed/?
      input += proc;
      length -= proc;
   }
}

/*
* Handle the output
*/
void Base64_Encoder::do_output(const uint8_t input[], size_t length) {
   if(m_line_length == 0) {
      send(input, length);
   } else {
      size_t remaining = length, offset = 0;
      while(remaining) {
         size_t sent = std::min(m_line_length - m_out_position, remaining);
         send(input + offset, sent);
         m_out_position += sent;
         remaining -= sent;
         offset += sent;
         if(m_out_position == m_line_length) {
            send('\n');
            m_out_position = 0;
         }
      }
   }
}

/*
* Convert some data into Base64
*/
void Base64_Encoder::write(const uint8_t input[], size_t length) {
   const size_t initial_fill = std::min(m_in.size() - m_position, length);
   copy_mem(&m_in[m_position], input, initial_fill);

   if(m_position + length >= m_in.size()) {
      encode_and_send(m_in.data(), m_in.size());
      input += (m_in.size() - m_position);
      length -= (m_in.size() - m_position);
      while(length >= m_in.size()) {
         encode_and_send(input, m_in.size());
         input += m_in.size();
         length -= m_in.size();
      }
      copy_mem(m_in.data(), input, length);
      m_position = 0;
   }
   m_position += length;
}

/*
* Flush buffers
*/
void Base64_Encoder::end_msg() {
   encode_and_send(m_in.data(), m_position, true);

   if(m_trailing_newline || (m_out_position && m_line_length)) {
      send('\n');
   }

   m_out_position = m_position = 0;
}

/*
* Base64_Decoder Constructor
*/
Base64_Decoder::Base64_Decoder(Decoder_Checking c) : m_checking(c), m_in(64), m_out(48), m_position(0) {}

/*
* Convert some data from Base64
*/
void Base64_Decoder::write(const uint8_t input[], size_t length) {
   while(length) {
      size_t to_copy = std::min<size_t>(length, m_in.size() - m_position);
      if(to_copy == 0) {
         m_in.resize(m_in.size() * 2);
         m_out.resize(m_out.size() * 2);
      }
      copy_mem(&m_in[m_position], input, to_copy);
      m_position += to_copy;

      size_t consumed = 0;
      size_t written = base64_decode(
         m_out.data(), cast_uint8_ptr_to_char(m_in.data()), m_position, consumed, false, m_checking != FULL_CHECK);

      send(m_out, written);

      if(consumed != m_position) {
         copy_mem(m_in.data(), m_in.data() + consumed, m_position - consumed);
         m_position = m_position - consumed;
      } else {
         m_position = 0;
      }

      length -= to_copy;
      input += to_copy;
   }
}

/*
* Flush buffers
*/
void Base64_Decoder::end_msg() {
   size_t consumed = 0;
   size_t written = base64_decode(
      m_out.data(), cast_uint8_ptr_to_char(m_in.data()), m_position, consumed, true, m_checking != FULL_CHECK);

   send(m_out, written);

   const bool not_full_bytes = consumed != m_position;

   m_position = 0;

   if(not_full_bytes) {
      throw Invalid_Argument("Base64_Decoder: Input not full bytes");
   }
}

}  // namespace Botan
