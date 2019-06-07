/*
* Hex Encoder/Decoder
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/filters.h>
#include <botan/hex.h>
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
   m_casing(c), m_line_length(breaks ? length : 0)
   {
   m_in.resize(HEX_CODEC_BUFFER_SIZE);
   m_out.resize(2*m_in.size());
   m_counter = m_position = 0;
   }

/*
* Hex_Encoder Constructor
*/
Hex_Encoder::Hex_Encoder(Case c) : m_casing(c), m_line_length(0)
   {
   m_in.resize(HEX_CODEC_BUFFER_SIZE);
   m_out.resize(2*m_in.size());
   m_counter = m_position = 0;
   }

/*
* Encode and send a block
*/
void Hex_Encoder::encode_and_send(const uint8_t block[], size_t length)
   {
   hex_encode(cast_uint8_ptr_to_char(m_out.data()),
              block, length,
              m_casing == Uppercase);

   if(m_line_length == 0)
      send(m_out, 2*length);
   else
      {
      size_t remaining = 2*length, offset = 0;
      while(remaining)
         {
         size_t sent = std::min(m_line_length - m_counter, remaining);
         send(&m_out[offset], sent);
         m_counter += sent;
         remaining -= sent;
         offset += sent;
         if(m_counter == m_line_length)
            {
            send('\n');
            m_counter = 0;
            }
         }
      }
   }

/*
* Convert some data into hex format
*/
void Hex_Encoder::write(const uint8_t input[], size_t length)
   {
   buffer_insert(m_in, m_position, input, length);
   if(m_position + length >= m_in.size())
      {
      encode_and_send(m_in.data(), m_in.size());
      input += (m_in.size() - m_position);
      length -= (m_in.size() - m_position);
      while(length >= m_in.size())
         {
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
void Hex_Encoder::end_msg()
   {
   encode_and_send(m_in.data(), m_position);
   if(m_counter && m_line_length)
      send('\n');
   m_counter = m_position = 0;
   }

/*
* Hex_Decoder Constructor
*/
Hex_Decoder::Hex_Decoder(Decoder_Checking c) : m_checking(c)
   {
   m_in.resize(HEX_CODEC_BUFFER_SIZE);
   m_out.resize(m_in.size() / 2);
   m_position = 0;
   }

/*
* Convert some data from hex format
*/
void Hex_Decoder::write(const uint8_t input[], size_t length)
   {
   while(length)
      {
      size_t to_copy = std::min<size_t>(length, m_in.size() - m_position);
      copy_mem(&m_in[m_position], input, to_copy);
      m_position += to_copy;

      size_t consumed = 0;
      size_t written = hex_decode(m_out.data(),
                                  cast_uint8_ptr_to_char(m_in.data()),
                                  m_position,
                                  consumed,
                                  m_checking != FULL_CHECK);

      send(m_out, written);

      if(consumed != m_position)
         {
         copy_mem(m_in.data(), m_in.data() + consumed, m_position - consumed);
         m_position = m_position - consumed;
         }
      else
         m_position = 0;

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
   size_t written = hex_decode(m_out.data(),
                               cast_uint8_ptr_to_char(m_in.data()),
                               m_position,
                               consumed,
                               m_checking != FULL_CHECK);

   send(m_out, written);

   const bool not_full_bytes = consumed != m_position;

   m_position = 0;

   if(not_full_bytes)
      throw Invalid_Argument("Hex_Decoder: Input not full bytes");
   }

}
