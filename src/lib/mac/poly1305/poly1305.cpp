/*
* Poly1305
* (C) 2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/poly1305.h>
#include <botan/internal/poly1305_donna.h>

namespace Botan {

void Poly1305::clear()
   {
   zap(m_poly);
   zap(m_buf);
   m_buf_pos = 0;
   }

void Poly1305::key_schedule(const byte key[], size_t key_len)
   {
   m_buf_pos = 0;
   m_buf.resize(16);
   m_poly.resize(8);

   poly1305_init(m_poly, key);
   }

void Poly1305::add_data(const byte input[], size_t length)
   {
   BOTAN_ASSERT_EQUAL(m_poly.size(), 8, "Initialized");

   if(m_buf_pos)
      {
      buffer_insert(m_buf, m_buf_pos, input, length);

      if(m_buf_pos + length >= m_buf.size())
         {
         poly1305_blocks(m_poly, &m_buf[0], 1);
         input += (m_buf.size() - m_buf_pos);
         length -= (m_buf.size() - m_buf_pos);
         m_buf_pos = 0;
         }
      }

   const size_t full_blocks = length / m_buf.size();
   const size_t remaining   = length % m_buf.size();

   if(full_blocks)
      poly1305_blocks(m_poly, input, full_blocks);

   buffer_insert(m_buf, m_buf_pos, input + full_blocks * m_buf.size(), remaining);
   m_buf_pos += remaining;
   }

void Poly1305::final_result(byte out[])
   {
   BOTAN_ASSERT_EQUAL(m_poly.size(), 8, "Initialized");

   if(m_buf_pos != 0)
      {
      m_buf[m_buf_pos] = 1;
      clear_mem(&m_buf[m_buf_pos+1], m_buf.size() - m_buf_pos - 1);
      poly1305_blocks(m_poly, &m_buf[0], 1, true);
      }

   poly1305_finish(m_poly, out);

   m_poly.clear();
   m_buf_pos = 0;
   }

}
