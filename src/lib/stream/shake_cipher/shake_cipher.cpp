/*
 * SHAKE-128 and SHAKE-256
 * (C) 2016 Jack Lloyd
 *     2022 René Meusel, Michael Boric - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/shake_cipher.h>
#include <botan/exceptn.h>
#include <botan/internal/sha3.h>
#include <botan/internal/loadstor.h>

namespace Botan {

SHAKE_Cipher::SHAKE_Cipher(size_t shake_rate) :
   m_shake_rate(shake_rate),
   m_buf_pos(0)
   {
   BOTAN_ASSERT_NOMSG(shake_rate >= 72 && shake_rate <= 168);
   }

void SHAKE_Cipher::clear()
   {
   zap(m_state);
   zap(m_buffer);
   m_buf_pos = 0;
   }

void SHAKE_Cipher::set_iv(const uint8_t /*iv*/[], size_t length)
   {
   /*
   * This could be supported in some way (say, by treating iv as
   * a prefix or suffix of the key).
   */
   if(length != 0)
      { throw Invalid_IV_Length(name(), length); }
   }

void SHAKE_Cipher::seek(uint64_t /*offset*/)
   {
   throw Not_Implemented("SHAKE_Cipher::seek");
   }

void SHAKE_Cipher::cipher(const uint8_t in[], uint8_t out[], size_t length)
   {
   assert_key_material_set();

   while(length >= m_shake_rate - m_buf_pos)
      {
      xor_buf(out, in, &m_buffer[m_buf_pos], m_shake_rate - m_buf_pos);
      length -= (m_shake_rate - m_buf_pos);
      in += (m_shake_rate - m_buf_pos);
      out += (m_shake_rate - m_buf_pos);

      SHA_3::permute(m_state.data());
      copy_out_le(m_buffer.data(), m_shake_rate, m_state.data());

      m_buf_pos = 0;
      }
   xor_buf(out, in, &m_buffer[m_buf_pos], length);
   m_buf_pos += length;
   }

void SHAKE_Cipher::write_keystream(uint8_t out[], size_t length)
   {
   assert_key_material_set();

   if(m_buf_pos > 0)
      {
      const size_t take = std::min(length, m_shake_rate - m_buf_pos);
      copy_mem(out, &m_buffer[m_buf_pos], take);
      out += take;
      length -= take;
      m_buf_pos += take;

      if(m_buf_pos == m_shake_rate)
         {
         SHA_3::permute(m_state.data());
         m_buf_pos = 0;
         }
      }

   if(length == 0)
      return;

   BOTAN_ASSERT_NOMSG(m_buf_pos == 0);

   while(length >= m_shake_rate)
      {
      copy_out_le(out, m_shake_rate, m_state.data());
      SHA_3::permute(m_state.data());
      length -= m_shake_rate;
      out += m_shake_rate;
      }

   copy_out_le(m_buffer.data(), m_shake_rate, m_state.data());

   copy_mem(out, &m_buffer[0], length);
   m_buf_pos += length;
   }

bool SHAKE_Cipher::has_keying_material() const
   {
   return !m_state.empty();
   }

void SHAKE_Cipher::key_schedule(const uint8_t key[], size_t length)
   {
   const size_t SHAKE_BITRATE = m_shake_rate*8;
   m_state.resize(25);
   m_buffer.resize(m_shake_rate);
   zeroise(m_state);

   const size_t S_pos = SHA_3::absorb(SHAKE_BITRATE, m_state, 0, key, length);
   SHA_3::finish(SHAKE_BITRATE, m_state, S_pos, 0x1F, 0x80);
   copy_out_le(m_buffer.data(), m_buffer.size(), m_state.data());
   m_buf_pos = 0;
   }

Key_Length_Specification SHAKE_Cipher::key_spec() const
   {
   return Key_Length_Specification(1, 160);
   }

SHAKE_128_Cipher::SHAKE_128_Cipher() : SHAKE_Cipher((1600-256)/8) {}
SHAKE_256_Cipher::SHAKE_256_Cipher() : SHAKE_Cipher((1600-512)/8) {}

}
