/*
* SHAKE-128
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/shake_cipher.h>
#include <botan/exceptn.h>
#include <botan/sha3.h>
#include <botan/loadstor.h>

namespace Botan {

SHAKE_128_Cipher::SHAKE_128_Cipher() :
   m_buf_pos(0)
   {}

void SHAKE_128_Cipher::cipher(const uint8_t in[], uint8_t out[], size_t length)
   {
   const size_t SHAKE_128_BYTERATE = (1600-256)/8;

   verify_key_set(m_state.empty() == false);

   while(length >= SHAKE_128_BYTERATE - m_buf_pos)
      {
      xor_buf(out, in, &m_buffer[m_buf_pos], SHAKE_128_BYTERATE - m_buf_pos);
      length -= (SHAKE_128_BYTERATE - m_buf_pos);
      in += (SHAKE_128_BYTERATE - m_buf_pos);
      out += (SHAKE_128_BYTERATE - m_buf_pos);

      SHA_3::permute(m_state.data());
      copy_out_le(m_buffer.data(), SHAKE_128_BYTERATE, m_state.data());

      m_buf_pos = 0;
      }
   xor_buf(out, in, &m_buffer[m_buf_pos], length);
   m_buf_pos += length;
   }

void SHAKE_128_Cipher::key_schedule(const uint8_t key[], size_t length)
   {
   const size_t SHAKE_128_BITRATE = (1600-256);
   m_state.resize(25);
   m_buffer.resize(SHAKE_128_BITRATE/8);
   zeroise(m_state);

   const size_t S_pos = SHA_3::absorb(SHAKE_128_BITRATE, m_state, 0, key, length);
   SHA_3::finish(SHAKE_128_BITRATE, m_state, S_pos, 0x1F, 0x80);
   copy_out_le(m_buffer.data(), m_buffer.size(), m_state.data());
   }

void SHAKE_128_Cipher::clear()
   {
   zap(m_state);
   zap(m_buffer);
   m_buf_pos = 0;
   }

void SHAKE_128_Cipher::set_iv(const uint8_t[], size_t length)
   {
   /*
   * This could be supported in some way (say, by treating iv as
   * a prefix or suffix of the key).
   */
   if(length != 0)
      throw Invalid_IV_Length(name(), length);
   }

void SHAKE_128_Cipher::seek(uint64_t)
   {
   throw Not_Implemented("SHAKE_128_Cipher::seek");
   }

Key_Length_Specification SHAKE_128_Cipher::key_spec() const
   {
   return Key_Length_Specification(1, 160);
   }

std::string SHAKE_128_Cipher::name() const
   {
   return "SHAKE-128";
   }

StreamCipher* SHAKE_128_Cipher::clone() const
   {
   return new SHAKE_128_Cipher;
   }

}
