/*
* RC4
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rc4.h>
#include <botan/exceptn.h>

namespace Botan {

RC4* RC4::make(const Spec& spec)
   {
   if(spec.algo_name() == "RC4")
      return new RC4(spec.arg_as_integer(0, 0));
   if(spec.algo_name() == "RC4_drop")
      return new RC4(768);
   return nullptr;
   }

/*
* Combine cipher stream with message
*/
void RC4::cipher(const byte in[], byte out[], size_t length)
   {
   while(length >= m_buffer.size() - m_position)
      {
      xor_buf(out, in, &m_buffer[m_position], m_buffer.size() - m_position);
      length -= (m_buffer.size() - m_position);
      in += (m_buffer.size() - m_position);
      out += (m_buffer.size() - m_position);
      generate();
      }
   xor_buf(out, in, &m_buffer[m_position], length);
   m_position += length;
   }

void RC4::set_iv(const byte*, size_t)
   {
   throw Exception("RC4 does not support an IV");
   }

/*
* Generate cipher stream
*/
void RC4::generate()
   {
   byte SX, SY;
   for(size_t i = 0; i != m_buffer.size(); i += 4)
      {
      SX = m_state[m_X+1]; m_Y = (m_Y + SX) % 256; SY = m_state[m_Y];
      m_state[m_X+1] = SY; m_state[m_Y] = SX;
      m_buffer[i] = m_state[(SX + SY) % 256];

      SX = m_state[m_X+2]; m_Y = (m_Y + SX) % 256; SY = m_state[m_Y];
      m_state[m_X+2] = SY; m_state[m_Y] = SX;
      m_buffer[i+1] = m_state[(SX + SY) % 256];

      SX = m_state[m_X+3]; m_Y = (m_Y + SX) % 256; SY = m_state[m_Y];
      m_state[m_X+3] = SY; m_state[m_Y] = SX;
      m_buffer[i+2] = m_state[(SX + SY) % 256];

      m_X = (m_X + 4) % 256;
      SX = m_state[m_X]; m_Y = (m_Y + SX) % 256; SY = m_state[m_Y];
      m_state[m_X] = SY; m_state[m_Y] = SX;
      m_buffer[i+3] = m_state[(SX + SY) % 256];
      }
   m_position = 0;
   }

/*
* RC4 Key Schedule
*/
void RC4::key_schedule(const byte key[], size_t length)
   {
   m_state.resize(256);
   m_buffer.resize(256);

   m_position = m_X = m_Y = 0;

   for(size_t i = 0; i != 256; ++i)
      m_state[i] = static_cast<byte>(i);

   for(size_t i = 0, state_index = 0; i != 256; ++i)
      {
      state_index = (state_index + key[i % length] + m_state[i]) % 256;
      std::swap(m_state[i], m_state[state_index]);
      }

   for(size_t i = 0; i <= m_SKIP; i += m_buffer.size())
      generate();

   m_position += (m_SKIP % m_buffer.size());
   }

/*
* Return the name of this type
*/
std::string RC4::name() const
   {
   if(m_SKIP == 0)   return "RC4";
   if(m_SKIP == 256) return "MARK-4";
   else            return "RC4_skip(" + std::to_string(m_SKIP) + ")";
   }

/*
* Clear memory of sensitive data
*/
void RC4::clear()
   {
   zap(m_state);
   zap(m_buffer);
   m_position = m_X = m_Y = 0;
   }

/*
* RC4 Constructor
*/
RC4::RC4(size_t s) : m_SKIP(s) {}

void RC4::seek(u64bit)
   {
   throw Exception("RC4 does not support seeking");
   }
}
