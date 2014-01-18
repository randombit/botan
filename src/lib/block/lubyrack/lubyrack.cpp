/*
* Luby-Rackoff
* (C) 1999-2008,2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/lubyrack.h>
#include <botan/internal/xor_buf.h>

namespace Botan {

/*
* Luby-Rackoff Encryption
*/
void LubyRackoff::encrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   const size_t len = m_hash->output_length();

   secure_vector<byte> buffer_vec(len);
   byte* buffer = &buffer_vec[0];

   for(size_t i = 0; i != blocks; ++i)
      {
      m_hash->update(m_K1);
      m_hash->update(in, len);
      m_hash->final(buffer);
      xor_buf(out + len, in + len, buffer, len);

      m_hash->update(m_K2);
      m_hash->update(out + len, len);
      m_hash->final(buffer);
      xor_buf(out, in, buffer, len);

      m_hash->update(m_K1);
      m_hash->update(out, len);
      m_hash->final(buffer);
      xor_buf(out + len, buffer, len);

      m_hash->update(m_K2);
      m_hash->update(out + len, len);
      m_hash->final(buffer);
      xor_buf(out, buffer, len);

      in += 2 * len;
      out += 2 * len;
      }
   }

/*
* Luby-Rackoff Decryption
*/
void LubyRackoff::decrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   const size_t len = m_hash->output_length();

   secure_vector<byte> buffer_vec(len);
   byte* buffer = &buffer_vec[0];

   for(size_t i = 0; i != blocks; ++i)
      {
      m_hash->update(m_K2);
      m_hash->update(in + len, len);
      m_hash->final(buffer);
      xor_buf(out, in, buffer, len);

      m_hash->update(m_K1);
      m_hash->update(out, len);
      m_hash->final(buffer);
      xor_buf(out + len, in + len, buffer, len);

      m_hash->update(m_K2);
      m_hash->update(out + len, len);
      m_hash->final(buffer);
      xor_buf(out, buffer, len);

      m_hash->update(m_K1);
      m_hash->update(out, len);
      m_hash->final(buffer);
      xor_buf(out + len, buffer, len);

      in += 2 * len;
      out += 2 * len;
      }
   }

/*
* Luby-Rackoff Key Schedule
*/
void LubyRackoff::key_schedule(const byte key[], size_t length)
   {
   m_K1.assign(key, key + (length / 2));
   m_K2.assign(key + (length / 2), key + length);
   }

/*
* Clear memory of sensitive data
*/
void LubyRackoff::clear()
   {
   zap(m_K1);
   zap(m_K2);
   m_hash->clear();
   }

/*
* Return a clone of this object
*/
BlockCipher* LubyRackoff::clone() const
   {
   return new LubyRackoff(m_hash->clone());
   }

/*
* Return the name of this type
*/
std::string LubyRackoff::name() const
   {
   return "Luby-Rackoff(" + m_hash->name() + ")";
   }

}
