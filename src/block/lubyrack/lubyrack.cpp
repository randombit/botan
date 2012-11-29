/*
* Luby-Rackoff
* (C) 1999-2008 Jack Lloyd
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
   const size_t len = hash->output_length();

   secure_vector<byte> buffer_vec(len);
   byte* buffer = &buffer_vec[0];

   for(size_t i = 0; i != blocks; ++i)
      {
      hash->update(K1);
      hash->update(in, len);
      hash->final(buffer);
      xor_buf(out + len, in + len, buffer, len);

      hash->update(K2);
      hash->update(out + len, len);
      hash->final(buffer);
      xor_buf(out, in, buffer, len);

      hash->update(K1);
      hash->update(out, len);
      hash->final(buffer);
      xor_buf(out + len, buffer, len);

      hash->update(K2);
      hash->update(out + len, len);
      hash->final(buffer);
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
   const size_t len = hash->output_length();

   secure_vector<byte> buffer_vec(len);
   byte* buffer = &buffer_vec[0];

   for(size_t i = 0; i != blocks; ++i)
      {
      hash->update(K2);
      hash->update(in + len, len);
      hash->final(buffer);
      xor_buf(out, in, buffer, len);

      hash->update(K1);
      hash->update(out, len);
      hash->final(buffer);
      xor_buf(out + len, in + len, buffer, len);

      hash->update(K2);
      hash->update(out + len, len);
      hash->final(buffer);
      xor_buf(out, buffer, len);

      hash->update(K1);
      hash->update(out, len);
      hash->final(buffer);
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
   K1.assign(key, key + (length / 2));
   K2.assign(key + (length / 2), key + length);
   }

/*
* Clear memory of sensitive data
*/
void LubyRackoff::clear()
   {
   zap(K1);
   zap(K2);
   hash->clear();
   }

/*
* Return a clone of this object
*/
BlockCipher* LubyRackoff::clone() const
   {
   return new LubyRackoff(hash->clone());
   }

/*
* Return the name of this type
*/
std::string LubyRackoff::name() const
   {
   return "Luby-Rackoff(" + hash->name() + ")";
   }

/*
* Luby-Rackoff Constructor
*/
LubyRackoff::LubyRackoff(HashFunction* h) : hash(h)
   {
   }

}
