/*************************************************
* Luby-Rackoff Source File                       *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/lubyrack.h>
#include <botan/lookup.h>
#include <botan/xor_buf.h>

namespace Botan {

/*************************************************
* Luby-Rackoff Encryption                        *
*************************************************/
void LubyRackoff::enc(const byte in[], byte out[]) const
   {
   const u32bit OUTPUT_LENGTH = hash->OUTPUT_LENGTH;

   SecureVector<byte> buffer(OUTPUT_LENGTH);
   hash->update(K1);
   hash->update(in, OUTPUT_LENGTH);
   hash->final(buffer);
   xor_buf(out + OUTPUT_LENGTH, in + OUTPUT_LENGTH, buffer, OUTPUT_LENGTH);

   hash->update(K2);
   hash->update(out + OUTPUT_LENGTH, OUTPUT_LENGTH);
   hash->final(buffer);
   xor_buf(out, in, buffer, OUTPUT_LENGTH);

   hash->update(K1);
   hash->update(out, OUTPUT_LENGTH);
   hash->final(buffer);
   xor_buf(out + OUTPUT_LENGTH, buffer, OUTPUT_LENGTH);

   hash->update(K2);
   hash->update(out + OUTPUT_LENGTH, OUTPUT_LENGTH);
   hash->final(buffer);
   xor_buf(out, buffer, OUTPUT_LENGTH);
   }

/*************************************************
* Luby-Rackoff Decryption                        *
*************************************************/
void LubyRackoff::dec(const byte in[], byte out[]) const
   {
   const u32bit OUTPUT_LENGTH = hash->OUTPUT_LENGTH;

   SecureVector<byte> buffer(OUTPUT_LENGTH);
   hash->update(K2);
   hash->update(in + OUTPUT_LENGTH, OUTPUT_LENGTH);
   hash->final(buffer);
   xor_buf(out, in, buffer, OUTPUT_LENGTH);

   hash->update(K1);
   hash->update(out, OUTPUT_LENGTH);
   hash->final(buffer);
   xor_buf(out + OUTPUT_LENGTH, in + OUTPUT_LENGTH, buffer, OUTPUT_LENGTH);

   hash->update(K2);
   hash->update(out + OUTPUT_LENGTH, OUTPUT_LENGTH);
   hash->final(buffer);
   xor_buf(out, buffer, OUTPUT_LENGTH);

   hash->update(K1);
   hash->update(out, OUTPUT_LENGTH);
   hash->final(buffer);
   xor_buf(out + OUTPUT_LENGTH, buffer, OUTPUT_LENGTH);
   }

/*************************************************
* Luby-Rackoff Key Schedule                      *
*************************************************/
void LubyRackoff::key(const byte key[], u32bit length)
   {
   K1.set(key, length / 2);
   K2.set(key + length / 2, length / 2);
   }

/*************************************************
* Clear memory of sensitive data                 *
*************************************************/
void LubyRackoff::clear() throw()
   {
   K1.clear();
   K2.clear();
   hash->clear();
   }

/*************************************************
* Return a clone of this object                  *
*************************************************/
BlockCipher* LubyRackoff::clone() const
   {
   return new LubyRackoff(hash->name());
   }

/*************************************************
* Return the name of this type                   *
*************************************************/
std::string LubyRackoff::name() const
   {
   return "Luby-Rackoff(" + hash->name() + ")";
   }

/*************************************************
* Luby-Rackoff Constructor                       *
*************************************************/
LubyRackoff::LubyRackoff(const std::string& hash_name) :
   BlockCipher(2*output_length_of(hash_name), 2, 32, 2),
   hash(get_hash(hash_name))
   {
   }

}
