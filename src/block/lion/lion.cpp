/*
* Lion
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/lion.h>
#include <botan/xor_buf.h>
#include <botan/parsing.h>

namespace Botan {

/*
* Lion Encryption
*/
void Lion::enc(const byte in[], byte out[]) const
   {
   SecureVector<byte> buffer(LEFT_SIZE);

   xor_buf(buffer, in, key1, LEFT_SIZE);
   cipher->set_key(buffer, LEFT_SIZE);
   cipher->encrypt(in + LEFT_SIZE, out + LEFT_SIZE, RIGHT_SIZE);

   hash->update(out + LEFT_SIZE, RIGHT_SIZE);
   hash->final(buffer);
   xor_buf(out, in, buffer, LEFT_SIZE);

   xor_buf(buffer, out, key2, LEFT_SIZE);
   cipher->set_key(buffer, LEFT_SIZE);
   cipher->encrypt(out + LEFT_SIZE, RIGHT_SIZE);
   }

/*
* Lion Decryption
*/
void Lion::dec(const byte in[], byte out[]) const
   {
   SecureVector<byte> buffer(LEFT_SIZE);

   xor_buf(buffer, in, key2, LEFT_SIZE);
   cipher->set_key(buffer, LEFT_SIZE);
   cipher->encrypt(in + LEFT_SIZE, out + LEFT_SIZE, RIGHT_SIZE);

   hash->update(out + LEFT_SIZE, RIGHT_SIZE);
   hash->final(buffer);
   xor_buf(out, in, buffer, LEFT_SIZE);

   xor_buf(buffer, out, key1, LEFT_SIZE);
   cipher->set_key(buffer, LEFT_SIZE);
   cipher->encrypt(out + LEFT_SIZE, RIGHT_SIZE);
   }

/*
* Lion Key Schedule
*/
void Lion::key_schedule(const byte key[], u32bit length)
   {
   clear();

   key1.copy(key,              length / 2);
   key2.copy(key + length / 2, length / 2);
   }

/*
* Return the name of this type
*/
std::string Lion::name() const
   {
   return "Lion(" + hash->name() + "," +
                    cipher->name() + "," +
                    to_string(BLOCK_SIZE) + ")";
   }

/*
* Return a clone of this object
*/
BlockCipher* Lion::clone() const
   {
   return new Lion(hash->clone(), cipher->clone(), BLOCK_SIZE);
   }

/*
* Clear memory of sensitive data
*/
void Lion::clear() throw()
   {
   hash->clear();
   cipher->clear();
   key1.clear();
   key2.clear();
   }

/*
* Lion Constructor
*/
Lion::Lion(HashFunction* hash_in, StreamCipher* sc_in, u32bit block_len) :
   BlockCipher(std::max<u32bit>(2*hash_in->OUTPUT_LENGTH + 1, block_len),
               2, 2*hash_in->OUTPUT_LENGTH, 2),
   LEFT_SIZE(hash_in->OUTPUT_LENGTH),
   RIGHT_SIZE(BLOCK_SIZE - LEFT_SIZE),
   hash(hash_in),
   cipher(sc_in)
   {
   if(2*LEFT_SIZE + 1 > BLOCK_SIZE)
      throw Invalid_Argument(name() + ": Chosen block size is too small");
   if(!cipher->valid_keylength(LEFT_SIZE))
      throw Exception(name() + ": This stream/hash combination is invalid");

   key1.create(LEFT_SIZE);
   key2.create(LEFT_SIZE);
   }

}
