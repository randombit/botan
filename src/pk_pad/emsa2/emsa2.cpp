/*
* EMSA2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/emsa2.h>
#include <botan/hash_id.h>

namespace Botan {

namespace {

/*
* EMSA2 Encode Operation
*/
SecureVector<byte> emsa2_encoding(const MemoryRegion<byte>& msg,
                                  u32bit output_bits,
                                  const MemoryRegion<byte>& empty_hash,
                                  byte hash_id)
   {
   const u32bit HASH_SIZE = empty_hash.size();

   u32bit output_length = (output_bits + 1) / 8;

   if(msg.size() != HASH_SIZE)
      throw Encoding_Error("EMSA2::encoding_of: Bad input length");
   if(output_length < HASH_SIZE + 4)
      throw Encoding_Error("EMSA2::encoding_of: Output length is too small");

   bool empty = true;
   for(u32bit j = 0; j != HASH_SIZE; ++j)
      if(empty_hash[j] != msg[j])
         empty = false;

   SecureVector<byte> output(output_length);

   output[0] = (empty ? 0x4B : 0x6B);
   output[output_length - 3 - HASH_SIZE] = 0xBA;
   set_mem(output + 1, output_length - 4 - HASH_SIZE, 0xBB);
   output.copy(output_length - (HASH_SIZE + 2), msg, msg.size());
   output[output_length-2] = hash_id;
   output[output_length-1] = 0xCC;

   return output;
   }

}

/*
* EMSA2 Update Operation
*/
void EMSA2::update(const byte input[], u32bit length)
   {
   hash->update(input, length);
   }

/*
* Return the raw (unencoded) data
*/
SecureVector<byte> EMSA2::raw_data()
   {
   return hash->final();
   }

/*
* EMSA2 Encode Operation
*/
SecureVector<byte> EMSA2::encoding_of(const MemoryRegion<byte>& msg,
                                      u32bit output_bits,
                                      RandomNumberGenerator&)
   {
   return emsa2_encoding(msg, output_bits, empty_hash, hash_id);
   }

/*
* EMSA2 Verify Operation
*/
bool EMSA2::verify(const MemoryRegion<byte>& coded,
                   const MemoryRegion<byte>& raw,
                   u32bit key_bits) throw()
   {
   try
      {
      return (coded == emsa2_encoding(raw, key_bits,
                                      empty_hash, hash_id));
      }
   catch(...)
      {
      return false;
      }
   }

/*
* EMSA2 Constructor
*/
EMSA2::EMSA2(HashFunction* hash_in) : hash(hash_in)
   {
   empty_hash = hash->final();

   hash_id = ieee1363_hash_id(hash->name());

   if(hash_id == 0)
      {
      delete hash;
      throw Encoding_Error("EMSA2 cannot be used with " + hash->name());
      }
   }

}
