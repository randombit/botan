/*************************************************
* EMSA2 Source File                              *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/emsa.h>
#include <botan/hash_id.h>
#include <botan/lookup.h>

namespace Botan {

/*************************************************
* EMSA2 Update Operation                         *
*************************************************/
void EMSA2::update(const byte input[], u32bit length)
   {
   hash->update(input, length);
   }

/*************************************************
* Return the raw (unencoded) data                *
*************************************************/
SecureVector<byte> EMSA2::raw_data()
   {
   return hash->final();
   }

/*************************************************
* EMSA2 Encode Operation                         *
*************************************************/
SecureVector<byte> EMSA2::encoding_of(const MemoryRegion<byte>& msg,
                                      u32bit output_bits)
   {
   u32bit output_length = (output_bits + 1) / 8;

   if(msg.size() != hash->OUTPUT_LENGTH)
      throw Encoding_Error("EMSA2::encoding_of: Bad input length");
   if(output_length < hash->OUTPUT_LENGTH + 4)
      throw Encoding_Error("EMSA2::encoding_of: Output length is too small");

   bool empty = true;
   for(u32bit j = 0; j != hash->OUTPUT_LENGTH; ++j)
      if(empty_hash[j] != msg[j])
         empty = false;

   SecureVector<byte> output(output_length);

   output[0] = (empty ? 0x4B : 0x6B);
   output[output_length - 3 - hash->OUTPUT_LENGTH] = 0xBA;
   set_mem(output + 1, output_length - 4 - hash->OUTPUT_LENGTH, 0xBB);
   output.copy(output_length-2-hash->OUTPUT_LENGTH, msg, msg.size());
   output[output_length-2] = hash_id;
   output[output_length-1] = 0xCC;

   return output;
   }

/*************************************************
* EMSA2 Constructor                              *
*************************************************/
EMSA2::EMSA2(const std::string& hash_name)
   {
   hash_id = ieee1363_hash_id(hash_name);
   if(hash_id == 0)
      throw Encoding_Error("EMSA2 cannot be used with " + hash->name());
   hash = get_hash(hash_name);
   empty_hash = hash->final();
   }

}
