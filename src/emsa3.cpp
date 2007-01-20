/*************************************************
* EMSA3 Source File                              *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/emsa.h>
#include <botan/hash_id.h>
#include <botan/lookup.h>

namespace Botan {

/*************************************************
* EMSA3 Update Operation                         *
*************************************************/
void EMSA3::update(const byte input[], u32bit length)
   {
   hash->update(input, length);
   }

/*************************************************
* Return the raw (unencoded) data                *
*************************************************/
SecureVector<byte> EMSA3::raw_data()
   {
   return hash->final();
   }

/*************************************************
* EMSA3 Encode Operation                         *
*************************************************/
SecureVector<byte> EMSA3::encoding_of(const MemoryRegion<byte>& msg,
                                      u32bit output_bits)
   {
   if(msg.size() != hash->OUTPUT_LENGTH)
      throw Encoding_Error("EMSA3::encoding_of: Bad input length");

   u32bit output_length = output_bits / 8;
   if(output_length < hash_id.size() + hash->OUTPUT_LENGTH + 10)
      throw Encoding_Error("EMSA3::pad: Output length is too small");

   SecureVector<byte> T(output_length);
   const u32bit P_LENGTH = output_length - hash->OUTPUT_LENGTH -
                           hash_id.size() - 2;

   T[0] = 0x01;
   set_mem(T+1, P_LENGTH, 0xFF);
   T[P_LENGTH+1] = 0x00;
   T.copy(P_LENGTH+2, hash_id, hash_id.size());
   T.copy(output_length-hash->OUTPUT_LENGTH, msg, msg.size());
   return T;
   }

/*************************************************
* EMSA3 Constructor                              *
*************************************************/
EMSA3::EMSA3(const std::string& hash_name)
   {
   hash_id = pkcs_hash_id(hash_name);
   hash = get_hash(hash_name);
   }

}
