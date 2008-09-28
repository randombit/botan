/*************************************************
* EMSA3 Source File                              *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/emsa.h>
#include <botan/hash_id.h>
#include <botan/lookup.h>

namespace Botan {

namespace {

/*************************************************
* EMSA3 Encode Operation                         *
*************************************************/
SecureVector<byte> emsa3_encoding(const MemoryRegion<byte>& msg,
                                  u32bit output_bits,
                                  const MemoryRegion<byte>& hash_id,
                                  u32bit hash_size)
   {
   if(msg.size() != hash_size)
      throw Encoding_Error("EMSA3::encoding_of: Bad input length");

   u32bit output_length = output_bits / 8;
   if(output_length < hash_id.size() + hash_size + 10)
      throw Encoding_Error("EMSA3::pad: Output length is too small");

   SecureVector<byte> T(output_length);
   const u32bit P_LENGTH = output_length - hash_size - hash_id.size() - 2;

   T[0] = 0x01;
   set_mem(T+1, P_LENGTH, 0xFF);
   T[P_LENGTH+1] = 0x00;
   T.copy(P_LENGTH+2, hash_id, hash_id.size());
   T.copy(output_length-hash_size, msg, msg.size());
   return T;
   }

}

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
                                      u32bit output_bits,
                                      RandomNumberGenerator&)
   {
   return emsa3_encoding(msg, output_bits, hash_id,
                         hash->OUTPUT_LENGTH);
   }

/*************************************************
* Default signature decoding                     *
*************************************************/
bool EMSA3::verify(const MemoryRegion<byte>& coded,
                   const MemoryRegion<byte>& raw,
                   u32bit key_bits) throw()
   {
   try
      {
      return (coded == emsa3_encoding(raw, key_bits,
                                      hash_id,
                                      hash->OUTPUT_LENGTH));
      }
   catch(...)
      {
      return false;
      }
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
