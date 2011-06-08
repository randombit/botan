/*
* EMSA3 and EMSA3_Raw
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/emsa3.h>
#include <botan/hash_id.h>

namespace Botan {

namespace {

/**
* EMSA3 Encode Operation
*/
SecureVector<byte> emsa3_encoding(const MemoryRegion<byte>& msg,
                                  u32bit output_bits,
                                  const byte hash_id[],
                                  u32bit hash_id_length)
   {
   u32bit output_length = output_bits / 8;
   if(output_length < hash_id_length + msg.size() + 10)
      throw Encoding_Error("emsa3_encoding: Output length is too small");

   SecureVector<byte> T(output_length);
   const u32bit P_LENGTH = output_length - msg.size() - hash_id_length - 2;

   T[0] = 0x01;
   set_mem(T+1, P_LENGTH, 0xFF);
   T[P_LENGTH+1] = 0x00;
   T.copy(P_LENGTH+2, hash_id, hash_id_length);
   T.copy(output_length-msg.size(), msg, msg.size());
   return T;
   }

}

/**
* EMSA3 Update Operation
*/
void EMSA3::update(const byte input[], u32bit length)
   {
   hash->update(input, length);
   }

/**
* Return the raw (unencoded) data
*/
SecureVector<byte> EMSA3::raw_data()
   {
   return hash->final();
   }

/**
* EMSA3 Encode Operation
*/
SecureVector<byte> EMSA3::encoding_of(const MemoryRegion<byte>& msg,
                                      u32bit output_bits,
                                      RandomNumberGenerator&)
   {
   if(msg.size() != hash->OUTPUT_LENGTH)
      throw Encoding_Error("EMSA3::encoding_of: Bad input length");

   return emsa3_encoding(msg, output_bits,
                         hash_id, hash_id.size());
   }

/**
* Default signature decoding
*/
bool EMSA3::verify(const MemoryRegion<byte>& coded,
                   const MemoryRegion<byte>& raw,
                   u32bit key_bits) throw()
   {
   if(raw.size() != hash->OUTPUT_LENGTH)
      return false;

   try
      {
      return (coded == emsa3_encoding(raw, key_bits,
                                      hash_id, hash_id.size()));
      }
   catch(...)
      {
      return false;
      }
   }

/**
* EMSA3 Constructor
*/
EMSA3::EMSA3(HashFunction* hash_in) : hash(hash_in)
   {
   hash_id = pkcs_hash_id(hash->name());
   }

/**
* EMSA3 Destructor
*/
EMSA3::~EMSA3()
   {
   delete hash;
   }

/**
* EMSA3_Raw Update Operation
*/
void EMSA3_Raw::update(const byte input[], u32bit length)
   {
   message.append(input, length);
   }

/**
* Return the raw (unencoded) data
*/
SecureVector<byte> EMSA3_Raw::raw_data()
   {
   SecureVector<byte> ret;
   std::swap(message, ret);
   return ret;
   }

/**
* EMSA3_Raw Encode Operation
*/
SecureVector<byte> EMSA3_Raw::encoding_of(const MemoryRegion<byte>& msg,
                                          u32bit output_bits,
                                          RandomNumberGenerator&)
   {
   return emsa3_encoding(msg, output_bits, 0, 0);
   }

/**
* Default signature decoding
*/
bool EMSA3_Raw::verify(const MemoryRegion<byte>& coded,
                       const MemoryRegion<byte>& raw,
                       u32bit key_bits) throw()
   {
   try
      {
      return (coded == emsa3_encoding(raw, key_bits, 0, 0));
      }
   catch(...)
      {
      return false;
      }
   }

}
