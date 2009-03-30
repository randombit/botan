/*
* EMSA-Raw
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/emsa_raw.h>

namespace Botan {

/*
* EMSA-Raw Encode Operation
*/
void EMSA_Raw::update(const byte input[], u32bit length)
   {
   message.append(input, length);
   }

/*
* Return the raw (unencoded) data
*/
SecureVector<byte> EMSA_Raw::raw_data()
   {
   SecureVector<byte> buf = message;
   message.destroy();
   return buf;
   }

/*
* EMSA-Raw Encode Operation
*/
SecureVector<byte> EMSA_Raw::encoding_of(const MemoryRegion<byte>& msg,
                                         u32bit,
                                         RandomNumberGenerator&)
   {
   return msg;
   }

/*
* EMSA-Raw Verify Operation
*/
bool EMSA_Raw::verify(const MemoryRegion<byte>& coded,
                      const MemoryRegion<byte>& raw,
                      u32bit) throw()
   {
   return (coded == raw);
   }

}
