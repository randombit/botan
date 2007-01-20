/*************************************************
* EMSA-Raw Source File                           *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/emsa.h>

namespace Botan {

/*************************************************
* EMSA-Raw Encode Operation                      *
*************************************************/
void EMSA_Raw::update(const byte input[], u32bit length)
   {
   message.append(input, length);
   }

/*************************************************
* Return the raw (unencoded) data                *
*************************************************/
SecureVector<byte> EMSA_Raw::raw_data()
   {
   SecureVector<byte> buf = message;
   message.destroy();
   return buf;
   }

/*************************************************
* EMSA-Raw Encode Operation                      *
*************************************************/
SecureVector<byte> EMSA_Raw::encoding_of(const MemoryRegion<byte>& msg,
                                         u32bit)
   {
   return msg;
   }

}
