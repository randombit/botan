/*************************************************
* PK Utility Classes Source File                 *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/pk_util.h>

namespace Botan {

/*************************************************
* Encode a message                               *
*************************************************/
SecureVector<byte> EME::encode(const byte msg[], u32bit msg_len,
                               u32bit key_bits) const
   {
   return pad(msg, msg_len, key_bits);
   }

/*************************************************
* Encode a message                               *
*************************************************/
SecureVector<byte> EME::encode(const MemoryRegion<byte>& msg,
                               u32bit key_bits) const
   {
   return pad(msg, msg.size(), key_bits);
   }

/*************************************************
* Decode a message                               *
*************************************************/
SecureVector<byte> EME::decode(const byte msg[], u32bit msg_len,
                               u32bit key_bits) const
   {
   return unpad(msg, msg_len, key_bits);
   }

/*************************************************
* Decode a message                               *
*************************************************/
SecureVector<byte> EME::decode(const MemoryRegion<byte>& msg,
                               u32bit key_bits) const
   {
   return unpad(msg, msg.size(), key_bits);
   }

/*************************************************
* Default signature decoding                     *
*************************************************/
bool EMSA::verify(const MemoryRegion<byte>& coded,
                  const MemoryRegion<byte>& raw,
                  u32bit key_bits) throw()
   {
   try {
      return (coded == encoding_of(raw, key_bits));
      }
   catch(Invalid_Argument)
      {
      return false;
      }
   }

}
