/*
* EME Classes
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PUBKEY_EME_ENCRYPTION_PAD_H__
#define BOTAN_PUBKEY_EME_ENCRYPTION_PAD_H__

#include <botan/secmem.h>
#include <botan/rng.h>

namespace Botan {

/*
* Encoding Method for Encryption
*/
class BOTAN_DLL EME
   {
   public:
      virtual u32bit maximum_input_size(u32bit) const = 0;

      SecureVector<byte> encode(const byte[], u32bit, u32bit,
                                RandomNumberGenerator&) const;
      SecureVector<byte> encode(const MemoryRegion<byte>&, u32bit,
                                RandomNumberGenerator&) const;

      SecureVector<byte> decode(const byte[], u32bit, u32bit) const;
      SecureVector<byte> decode(const MemoryRegion<byte>&, u32bit) const;

      virtual ~EME() {}
   private:
      virtual SecureVector<byte> pad(const byte[], u32bit, u32bit,
                                     RandomNumberGenerator&) const = 0;

      virtual SecureVector<byte> unpad(const byte[], u32bit, u32bit) const = 0;
   };

}

#endif
