/*
* EMSA Classes
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PUBKEY_EMSA_H__
#define BOTAN_PUBKEY_EMSA_H__

#include <botan/secmem.h>
#include <botan/rng.h>

namespace Botan {

/*
* Encoding Method for Signatures, Appendix
*/
class BOTAN_DLL EMSA
   {
   public:
      virtual void update(const byte[], u32bit) = 0;
      virtual SecureVector<byte> raw_data() = 0;

      virtual SecureVector<byte> encoding_of(const MemoryRegion<byte>&,
                                             u32bit,
                                             RandomNumberGenerator& rng) = 0;

      virtual bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                          u32bit) throw() = 0;
      virtual ~EMSA() {}
   };

}

#endif
