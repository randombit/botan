/*
* EMSA2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_EMSA2_H__
#define BOTAN_EMSA2_H__

#include <botan/emsa.h>
#include <botan/hash.h>

namespace Botan {

/*
* EMSA2
*/
class BOTAN_DLL EMSA2 : public EMSA
   {
   public:
      EMSA2(HashFunction* hash);
      ~EMSA2() { delete hash; }
   private:
      void update(const byte[], u32bit);
      SecureVector<byte> raw_data();

      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, u32bit,
                                     RandomNumberGenerator& rng);

      bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  u32bit) throw();

      SecureVector<byte> empty_hash;
      HashFunction* hash;
      byte hash_id;
   };

}

#endif
