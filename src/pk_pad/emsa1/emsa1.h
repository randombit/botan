/*
* EMSA1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_EMSA1_H__
#define BOTAN_EMSA1_H__

#include <botan/emsa.h>
#include <botan/hash.h>

namespace Botan {

/*
* EMSA1
*/
class BOTAN_DLL EMSA1 : public EMSA
   {
   public:
      EMSA1(HashFunction* h) : hash(h) {}
      ~EMSA1() { delete hash; }
   protected:
      const HashFunction* hash_ptr() const { return hash; }
   private:
      void update(const byte[], u32bit);
      SecureVector<byte> raw_data();

      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, u32bit,
                                     RandomNumberGenerator& rng);

      bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  u32bit) throw();

      HashFunction* hash;
   };

}

#endif
