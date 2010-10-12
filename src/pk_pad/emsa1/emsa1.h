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

/**
* EMSA1 from IEEE 1363
* Essentially, sign the hash directly
*/
class BOTAN_DLL EMSA1 : public EMSA
   {
   public:
      /**
      * @param h the hash object to use
      */
      EMSA1(HashFunction* h) : hash(h) {}
      ~EMSA1() { delete hash; }
   protected:
      /**
      * @return const pointer to the underlying hash
      */
      const HashFunction* hash_ptr() const { return hash; }
   private:
      void update(const byte[], size_t);
      SecureVector<byte> raw_data();

      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, size_t,
                                     RandomNumberGenerator& rng);

      bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  size_t);

      HashFunction* hash;
   };

}

#endif
