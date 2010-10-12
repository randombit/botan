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

/**
* EMSA2 from IEEE 1363
* Useful for Rabin-Williams
*/
class BOTAN_DLL EMSA2 : public EMSA
   {
   public:
      /**
      * @param hash the hash object to use
      */
      EMSA2(HashFunction* hash);
      ~EMSA2() { delete hash; }
   private:
      void update(const byte[], size_t);
      SecureVector<byte> raw_data();

      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, size_t,
                                     RandomNumberGenerator& rng);

      bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  size_t);

      SecureVector<byte> empty_hash;
      HashFunction* hash;
      byte hash_id;
   };

}

#endif
