/*
* EMSA4
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_EMSA4_H__
#define BOTAN_EMSA4_H__

#include <botan/emsa.h>
#include <botan/hash.h>
#include <botan/kdf.h>

namespace Botan {

/**
* EMSA4 aka PSS-R
*/
class BOTAN_DLL EMSA4 : public EMSA
   {
   public:
      /**
      * @param hash the hash object to use
      */
      EMSA4(HashFunction* hash);

      /**
      * @param hash the hash object to use
      * @param salt_size the size of the salt to use in bytes
      */
      EMSA4(HashFunction* hash, size_t salt_size);

      ~EMSA4() { delete hash; delete mgf; }
   private:
      void update(const byte[], size_t);
      SecureVector<byte> raw_data();

      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, size_t,
                                     RandomNumberGenerator& rng);
      bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  size_t);

      size_t SALT_SIZE;
      HashFunction* hash;
      const MGF* mgf;
   };

}

#endif
