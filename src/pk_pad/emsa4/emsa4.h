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

/*
* EMSA4
*/
class BOTAN_DLL EMSA4 : public EMSA
   {
   public:
      EMSA4(HashFunction*);
      EMSA4(HashFunction*, u32bit);

      ~EMSA4() { delete hash; delete mgf; }
   private:
      void update(const byte[], u32bit);
      SecureVector<byte> raw_data();

      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, u32bit,
                                     RandomNumberGenerator& rng);
      bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  u32bit) throw();

      u32bit SALT_SIZE;
      HashFunction* hash;
      const MGF* mgf;
   };

}

#endif
