/*************************************************
* EMSA3 Header File                              *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_EMSA3_H__
#define BOTAN_EMSA3_H__

#include <botan/pk_pad.h>

namespace Botan {

/*************************************************
* EMSA3                                          *
*************************************************/
class BOTAN_DLL EMSA3 : public EMSA
   {
   public:
      EMSA3(const std::string&);
      ~EMSA3() { delete hash; }
   private:
      void update(const byte[], u32bit);

      SecureVector<byte> raw_data();

      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, u32bit,
                                     RandomNumberGenerator& rng);

      bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  u32bit) throw();

      HashFunction* hash;
      SecureVector<byte> hash_id;
   };

}

#endif
