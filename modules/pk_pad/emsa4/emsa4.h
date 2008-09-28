/*************************************************
* EMSA4 Header File                              *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_EMSA4_H__
#define BOTAN_EMSA4_H__

#include <botan/pk_util.h>

namespace Botan {

/*************************************************
* EMSA4                                          *
*************************************************/
class BOTAN_DLL EMSA4 : public EMSA
   {
   public:
      EMSA4(const std::string&, const std::string&);
      EMSA4(const std::string&, const std::string&, u32bit);
      ~EMSA4() { delete hash; delete mgf; }
   private:
      void update(const byte[], u32bit);
      SecureVector<byte> raw_data();

      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, u32bit,
                                     RandomNumberGenerator& rng);
      bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  u32bit) throw();

      const u32bit SALT_SIZE;
      HashFunction* hash;
      const MGF* mgf;
   };

}

#endif
