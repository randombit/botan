/*************************************************
* EMSA-Raw Header File                           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_EMSA_RAW_H__
#define BOTAN_EMSA_RAW_H__

#include <botan/pk_pad.h>

namespace Botan {

/*************************************************
* EMSA-Raw                                       *
*************************************************/
class BOTAN_DLL EMSA_Raw : public EMSA
   {
   private:
      void update(const byte[], u32bit);
      SecureVector<byte> raw_data();

      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, u32bit,
                                     RandomNumberGenerator&);
      bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  u32bit) throw();

      SecureVector<byte> message;
   };

}

#endif
