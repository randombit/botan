/*************************************************
* EME PKCS#1 v1.5 Header File                    *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_EME_PKCS1_H__
#define BOTAN_EME_PKCS1_H__

#include <botan/eme.h>

namespace Botan {

/*************************************************
* EME_PKCS1v15                                   *
*************************************************/
class BOTAN_DLL EME_PKCS1v15 : public EME
   {
   public:
      u32bit maximum_input_size(u32bit) const;
   private:
      SecureVector<byte> pad(const byte[], u32bit, u32bit,
                             RandomNumberGenerator&) const;
      SecureVector<byte> unpad(const byte[], u32bit, u32bit) const;
   };

}

#endif
