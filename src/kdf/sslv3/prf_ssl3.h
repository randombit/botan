/*************************************************
* SSLv3 PRF Header File                          *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_SSLV3_PRF_H__
#define BOTAN_SSLV3_PRF_H__

#include <botan/kdf.h>

namespace Botan {

/*************************************************
* SSL3 PRF                                       *
*************************************************/
class BOTAN_DLL SSL3_PRF : public KDF
   {
   public:
      SecureVector<byte> derive(u32bit, const byte[], u32bit,
                                const byte[], u32bit) const;
   };

}

#endif
