/*
* TLS v1.0 PRF
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_TLS_PRF_H__
#define BOTAN_TLS_PRF_H__

#include <botan/kdf.h>
#include <botan/mac.h>

namespace Botan {

/*
* TLS PRF
*/
class BOTAN_DLL TLS_PRF : public KDF
   {
   public:
      SecureVector<byte> derive(u32bit, const byte[], u32bit,
                                const byte[], u32bit) const;

      TLS_PRF();
      ~TLS_PRF();
   private:
      MessageAuthenticationCode* hmac_md5;
      MessageAuthenticationCode* hmac_sha1;
   };

}

#endif
