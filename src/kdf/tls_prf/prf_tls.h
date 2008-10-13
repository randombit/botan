/*************************************************
* TLS v1.0 PRF Header File                       *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_TLS_PRF_H__
#define BOTAN_TLS_PRF_H__

#include <botan/kdf.h>
#include <botan/base.h>

namespace Botan {

/*************************************************
* TLS PRF                                        *
*************************************************/
class BOTAN_DLL TLS_PRF : public KDF
   {
   public:
      SecureVector<byte> derive(u32bit, const byte[], u32bit,
                                const byte[], u32bit) const;

      TLS_PRF();
      ~TLS_PRF();
   private:
      static SecureVector<byte> P_hash(MessageAuthenticationCode*,
                                       u32bit,
                                       const byte[], u32bit,
                                       const byte[], u32bit);

      MessageAuthenticationCode* hmac_md5;
      MessageAuthenticationCode* hmac_sha1;
   };

}

#endif
