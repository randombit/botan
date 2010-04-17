/*
* TLS v1.0 and v1.2 PRFs
* (C) 2004-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_TLS_PRF_H__
#define BOTAN_TLS_PRF_H__

#include <botan/kdf.h>
#include <botan/mac.h>
#include <botan/hash.h>

namespace Botan {

/*
* TLS PRF
*/
class BOTAN_DLL TLS_PRF : public KDF
   {
   public:
      SecureVector<byte> derive(u32bit key_len,
                                const byte secret[], u32bit secret_len,
                                const byte seed[], u32bit seed_len) const;

      TLS_PRF();
      ~TLS_PRF();
   private:
      MessageAuthenticationCode* hmac_md5;
      MessageAuthenticationCode* hmac_sha1;
   };

/*
* TLS 1.2 PRF
*/
class BOTAN_DLL TLS_12_PRF : public KDF
   {
   public:
      SecureVector<byte> derive(u32bit key_len,
                                const byte secret[], u32bit secret_len,
                                const byte seed[], u32bit seed_len) const;

      TLS_12_PRF(HashFunction* hash);
      ~TLS_12_PRF();
   private:
      MessageAuthenticationCode* hmac;
   };

}

#endif
