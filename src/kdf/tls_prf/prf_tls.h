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

/**
* PRF used in TLS 1.0/1.1
*/
class BOTAN_DLL TLS_PRF : public KDF
   {
   public:
      SecureVector<byte> derive(size_t key_len,
                                const byte secret[], size_t secret_len,
                                const byte seed[], size_t seed_len) const;

      TLS_PRF();
      ~TLS_PRF();
   private:
      MessageAuthenticationCode* hmac_md5;
      MessageAuthenticationCode* hmac_sha1;
   };

/**
* PRF used in TLS 1.2
*/
class BOTAN_DLL TLS_12_PRF : public KDF
   {
   public:
      SecureVector<byte> derive(size_t key_len,
                                const byte secret[], size_t secret_len,
                                const byte seed[], size_t seed_len) const;

      TLS_12_PRF(HashFunction* hash);
      ~TLS_12_PRF();
   private:
      MessageAuthenticationCode* hmac;
   };

}

#endif
