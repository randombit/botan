/*
* OpenSSL BN Wrapper
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_OPENSSL_BN_WRAP_H__
#define BOTAN_OPENSSL_BN_WRAP_H__

#include <botan/bigint.h>
#include <openssl/bn.h>

namespace Botan {

/*
* Lightweight OpenSSL BN Wrapper
*/
class BOTAN_DLL OSSL_BN
   {
   public:
      BIGNUM* value;

      BigInt to_bigint() const;
      void encode(byte[], u32bit) const;
      u32bit bytes() const;

      OSSL_BN& operator=(const OSSL_BN&);

      OSSL_BN(const OSSL_BN&);
      OSSL_BN(const BigInt& = 0);
      OSSL_BN(const byte[], u32bit);
      ~OSSL_BN();
   };

/*
* Lightweight OpenSSL BN_CTX Wrapper
*/
class BOTAN_DLL OSSL_BN_CTX
   {
   public:
      BN_CTX* value;

      OSSL_BN_CTX& operator=(const OSSL_BN_CTX&);

      OSSL_BN_CTX();
      OSSL_BN_CTX(const OSSL_BN_CTX&);
      ~OSSL_BN_CTX();
   };

}

#endif
