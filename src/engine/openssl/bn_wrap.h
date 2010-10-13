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

/**
* Lightweight OpenSSL BN wrapper. For internal use only.
*/
class OSSL_BN
   {
   public:
      BIGNUM* value;

      BigInt to_bigint() const;
      void encode(byte[], size_t) const;
      size_t bytes() const;

      SecureVector<byte> to_bytes() const
         { return BigInt::encode(to_bigint()); }

      OSSL_BN& operator=(const OSSL_BN&);

      OSSL_BN(const OSSL_BN&);
      OSSL_BN(const BigInt& = 0);
      OSSL_BN(const byte[], size_t);
      ~OSSL_BN();
   };

/**
* Lightweight OpenSSL BN_CTX wrapper. For internal use only.
*/
class OSSL_BN_CTX
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
