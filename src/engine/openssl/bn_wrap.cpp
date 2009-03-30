/*
* OpenSSL BN Wrapper
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/bn_wrap.h>

namespace Botan {

/*
* OSSL_BN Constructor
*/
OSSL_BN::OSSL_BN(const BigInt& in)
   {
   value = BN_new();
   SecureVector<byte> encoding = BigInt::encode(in);
   if(in != 0)
      BN_bin2bn(encoding, encoding.size(), value);
   }

/*
* OSSL_BN Constructor
*/
OSSL_BN::OSSL_BN(const byte in[], u32bit length)
   {
   value = BN_new();
   BN_bin2bn(in, length, value);
   }

/*
* OSSL_BN Copy Constructor
*/
OSSL_BN::OSSL_BN(const OSSL_BN& other)
   {
   value = BN_dup(other.value);
   }

/*
* OSSL_BN Destructor
*/
OSSL_BN::~OSSL_BN()
   {
   BN_clear_free(value);
   }

/*
* OSSL_BN Assignment Operator
*/
OSSL_BN& OSSL_BN::operator=(const OSSL_BN& other)
   {
   BN_copy(value, other.value);
   return (*this);
   }

/*
* Export the BIGNUM as a bytestring
*/
void OSSL_BN::encode(byte out[], u32bit length) const
   {
   BN_bn2bin(value, out + (length - bytes()));
   }

/*
* Return the number of significant bytes
*/
u32bit OSSL_BN::bytes() const
   {
   return BN_num_bytes(value);
   }

/*
* OpenSSL to BigInt Conversions
*/
BigInt OSSL_BN::to_bigint() const
   {
   SecureVector<byte> out(bytes());
   BN_bn2bin(value, out);
   return BigInt::decode(out);
   }

/*
* OSSL_BN_CTX Constructor
*/
OSSL_BN_CTX::OSSL_BN_CTX()
   {
   value = BN_CTX_new();
   }

/*
* OSSL_BN_CTX Copy Constructor
*/
OSSL_BN_CTX::OSSL_BN_CTX(const OSSL_BN_CTX&)
   {
   value = BN_CTX_new();
   }

/*
* OSSL_BN_CTX Destructor
*/
OSSL_BN_CTX::~OSSL_BN_CTX()
   {
   BN_CTX_free(value);
   }

/*
* OSSL_BN_CTX Assignment Operator
*/
OSSL_BN_CTX& OSSL_BN_CTX::operator=(const OSSL_BN_CTX&)
   {
   value = BN_CTX_new();
   return (*this);
   }

}
