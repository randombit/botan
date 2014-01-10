/*
* OpenSSL BN Wrapper
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/bn_wrap.h>

namespace Botan {

/*
* OSSL_BN Constructor
*/
OSSL_BN::OSSL_BN(const BigInt& in)
   {
   m_bn = BN_new();
   secure_vector<byte> encoding = BigInt::encode_locked(in);
   if(in != 0)
      BN_bin2bn(&encoding[0], encoding.size(), m_bn);
   }

/*
* OSSL_BN Constructor
*/
OSSL_BN::OSSL_BN(const byte in[], size_t length)
   {
   m_bn = BN_new();
   BN_bin2bn(in, length, m_bn);
   }

/*
* OSSL_BN Copy Constructor
*/
OSSL_BN::OSSL_BN(const OSSL_BN& other)
   {
   m_bn = BN_dup(other.m_bn);
   }

/*
* OSSL_BN Destructor
*/
OSSL_BN::~OSSL_BN()
   {
   BN_clear_free(m_bn);
   }

/*
* OSSL_BN Assignment Operator
*/
OSSL_BN& OSSL_BN::operator=(const OSSL_BN& other)
   {
   BN_copy(m_bn, other.m_bn);
   return (*this);
   }

/*
* Export the BIGNUM as a bytestring
*/
void OSSL_BN::encode(byte out[], size_t length) const
   {
   BN_bn2bin(m_bn, out + (length - bytes()));
   }

/*
* Return the number of significant bytes
*/
size_t OSSL_BN::bytes() const
   {
   return BN_num_bytes(m_bn);
   }

/*
* OpenSSL to BigInt Conversions
*/
BigInt OSSL_BN::to_bigint() const
   {
   secure_vector<byte> out(bytes());
   BN_bn2bin(m_bn, &out[0]);
   return BigInt::decode(out);
   }

/*
* OSSL_BN_CTX Constructor
*/
OSSL_BN_CTX::OSSL_BN_CTX()
   {
   m_ctx = BN_CTX_new();
   }

/*
* OSSL_BN_CTX Copy Constructor
*/
OSSL_BN_CTX::OSSL_BN_CTX(const OSSL_BN_CTX&)
   {
   m_ctx = BN_CTX_new();
   }

/*
* OSSL_BN_CTX Destructor
*/
OSSL_BN_CTX::~OSSL_BN_CTX()
   {
   BN_CTX_free(m_ctx);
   }

/*
* OSSL_BN_CTX Assignment Operator
*/
OSSL_BN_CTX& OSSL_BN_CTX::operator=(const OSSL_BN_CTX&)
   {
   m_ctx = BN_CTX_new();
   return (*this);
   }

}
