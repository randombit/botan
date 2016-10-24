/*
* Utils for calling OpenSSL
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_INTERNAL_OPENSSL_H__
#define BOTAN_INTERNAL_OPENSSL_H__

#include <botan/internal/pk_ops.h>
#include <botan/secmem.h>
#include <botan/exceptn.h>
#include <memory>
#include <string>

#include <openssl/err.h>
#include <openssl/evp.h>

#if defined(BOTAN_HAS_RC4)
#include <openssl/rc4.h>
#endif

namespace Botan {

class BlockCipher;
class StreamCipher;
class HashFunction;

class OpenSSL_Error : public Exception
   {
   public:
      OpenSSL_Error(const std::string& what) :
         Exception(what + " failed: " + ERR_error_string(ERR_get_error(), nullptr)) {}
   };

/* Block Ciphers */

std::unique_ptr<BlockCipher>
make_openssl_block_cipher(const std::string& name);

/* Hash */

std::unique_ptr<HashFunction>
make_openssl_hash(const std::string& name);

/* RSA */

#if defined(BOTAN_HAS_RSA)

class RSA_PublicKey;
class RSA_PrivateKey;

std::unique_ptr<PK_Ops::Encryption>
make_openssl_rsa_enc_op(const RSA_PublicKey& key, const std::string& params);
std::unique_ptr<PK_Ops::Decryption>
make_openssl_rsa_dec_op(const RSA_PrivateKey& key, const std::string& params);

std::unique_ptr<PK_Ops::Verification>
make_openssl_rsa_ver_op(const RSA_PublicKey& key, const std::string& params);
std::unique_ptr<PK_Ops::Signature>
make_openssl_rsa_sig_op(const RSA_PrivateKey& key, const std::string& params);

#endif

/* ECDSA */

#if defined(BOTAN_HAS_ECDSA)

class ECDSA_PublicKey;
class ECDSA_PrivateKey;

std::unique_ptr<PK_Ops::Verification>
make_openssl_ecdsa_ver_op(const ECDSA_PublicKey& key, const std::string& params);
std::unique_ptr<PK_Ops::Signature>
make_openssl_ecdsa_sig_op(const ECDSA_PrivateKey& key, const std::string& params);

#endif

/* ECDH */

#if defined(BOTAN_HAS_ECDH)

class ECDH_PrivateKey;

std::unique_ptr<PK_Ops::Key_Agreement>
make_openssl_ecdh_ka_op(const ECDH_PrivateKey& key, const std::string& params);

#endif

#if defined(BOTAN_HAS_RC4)

std::unique_ptr<StreamCipher>
make_openssl_rc4(size_t skip);

#endif

}

#endif
