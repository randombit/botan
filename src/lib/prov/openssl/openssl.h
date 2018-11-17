/*
* Utils for calling OpenSSL
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_INTERNAL_OPENSSL_H_
#define BOTAN_INTERNAL_OPENSSL_H_

#include <botan/pk_ops_fwd.h>
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
class Cipher_Mode;
class StreamCipher;
class HashFunction;
class RandomNumberGenerator;
enum Cipher_Dir : int;

class BOTAN_PUBLIC_API(2,0) OpenSSL_Error final : public Exception
   {
   public:
      OpenSSL_Error(const std::string& what, int err) :
         Exception(what + " failed: " + ERR_error_string(err, nullptr)),
         m_err(err) {}

      ErrorType error_type() const noexcept override { return ErrorType::OpenSSLError; }

      int error_code() const noexcept override { return m_err; }

   private:
      int m_err;
   };

/* Block Ciphers */

std::unique_ptr<BlockCipher>
make_openssl_block_cipher(const std::string& name);

/* Cipher Modes */

Cipher_Mode*
make_openssl_cipher_mode(const std::string& name, Cipher_Dir direction);

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
std::unique_ptr<RSA_PrivateKey>
make_openssl_rsa_private_key(RandomNumberGenerator& rng, size_t rsa_bits);

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
