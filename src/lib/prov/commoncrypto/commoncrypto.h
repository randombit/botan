/*
* Utils for calling CommonCrypto
* (C) 2018 Jose Pereira
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_INTERNAL_COMMONCRYPTO_H_
#define BOTAN_INTERNAL_COMMONCRYPTO_H_

#include <botan/pk_ops_fwd.h>
#include <botan/secmem.h>
#include <botan/exceptn.h>
#include <memory>
#include <string>

namespace Botan {

class Cipher_Mode;
class BlockCipher;
class HashFunction;
enum Cipher_Dir : int;
typedef int32_t CCCryptorStatus;

class BOTAN_PUBLIC_API(2, 0) CommonCrypto_Error final : public Exception
   {
   public:
      CommonCrypto_Error(const std::string& what) :
         Exception(what + " failed."),
         m_rc(0) {}

      CommonCrypto_Error(const std::string& what, int32_t status) :
         Exception(what + std::string(" failed. Status: ") + ccryptorstatus_to_string(status)),
         m_rc(status) {}

      ErrorType error_type() const noexcept override { return ErrorType::CommonCryptoError; }

      int error_code() const noexcept override { return m_rc; }

   private:
      std::string ccryptorstatus_to_string(CCCryptorStatus status);

      int32_t m_rc;
   };

/* Cipher Modes */

Cipher_Mode*
make_commoncrypto_cipher_mode(const std::string& name, Cipher_Dir direction);

/* Block Ciphers */

std::unique_ptr<BlockCipher>
make_commoncrypto_block_cipher(const std::string& name);

/* Hash */

std::unique_ptr<HashFunction> make_commoncrypto_hash(const std::string& name);

}

#endif
