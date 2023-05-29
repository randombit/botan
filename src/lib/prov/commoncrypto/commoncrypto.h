/*
* Utils for calling CommonCrypto
* (C) 2018 Jose Pereira
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_INTERNAL_COMMONCRYPTO_H_
#define BOTAN_INTERNAL_COMMONCRYPTO_H_

#include <botan/exceptn.h>
#include <botan/pk_ops_fwd.h>
#include <botan/secmem.h>
#include <memory>
#include <string>
#include <string_view>

namespace Botan {

class Cipher_Mode;
class BlockCipher;
class HashFunction;
enum class Cipher_Dir : int;
typedef int32_t CCCryptorStatus;

class BOTAN_PUBLIC_API(2, 0) CommonCrypto_Error final : public Exception {
   public:
      CommonCrypto_Error(std::string_view what);

      CommonCrypto_Error(std::string_view what, int32_t status);

      ErrorType error_type() const noexcept override { return ErrorType::CommonCryptoError; }

      int error_code() const noexcept override { return m_rc; }

   private:
      static std::string ccryptorstatus_to_string(CCCryptorStatus status);

      int32_t m_rc;
};

/* Cipher Modes */

std::unique_ptr<Cipher_Mode> make_commoncrypto_cipher_mode(std::string_view name, Cipher_Dir direction);

/* Block Ciphers */

std::unique_ptr<BlockCipher> make_commoncrypto_block_cipher(std::string_view name);

/* Hash */

std::unique_ptr<HashFunction> make_commoncrypto_hash(std::string_view name);

}  // namespace Botan

#endif
