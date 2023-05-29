/*
* TLSv1.2 PRF
* (C) 2004-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_V12_PRF_H_
#define BOTAN_TLS_V12_PRF_H_

#include <botan/kdf.h>
#include <botan/mac.h>

namespace Botan {

/**
* PRF used in TLS 1.2
*/
class TLS_12_PRF final : public KDF {
   public:
      std::string name() const override;

      std::unique_ptr<KDF> new_object() const override;

      void kdf(uint8_t key[],
               size_t key_len,
               const uint8_t secret[],
               size_t secret_len,
               const uint8_t salt[],
               size_t salt_len,
               const uint8_t label[],
               size_t label_len) const override;

      /**
      * @param mac MAC algorithm to use
      */
      explicit TLS_12_PRF(std::unique_ptr<MessageAuthenticationCode> mac) : m_mac(std::move(mac)) {}

   private:
      std::unique_ptr<MessageAuthenticationCode> m_mac;
};

}  // namespace Botan

#endif
