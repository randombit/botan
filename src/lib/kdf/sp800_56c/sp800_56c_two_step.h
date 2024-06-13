/*
* Two-Step KDF defined in NIST SP 800-56Cr2 (Section 5)
* (C) 2016 Kai Michaelis
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SP800_56C_H_
#define BOTAN_SP800_56C_H_

#include <botan/kdf.h>
#include <botan/mac.h>

namespace Botan {

/**
 * NIST SP 800-56C Two-Step KDF (Section 5)
 */
class SP800_56C_Two_Step final : public KDF {
   public:
      std::string name() const override;

      std::unique_ptr<KDF> new_object() const override;

      /**
      * Derive a key using the SP800-56C Two-Step KDF.
      *
      * The implementation hard codes the context value for the
      * expansion step to the empty string.
      *
      * @param key derived keying material K_M
      * @param key_len the desired output length in bytes
      * @param secret shared secret Z
      * @param secret_len size of Z in bytes
      * @param salt salt s of the extraction step
      * @param salt_len size of s in bytes
      * @param label label for the expansion step
      * @param label_len size of label in bytes
      */
      void kdf(uint8_t key[],
               size_t key_len,
               const uint8_t secret[],
               size_t secret_len,
               const uint8_t salt[],
               size_t salt_len,
               const uint8_t label[],
               size_t label_len) const override;

      /**
      * @param mac MAC algorithm used for randomness extraction
      * @param exp KDF used for key expansion
      */
      SP800_56C_Two_Step(std::unique_ptr<MessageAuthenticationCode> mac, std::unique_ptr<KDF> exp) :
            m_prf(std::move(mac)), m_exp(std::move(exp)) {}

   private:
      std::unique_ptr<MessageAuthenticationCode> m_prf;
      std::unique_ptr<KDF> m_exp;
};
}  // namespace Botan

#endif
