/*
 * GMAC
 * (C) 2016 Matthias Gierlings, René Korthaus
 * (C) 2017 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_GMAC_H_
#define BOTAN_GMAC_H_

#include <botan/mac.h>

namespace Botan {

class BlockCipher;
class GHASH;

/**
* GMAC
*
* GMAC requires a unique initialization vector be used for each message.
* This must be provided via the MessageAuthenticationCode::start() API
*/
class GMAC final : public MessageAuthenticationCode {
   public:
      void clear() override;
      std::string name() const override;
      size_t output_length() const override;
      std::unique_ptr<MessageAuthenticationCode> new_object() const override;

      Key_Length_Specification key_spec() const override;

      bool has_keying_material() const override;

      /**
      * Creates a new GMAC instance.
      *
      * @param cipher the underlying block cipher to use
      */
      explicit GMAC(std::unique_ptr<BlockCipher> cipher);

      GMAC(const GMAC&) = delete;
      GMAC& operator=(const GMAC&) = delete;

      ~GMAC() override;

   private:
      void add_data(std::span<const uint8_t>) override;
      void final_result(std::span<uint8_t>) override;
      void start_msg(std::span<const uint8_t> nonce) override;
      void key_schedule(std::span<const uint8_t> key) override;

      static const size_t GCM_BS = 16;
      std::unique_ptr<BlockCipher> m_cipher;
      std::unique_ptr<GHASH> m_ghash;
      secure_vector<uint8_t> m_H;
      bool m_initialized;
};

}  // namespace Botan
#endif
