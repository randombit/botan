/*
* CMAC
* (C) 1999-2007,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CMAC_H_
#define BOTAN_CMAC_H_

#include <botan/block_cipher.h>
#include <botan/mac.h>

namespace Botan {

/**
* CMAC, also known as OMAC1
*/
class CMAC final : public MessageAuthenticationCode {
   public:
      std::string name() const override;

      size_t output_length() const override { return m_block_size; }

      std::unique_ptr<MessageAuthenticationCode> new_object() const override;

      void clear() override;
      bool has_keying_material() const override;

      Key_Length_Specification key_spec() const override { return m_cipher->key_spec(); }

      /**
      * @param cipher the block cipher to use
      */
      explicit CMAC(std::unique_ptr<BlockCipher> cipher);

      CMAC(const CMAC&) = delete;
      CMAC& operator=(const CMAC&) = delete;

   private:
      void add_data(std::span<const uint8_t>) override;
      void final_result(std::span<uint8_t>) override;
      void key_schedule(std::span<const uint8_t>) override;

      std::unique_ptr<BlockCipher> m_cipher;
      secure_vector<uint8_t> m_buffer, m_state, m_B, m_P;
      const size_t m_block_size;
      size_t m_position;
};

}  // namespace Botan

#endif
