/*
* OFB Mode
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_OUTPUT_FEEDBACK_MODE_H_
#define BOTAN_OUTPUT_FEEDBACK_MODE_H_

#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>

namespace Botan {

/**
* Output Feedback Mode
*/
class OFB final : public StreamCipher {
   public:
      size_t default_iv_length() const override;

      bool valid_iv_length(size_t iv_len) const override;

      Key_Length_Specification key_spec() const override;

      std::string name() const override;

      std::unique_ptr<StreamCipher> new_object() const override;

      void clear() override;

      bool has_keying_material() const override;

      size_t buffer_size() const override;

      /**
      * @param cipher the block cipher to use
      */
      explicit OFB(std::unique_ptr<BlockCipher> cipher);

      void seek(uint64_t offset) override;

   private:
      void key_schedule(std::span<const uint8_t> key) override;
      void cipher_bytes(const uint8_t in[], uint8_t out[], size_t length) override;
      void set_iv_bytes(const uint8_t iv[], size_t iv_len) override;

      std::unique_ptr<BlockCipher> m_cipher;
      secure_vector<uint8_t> m_buffer;
      size_t m_buf_pos;
};

}  // namespace Botan

#endif
