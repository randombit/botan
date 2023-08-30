/*
* (C) 2015 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_STREAM_MODE_H_
#define BOTAN_STREAM_MODE_H_

#include <botan/cipher_mode.h>

#if defined(BOTAN_HAS_STREAM_CIPHER)
   #include <botan/stream_cipher.h>
#endif

namespace Botan {

#if defined(BOTAN_HAS_STREAM_CIPHER)

class Stream_Cipher_Mode final : public Cipher_Mode {
   public:
      /**
      * @param cipher underyling stream cipher
      */
      explicit Stream_Cipher_Mode(std::unique_ptr<StreamCipher> cipher) : m_cipher(std::move(cipher)) {}

      size_t output_length(size_t input_length) const override { return input_length; }

      size_t update_granularity() const override { return 1; }

      size_t ideal_granularity() const override {
         const size_t buf_size = m_cipher->buffer_size();
         BOTAN_ASSERT_NOMSG(buf_size > 0);
         if(buf_size >= 256) {
            return buf_size;
         }
         return buf_size * (256 / buf_size);
      }

      size_t minimum_final_size() const override { return 0; }

      size_t default_nonce_length() const override { return 0; }

      bool valid_nonce_length(size_t nonce_len) const override { return m_cipher->valid_iv_length(nonce_len); }

      Key_Length_Specification key_spec() const override { return m_cipher->key_spec(); }

      std::string name() const override { return m_cipher->name(); }

      void clear() override {
         m_cipher->clear();
         reset();
      }

      void reset() override { /* no msg state */
      }

      bool has_keying_material() const override { return m_cipher->has_keying_material(); }

   private:
      void start_msg(const uint8_t nonce[], size_t nonce_len) override {
         if(nonce_len > 0) {
            m_cipher->set_iv(nonce, nonce_len);
         }
      }

      size_t process_msg(uint8_t buf[], size_t sz) override {
         m_cipher->cipher1(buf, sz);
         return sz;
      }

      void finish_msg(secure_vector<uint8_t>& buf, size_t offset) override { return update(buf, offset); }

      void key_schedule(std::span<const uint8_t> key) override { m_cipher->set_key(key); }

      std::unique_ptr<StreamCipher> m_cipher;
};

#endif

}  // namespace Botan

#endif
