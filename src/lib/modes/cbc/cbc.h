/*
* CBC mode
* (C) 1999-2007,2013 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MODE_CBC_H_
#define BOTAN_MODE_CBC_H_

#include <botan/block_cipher.h>
#include <botan/cipher_mode.h>
#include <botan/internal/mode_pad.h>

namespace Botan {

/**
* CBC Mode
*/
class CBC_Mode : public Cipher_Mode {
   public:
      std::string name() const final;

      size_t update_granularity() const final;

      size_t ideal_granularity() const final;

      Key_Length_Specification key_spec() const final;

      size_t default_nonce_length() const final;

      bool valid_nonce_length(size_t n) const override;

      void clear() final;

      void reset() override;

      bool has_keying_material() const final;

   protected:
      CBC_Mode(std::unique_ptr<BlockCipher> cipher, std::unique_ptr<BlockCipherModePaddingMethod> padding);

      const BlockCipher& cipher() const { return *m_cipher; }

      const BlockCipherModePaddingMethod& padding() const {
         BOTAN_ASSERT_NONNULL(m_padding);
         return *m_padding;
      }

      size_t block_size() const { return m_block_size; }

      secure_vector<uint8_t>& state() { return m_state; }

      uint8_t* state_ptr() { return m_state.data(); }

   private:
      void start_msg(const uint8_t nonce[], size_t nonce_len) override;

      void key_schedule(std::span<const uint8_t> key) override;

      std::unique_ptr<BlockCipher> m_cipher;
      std::unique_ptr<BlockCipherModePaddingMethod> m_padding;
      secure_vector<uint8_t> m_state;
      size_t m_block_size;
};

/**
* CBC Encryption
*/
class CBC_Encryption : public CBC_Mode {
   public:
      /**
      * @param cipher block cipher to use
      * @param padding padding method to use
      */
      CBC_Encryption(std::unique_ptr<BlockCipher> cipher, std::unique_ptr<BlockCipherModePaddingMethod> padding) :
            CBC_Mode(std::move(cipher), std::move(padding)) {}

      size_t output_length(size_t input_length) const override;

      size_t minimum_final_size() const override;

   private:
      size_t process_msg(uint8_t buf[], size_t size) override;
      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
};

/**
* CBC Encryption with ciphertext stealing (CBC-CS3 variant)
*/
class CTS_Encryption final : public CBC_Encryption {
   public:
      /**
      * @param cipher block cipher to use
      */
      explicit CTS_Encryption(std::unique_ptr<BlockCipher> cipher) : CBC_Encryption(std::move(cipher), nullptr) {}

      size_t output_length(size_t input_length) const override;

      size_t minimum_final_size() const override;

      bool valid_nonce_length(size_t n) const override;

   private:
      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
};

/**
* CBC Decryption
*/
class CBC_Decryption : public CBC_Mode {
   public:
      /**
      * @param cipher block cipher to use
      * @param padding padding method to use
      */
      CBC_Decryption(std::unique_ptr<BlockCipher> cipher, std::unique_ptr<BlockCipherModePaddingMethod> padding) :
            CBC_Mode(std::move(cipher), std::move(padding)), m_tempbuf(ideal_granularity()) {}

      size_t output_length(size_t input_length) const override;

      size_t minimum_final_size() const override;

      void reset() override;

   private:
      size_t process_msg(uint8_t buf[], size_t size) override;
      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;

      secure_vector<uint8_t> m_tempbuf;
};

/**
* CBC Decryption with ciphertext stealing (CBC-CS3 variant)
*/
class CTS_Decryption final : public CBC_Decryption {
   public:
      /**
      * @param cipher block cipher to use
      */
      explicit CTS_Decryption(std::unique_ptr<BlockCipher> cipher) : CBC_Decryption(std::move(cipher), nullptr) {}

      size_t minimum_final_size() const override;

      bool valid_nonce_length(size_t n) const override;

   private:
      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
};

}  // namespace Botan

#endif
