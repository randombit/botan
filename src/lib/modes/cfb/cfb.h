/*
* CFB mode
* (C) 1999-2007,2013 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MODE_CFB_H_
#define BOTAN_MODE_CFB_H_

#include <botan/block_cipher.h>
#include <botan/cipher_mode.h>

namespace Botan {

/**
* CFB Mode
*/
class CFB_Mode : public Cipher_Mode {
   public:
      std::string name() const final;

      size_t update_granularity() const final;

      size_t ideal_granularity() const final;

      size_t minimum_final_size() const final;

      Key_Length_Specification key_spec() const final;

      size_t output_length(size_t input_length) const final;

      size_t default_nonce_length() const final;

      bool valid_nonce_length(size_t n) const final;

      void clear() final;

      void reset() final;

      bool has_keying_material() const final;

   protected:
      CFB_Mode(std::unique_ptr<BlockCipher> cipher, size_t feedback_bits);

      void shift_register();

      size_t feedback() const { return m_feedback_bytes; }

      const BlockCipher& cipher() const { return *m_cipher; }

      size_t block_size() const { return m_block_size; }

      secure_vector<uint8_t> m_state;
      secure_vector<uint8_t> m_keystream;
      size_t m_keystream_pos = 0;

   private:
      void start_msg(const uint8_t nonce[], size_t nonce_len) override;
      void key_schedule(std::span<const uint8_t> key) override;

      std::unique_ptr<BlockCipher> m_cipher;
      const size_t m_block_size;
      const size_t m_feedback_bytes;
};

/**
* CFB Encryption
*/
class CFB_Encryption final : public CFB_Mode {
   public:
      /**
      * If feedback_bits is zero, cipher->block_size() bytes will be used.
      * @param cipher block cipher to use
      * @param feedback_bits number of bits fed back into the shift register,
      * must be a multiple of 8
      */
      CFB_Encryption(std::unique_ptr<BlockCipher> cipher, size_t feedback_bits) :
            CFB_Mode(std::move(cipher), feedback_bits) {}

   private:
      size_t process_msg(uint8_t buf[], size_t size) override;
      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
};

/**
* CFB Decryption
*/
class CFB_Decryption final : public CFB_Mode {
   public:
      /**
      * If feedback_bits is zero, cipher->block_size() bytes will be used.
      * @param cipher block cipher to use
      * @param feedback_bits number of bits fed back into the shift register,
      * must be a multiple of 8
      */
      CFB_Decryption(std::unique_ptr<BlockCipher> cipher, size_t feedback_bits) :
            CFB_Mode(std::move(cipher), feedback_bits) {}

   private:
      size_t process_msg(uint8_t buf[], size_t size) override;
      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
};

}  // namespace Botan

#endif
