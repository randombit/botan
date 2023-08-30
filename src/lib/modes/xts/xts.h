/*
* XTS mode, from IEEE P1619
* (C) 2009,2013 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MODE_XTS_H_
#define BOTAN_MODE_XTS_H_

#include <botan/block_cipher.h>
#include <botan/cipher_mode.h>

namespace Botan {

/**
* IEEE P1619 XTS Mode
*/
class XTS_Mode : public Cipher_Mode {
   public:
      std::string name() const final;

      size_t update_granularity() const final;

      size_t ideal_granularity() const final;

      size_t minimum_final_size() const final;

      Key_Length_Specification key_spec() const final;

      size_t default_nonce_length() const final;

      bool valid_nonce_length(size_t n) const final;

      void clear() final;

      void reset() final;

      bool has_keying_material() const final;

   protected:
      explicit XTS_Mode(std::unique_ptr<BlockCipher> cipher);

      const uint8_t* tweak() const { return m_tweak.data(); }

      bool tweak_set() const { return m_tweak.empty() == false; }

      size_t tweak_blocks() const { return m_tweak_blocks; }

      const BlockCipher& cipher() const { return *m_cipher; }

      void update_tweak(size_t last_used);

      size_t cipher_block_size() const { return m_cipher_block_size; }

   private:
      void start_msg(const uint8_t nonce[], size_t nonce_len) override;
      void key_schedule(std::span<const uint8_t> key) override;

      std::unique_ptr<BlockCipher> m_cipher;
      std::unique_ptr<BlockCipher> m_tweak_cipher;
      secure_vector<uint8_t> m_tweak;
      const size_t m_cipher_block_size;
      const size_t m_cipher_parallelism;
      const size_t m_tweak_blocks;
};

/**
* IEEE P1619 XTS Encryption
*/
class XTS_Encryption final : public XTS_Mode {
   public:
      /**
      * @param cipher underlying block cipher
      */
      explicit XTS_Encryption(std::unique_ptr<BlockCipher> cipher) : XTS_Mode(std::move(cipher)) {}

      size_t output_length(size_t input_length) const override;

   private:
      size_t process_msg(uint8_t buf[], size_t size) override;
      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
};

/**
* IEEE P1619 XTS Decryption
*/
class XTS_Decryption final : public XTS_Mode {
   public:
      /**
      * @param cipher underlying block cipher
      */
      explicit XTS_Decryption(std::unique_ptr<BlockCipher> cipher) : XTS_Mode(std::move(cipher)) {}

      size_t output_length(size_t input_length) const override;

   private:
      size_t process_msg(uint8_t buf[], size_t size) override;
      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
};

}  // namespace Botan

#endif
