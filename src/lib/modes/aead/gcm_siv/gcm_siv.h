/*
* GCM-SIV Mode
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_AEAD_GCM_SIV_H_
#define BOTAN_AEAD_GCM_SIV_H_

#include <botan/aead.h>

#include <botan/block_cipher.h>
#include <botan/internal/polyval.h>

namespace Botan {

/**
* GCM-SIV Mode (RFC 8452)
*/
class GCM_SIV_Mode : public AEAD_Mode /* NOLINT(*-special-member-functions) */ {
   public:
      void set_associated_data_n(size_t idx, std::span<const uint8_t> ad) final;

      std::string name() const final;

      size_t update_granularity() const final;

      size_t ideal_granularity() const final;

      Key_Length_Specification key_spec() const final;

      bool valid_nonce_length(size_t len) const final;

      size_t tag_size() const final { return 16; }

      bool requires_entire_message() const final { return true; }

      /// The AD is buffered as-is; it is not processed until finish
      bool associated_data_requires_key() const final { return false; }

      void clear() final;

      void reset() final;

      std::string provider() const final;

      bool has_keying_material() const final;

      ~GCM_SIV_Mode() override;

   protected:
      explicit GCM_SIV_Mode(std::unique_ptr<BlockCipher> cipher);

      static constexpr size_t BS = 16;

      /// RFC 8452 limits both the plaintext and the AD to 2**36 bytes
      static constexpr uint64_t MAX_INPUT_LEN = static_cast<uint64_t>(1) << 36;

      secure_vector<uint8_t>& msg_buf() { return m_msg_buf; }

      bool in_msg() const { return m_in_msg; }

      /// Compute the expected tag for the (unpadded) plaintext
      std::array<uint8_t, BS> compute_tag(std::span<const uint8_t> ptext);

      /// XOR the buffer with the CTR keystream, starting from the tag-derived counter
      void ctr_xor(std::span<const uint8_t, BS> tag, uint8_t buf[], size_t len);

   private:
      void start_msg(const uint8_t nonce[], size_t nonce_len) final;
      size_t process_msg(uint8_t buf[], size_t size) final;

      void key_schedule(std::span<const uint8_t> key) final;

      const std::string m_cipher_name;
      const Key_Length_Specification m_key_spec;

      std::unique_ptr<BlockCipher> m_cipher;      // keyed with the key-generating key
      std::unique_ptr<BlockCipher> m_msg_cipher;  // keyed with the per-message encryption key
      Polyval m_polyval;

      size_t m_kgk_len = 0;
      std::array<uint8_t, 12> m_nonce{};
      secure_vector<uint8_t> m_ad;
      secure_vector<uint8_t> m_msg_buf;
      bool m_in_msg = false;
};

/**
* GCM-SIV Encryption
*/
class GCM_SIV_Encryption final : public GCM_SIV_Mode {
   public:
      /**
      * @param cipher the 128 bit block cipher to use
      */
      explicit GCM_SIV_Encryption(std::unique_ptr<BlockCipher> cipher) : GCM_SIV_Mode(std::move(cipher)) {}

      size_t output_length(size_t input_length) const override;

      size_t minimum_final_size() const override { return 0; }

   private:
      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
};

/**
* GCM-SIV Decryption
*/
class GCM_SIV_Decryption final : public GCM_SIV_Mode {
   public:
      /**
      * @param cipher the 128 bit block cipher to use
      */
      explicit GCM_SIV_Decryption(std::unique_ptr<BlockCipher> cipher) : GCM_SIV_Mode(std::move(cipher)) {}

      size_t output_length(size_t input_length) const override;

      size_t minimum_final_size() const override { return tag_size(); }

   private:
      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
};

}  // namespace Botan

#endif
