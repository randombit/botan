/*
* OCB Mode
* (C) 2013,2014 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_AEAD_OCB_H_
#define BOTAN_AEAD_OCB_H_

#include <botan/aead.h>

#include <botan/assert.h>
#include <botan/block_cipher.h>

namespace Botan {

class L_computer;

/**
* OCB Mode (base class for OCB_Encryption and OCB_Decryption).
* OCB was previously patented in the United States but the patent
* has now been allowed to lapse.
*
* @see "The OCB Authenticated-Encryption Algorithm" RFC 7253
*      https://tools.ietf.org/html/rfc7253
* @see "OCB For Block Ciphers Without 128-Bit Blocks"
*      (draft-krovetz-ocb-wide-d3) for the extension of OCB to
*      block ciphers with larger block sizes.
* @see https://mailarchive.ietf.org/arch/msg/cfrg/qLTveWOdTJcLn4HP3ev-vrj05Vg/
*/
class BOTAN_TEST_API OCB_Mode : public AEAD_Mode /* NOLINT(*-special-member-functions) */ {
   public:
      void set_associated_data_n(size_t idx, std::span<const uint8_t> ad) final;

      std::string name() const final;

      size_t update_granularity() const final;

      size_t ideal_granularity() const final;

      Key_Length_Specification key_spec() const final;

      bool valid_nonce_length(size_t) const final;

      size_t tag_size() const final { return m_tag_size; }

      void clear() final;

      void reset() final;

      bool has_keying_material() const final;

      ~OCB_Mode() override;

   protected:
      /**
      * @param cipher the block cipher to use
      * @param tag_size is how big the auth tag will be
      */
      OCB_Mode(std::unique_ptr<BlockCipher> cipher, size_t tag_size);

      size_t block_size() const { return m_block_size; }

      size_t par_blocks() const { return m_par_blocks; }

      size_t par_bytes() const { return m_checksum.size(); }

      // fixme make these private
      std::unique_ptr<BlockCipher> m_cipher;  // NOLINT(*non-private-member-variables*)
      std::unique_ptr<L_computer> m_L;        // NOLINT(*non-private-member-variables*)

      size_t m_block_index = 0;  // NOLINT(*non-private-member-variables*)

      secure_vector<uint8_t> m_checksum;  // NOLINT(*non-private-member-variables*)
      secure_vector<uint8_t> m_ad_hash;   // NOLINT(*non-private-member-variables*)

   private:
      void start_msg(const uint8_t nonce[], size_t nonce_len) final;

      void key_schedule(std::span<const uint8_t> key) final;

      const secure_vector<uint8_t>& update_nonce(const uint8_t nonce[], size_t nonce_len);

      const size_t m_tag_size;
      const size_t m_block_size;
      const size_t m_par_blocks;
      secure_vector<uint8_t> m_last_nonce;
      secure_vector<uint8_t> m_stretch;
      secure_vector<uint8_t> m_nonce_buf;
      secure_vector<uint8_t> m_offset;
};

class BOTAN_TEST_API OCB_Encryption final : public OCB_Mode {
   public:
      /**
      * @param cipher the block cipher to use
      * @param tag_size is how big the auth tag will be
      */
      explicit OCB_Encryption(std::unique_ptr<BlockCipher> cipher, size_t tag_size = 16) :
            OCB_Mode(std::move(cipher), tag_size) {}

      size_t output_length(size_t input_length) const override { return input_length + tag_size(); }

      size_t bytes_needed_for_finalization(size_t final_input_length) const override {
         return output_length(final_input_length);
      }

      size_t minimum_final_size() const override { return 0; }

   private:
      void encrypt(uint8_t input[], size_t blocks);
      size_t process_msg(uint8_t buf[], size_t size) override;
      size_t finish_msg(std::span<uint8_t> final_block, size_t input_bytes) override;
};

class BOTAN_TEST_API OCB_Decryption final : public OCB_Mode {
   public:
      /**
      * @param cipher the block cipher to use
      * @param tag_size is how big the auth tag will be
      */
      explicit OCB_Decryption(std::unique_ptr<BlockCipher> cipher, size_t tag_size = 16) :
            OCB_Mode(std::move(cipher), tag_size) {}

      size_t output_length(size_t input_length) const override {
         BOTAN_ASSERT(input_length >= tag_size(), "Sufficient input");
         return input_length - tag_size();
      }

      size_t bytes_needed_for_finalization(size_t final_input_length) const override {
         BOTAN_ARG_CHECK(final_input_length >= tag_size(), "Sufficient input");
         return final_input_length;
      }

      size_t minimum_final_size() const override { return tag_size(); }

   private:
      void decrypt(uint8_t input[], size_t blocks);
      size_t process_msg(uint8_t buf[], size_t size) override;
      size_t finish_msg(std::span<uint8_t> final_block, size_t input_bytes) override;
};

}  // namespace Botan

#endif
