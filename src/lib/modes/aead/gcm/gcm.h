/*
* GCM Mode
* (C) 2013 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_AEAD_GCM_H_
#define BOTAN_AEAD_GCM_H_

#include <botan/aead.h>
#include <botan/block_cipher.h>
#include <botan/sym_algo.h>

namespace Botan {

class StreamCipher;
class GHASH;

/**
* GCM Mode
*/
class GCM_Mode : public AEAD_Mode {
   public:
      void set_associated_data_n(size_t idx, std::span<const uint8_t> ad) override final;

      std::string name() const override final;

      size_t update_granularity() const override final;

      size_t ideal_granularity() const override final;

      Key_Length_Specification key_spec() const override final;

      bool valid_nonce_length(size_t len) const override final;

      size_t tag_size() const override final { return m_tag_size; }

      void clear() override final;

      void reset() override final;

      std::string provider() const override final;

      bool has_keying_material() const override final;

      ~GCM_Mode();

   protected:
      GCM_Mode(std::unique_ptr<BlockCipher> cipher, size_t tag_size);

      static const size_t GCM_BS = 16;

      const size_t m_tag_size;
      const std::string m_cipher_name;

      std::unique_ptr<StreamCipher> m_ctr;
      std::unique_ptr<GHASH> m_ghash;

   private:
      void start_msg(const uint8_t nonce[], size_t nonce_len) override;

      void key_schedule(std::span<const uint8_t> key) override;

      secure_vector<uint8_t> m_y0;
};

/**
* GCM Encryption
*/
class GCM_Encryption final : public GCM_Mode {
   public:
      /**
      * @param cipher the 128 bit block cipher to use
      * @param tag_size is how big the auth tag will be
      */
      GCM_Encryption(std::unique_ptr<BlockCipher> cipher, size_t tag_size = 16) :
            GCM_Mode(std::move(cipher), tag_size) {}

      size_t output_length(size_t input_length) const override { return input_length + tag_size(); }

      size_t minimum_final_size() const override { return 0; }

   private:
      size_t process_msg(uint8_t buf[], size_t size) override;
      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
};

/**
* GCM Decryption
*/
class GCM_Decryption final : public GCM_Mode {
   public:
      /**
      * @param cipher the 128 bit block cipher to use
      * @param tag_size is how big the auth tag will be
      */
      GCM_Decryption(std::unique_ptr<BlockCipher> cipher, size_t tag_size = 16) :
            GCM_Mode(std::move(cipher), tag_size) {}

      size_t output_length(size_t input_length) const override {
         BOTAN_ARG_CHECK(input_length >= tag_size(), "Sufficient input");
         return input_length - tag_size();
      }

      size_t minimum_final_size() const override { return tag_size(); }

   private:
      size_t process_msg(uint8_t buf[], size_t size) override;
      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
};

}  // namespace Botan

#endif
