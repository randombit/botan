/*
* Ascon-AEAD128 AEAD
* (C) 2025 Jack Lloyd
*     2025 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASCON_AEAD128_H_
#define BOTAN_ASCON_AEAD128_H_

#include <botan/aead.h>

#include <botan/assert.h>
#include <botan/internal/ascon_perm.h>

#include <optional>

namespace Botan {

class Ascon_AEAD128_Mode : public AEAD_Mode {
   public:
      void set_associated_data_n(size_t idx, std::span<const uint8_t> ad) final;

      bool associated_data_requires_key() const final { return true; }

      std::string name() const final { return "Ascon_AEAD128"; }

      size_t update_granularity() const final { return 1; }

      size_t ideal_granularity() const final { return 2; }

      Key_Length_Specification key_spec() const final { return Key_Length_Specification(16); }

      bool valid_nonce_length(size_t n) const final { return n == 16; }

      size_t default_nonce_length() const final { return 16; }

      size_t tag_size() const final { return 16; }

      void clear() final;

      void reset() final;

      bool has_keying_material() const final { return m_key.has_value(); }

   private:
      void start_msg(const uint8_t nonce[], size_t nonce_len) final;

      void key_schedule(std::span<const uint8_t> key) final;

      size_t process_msg(uint8_t buf[], size_t size) final;

   protected:
      Ascon_AEAD128_Mode();

      bool has_nonce_and_ad() const { return m_ascon_state_with_ad.has_value(); }

   protected:
      std::optional<std::array<uint64_t, 2>> m_key;  // NOLINT(*-non-private-member-*)
      Ascon_p m_ascon_p;                             // NOLINT(*-non-private-member-*)

   private:
      std::vector<uint8_t> m_ad;
      std::optional<Ascon_p> m_ascon_state_with_ad;  // state after processing associated data
};

/**
* Ascon-AEAD128 Encryption
*/
class Ascon_AEAD128_Encryption final : public Ascon_AEAD128_Mode {
   public:
      size_t output_length(size_t input_length) const override { return input_length + tag_size(); }

      size_t minimum_final_size() const override { return 0; }

   private:
      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
};

/**
* Ascon-AEAD128 Decryption
*/
class Ascon_AEAD128_Decryption final : public Ascon_AEAD128_Mode {
   public:
      size_t output_length(size_t input_length) const override {
         BOTAN_ARG_CHECK(input_length >= tag_size(), "Sufficient input");
         return input_length - tag_size();
      }

      size_t minimum_final_size() const override { return tag_size(); }

   private:
      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
};

}  // namespace Botan

#endif
