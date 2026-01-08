/*
* Poly1305
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MAC_POLY1305_H_
#define BOTAN_MAC_POLY1305_H_

#include <botan/mac.h>
#include <botan/internal/alignment_buffer.h>
#include <memory>

namespace Botan {

/**
* DJB's Poly1305
* Important note: each key can only be used once
*/
class Poly1305 final : public MessageAuthenticationCode {
   public:
      std::string name() const override { return "Poly1305"; }

      std::unique_ptr<MessageAuthenticationCode> new_object() const override { return std::make_unique<Poly1305>(); }

      void clear() override;

      size_t output_length() const override { return 16; }

      Key_Length_Specification key_spec() const override { return Key_Length_Specification(32); }

      bool fresh_key_required_per_message() const override { return true; }

      bool has_keying_material() const override;

   private:
      void add_data(std::span<const uint8_t> input) override;
      void final_result(std::span<uint8_t> output) override;
      void key_schedule(std::span<const uint8_t> key) override;

#if defined(BOTAN_HAS_POLY1305_AVX2)
      static size_t poly1305_avx2_blocks(secure_vector<uint64_t>& X, const uint8_t m[], size_t blocks);
#endif

#if defined(BOTAN_HAS_POLY1305_AVX512)
      static size_t poly1305_avx512_blocks(secure_vector<uint64_t>& X, const uint8_t m[], size_t blocks);
#endif

      // State layout: pad [2] || accum [3] || r [3] || r^2 [3] || ... || r^n [3]
      secure_vector<uint64_t> m_poly;
      AlignmentBuffer<uint8_t, 16> m_buffer;
};

}  // namespace Botan

#endif
