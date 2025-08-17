/*
 * BLAKE2s
 * (C) 2023           Richard Huveneers
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_BLAKE2S_H_
#define BOTAN_BLAKE2S_H_

#include <botan/hash.h>

#include <array>

namespace Botan {

/**
 * BLAKE2s
 */
class BLAKE2s final : public HashFunction {
   public:
      explicit BLAKE2s(size_t output_bits = 256);
      ~BLAKE2s() override;

      BLAKE2s(const BLAKE2s&) = default;
      BLAKE2s& operator=(const BLAKE2s&) = delete;
      BLAKE2s(BLAKE2s&&) = delete;
      BLAKE2s& operator=(BLAKE2s&&) = delete;

      std::string name() const override;

      size_t output_length() const override { return m_outlen; }

      size_t hash_block_size() const override { return 64; }

      std::unique_ptr<HashFunction> copy_state() const override;

      std::unique_ptr<HashFunction> new_object() const override { return std::make_unique<BLAKE2s>(m_outlen << 3); }

      void clear() override;

   private:
      void add_data(std::span<const uint8_t> input) override;
      void final_result(std::span<uint8_t> output) override;
      void state_init(size_t outlen, const uint8_t* key, size_t keylen);
      void compress(bool last);

      std::array<uint8_t, 64> m_b{};  // input buffer
      std::array<uint32_t, 8> m_h{};  // chained state
      std::array<uint32_t, 2> m_t{};  // total number of bytes
      uint8_t m_c = 0;                // pointer for b[]
      size_t m_outlen = 0;            // digest size
};

}  // namespace Botan

#endif
