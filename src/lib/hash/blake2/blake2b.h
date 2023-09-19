/*
* BLAKE2b
* (C) 2016 cynecx
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BLAKE2B_H_
#define BOTAN_BLAKE2B_H_

#include <botan/hash.h>
#include <botan/sym_algo.h>
#include <botan/internal/alignment_buffer.h>
#include <memory>
#include <string>

namespace Botan {

class BLAKE2bMAC;

constexpr size_t BLAKE2B_BLOCKBYTES = 128;

/**
* BLAKE2B
*/
class BLAKE2b final : public HashFunction,
                      public SymmetricAlgorithm {
   public:
      /**
      * @param output_bits the output size of BLAKE2b in bits
      */
      explicit BLAKE2b(size_t output_bits = 512);

      size_t hash_block_size() const override { return 128; }

      size_t output_length() const override { return m_output_bits / 8; }

      size_t key_size() const { return m_key_size; }

      Key_Length_Specification key_spec() const override;

      std::unique_ptr<HashFunction> new_object() const override;
      std::string name() const override;
      void clear() override;
      bool has_keying_material() const override;

      std::unique_ptr<HashFunction> copy_state() const override;

   protected:
      friend class BLAKE2bMAC;

      void key_schedule(std::span<const uint8_t> key) override;

      void add_data(std::span<const uint8_t> input) override;
      void final_result(std::span<uint8_t> out) override;

   private:
      void state_init();
      void compress(const uint8_t* data, size_t blocks, uint64_t increment);

      const size_t m_output_bits;

      AlignmentBuffer<uint8_t, BLAKE2B_BLOCKBYTES, AlignmentBufferFinalBlock::must_be_deferred> m_buffer;

      secure_vector<uint64_t> m_H;
      uint64_t m_T[2];
      uint64_t m_F;

      size_t m_key_size;
      secure_vector<uint8_t> m_padded_key_buffer;
};

}  // namespace Botan

#endif
