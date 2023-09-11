/**
 * Wrapper for truncated hashes
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_TRUNCATED_HASH_H_
#define BOTAN_TRUNCATED_HASH_H_

#include <botan/hash.h>

namespace Botan {

/**
 * Wrapper class to truncate underlying hash function output to a given number
 * of bits. The leading bits are retained. Since the HashFunction interface is
 * defined to return bytes, if the desired truncation length is not a multiple
 * of 8, then the final byte of the output will have some number of trailing
 * bits always set to zero.
 */
class Truncated_Hash final : public HashFunction {
   public:
      void clear() override;
      std::string name() const override;
      std::unique_ptr<HashFunction> new_object() const override;
      std::unique_ptr<HashFunction> copy_state() const override;

      size_t output_length() const override;

      /**
      * @param hash   the underlying hash function whose output shall be truncated
      * @param length the number of bits the hash shall be truncated to
      */
      Truncated_Hash(std::unique_ptr<HashFunction> hash, size_t length);

   private:
      void add_data(std::span<const uint8_t>) override;
      void final_result(std::span<uint8_t>) override;

      std::unique_ptr<HashFunction> m_hash;
      size_t m_output_bits;

      secure_vector<uint8_t> m_buffer;
};

}  // namespace Botan

#endif
