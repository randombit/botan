/*
* The Skein-512 hash function
* (C) 2009,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SKEIN_512_H_
#define BOTAN_SKEIN_512_H_

#include <botan/hash.h>
#include <botan/internal/alignment_buffer.h>
#include <botan/internal/threefish_512.h>

#include <memory>
#include <string>

namespace Botan {

/**
* Skein-512, a SHA-3 candidate
*/
class Skein_512 final : public HashFunction {
   public:
      /**
      * @param output_bits the output size of Skein in bits
      * @param personalization is a string that will parameterize the
      * hash output
      */
      Skein_512(size_t output_bits = 512, std::string_view personalization = "");

      size_t hash_block_size() const override { return 64; }

      size_t output_length() const override { return m_output_bits / 8; }

      std::unique_ptr<HashFunction> new_object() const override;
      std::unique_ptr<HashFunction> copy_state() const override;
      std::string name() const override;
      void clear() override;

   private:
      enum type_code {
         SKEIN_KEY = 0,
         SKEIN_CONFIG = 4,
         SKEIN_PERSONALIZATION = 8,
         SKEIN_PUBLIC_KEY = 12,
         SKEIN_KEY_IDENTIFIER = 16,
         SKEIN_NONCE = 20,
         SKEIN_MSG = 48,
         SKEIN_OUTPUT = 63
      };

      void add_data(std::span<const uint8_t> input) override;
      void final_result(std::span<uint8_t> out) override;

      void ubi_512(const uint8_t msg[], size_t msg_len);

      void initial_block();
      void reset_tweak(type_code type, bool is_final);

      std::string m_personalization;
      size_t m_output_bits;

      std::unique_ptr<Threefish_512> m_threefish;
      secure_vector<uint64_t> m_T;
      AlignmentBuffer<uint8_t, 64, AlignmentBufferFinalBlock::must_be_deferred> m_buffer;
};

}  // namespace Botan

#endif
