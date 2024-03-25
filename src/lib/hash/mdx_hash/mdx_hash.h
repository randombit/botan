/*
* MDx Hash Function
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MDX_BASE_H_
#define BOTAN_MDX_BASE_H_

#include <botan/hash.h>

#include <botan/internal/alignment_buffer.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

namespace Botan {

enum class MD_Endian {
   Little,
   Big,
};

template <typename T>
concept md_hash_implementation =
   concepts::contiguous_container<typename T::digest_type> &&
   requires(typename T::digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
      { T::init(digest) } -> std::same_as<void>;
      { T::compress_n(digest, input, blocks) } -> std::same_as<void>;
      T::bit_endianness;
      T::byte_endianness;
      T::block_bytes;
      T::output_bytes;
      T::ctr_bytes;
   } && T::block_bytes >= 64 && is_power_of_2(T::block_bytes) && T::output_bytes >= 16 && T::ctr_bytes >= 8 &&
   is_power_of_2(T::ctr_bytes) && T::ctr_bytes < T::block_bytes;

template <md_hash_implementation MD>
class MerkleDamgard_Hash final {
   public:
      MerkleDamgard_Hash() { clear(); }

      void update(std::span<const uint8_t> input) {
         BufferSlicer in(input);

         while(!in.empty()) {
            if(const auto one_block = m_buffer.handle_unaligned_data(in)) {
               MD::compress_n(m_digest, one_block.value(), 1);
            }

            if(m_buffer.in_alignment()) {
               const auto [aligned_data, full_blocks] = m_buffer.aligned_data_to_process(in);
               if(full_blocks > 0) {
                  MD::compress_n(m_digest, aligned_data, full_blocks);
               }
            }
         }

         m_count += input.size();
      }

      void final(std::span<uint8_t> output) {
         append_padding_bit();
         append_counter_and_finalize();
         copy_output(output);
         clear();
      }

      void clear() {
         MD::init(m_digest);
         m_buffer.clear();
         m_count = 0;
      }

   private:
      void append_padding_bit() {
         BOTAN_ASSERT_NOMSG(!m_buffer.ready_to_consume());
         if constexpr(MD::bit_endianness == MD_Endian::Big) {
            const uint8_t final_byte = 0x80;
            m_buffer.append({&final_byte, 1});
         } else {
            const uint8_t final_byte = 0x01;
            m_buffer.append({&final_byte, 1});
         }
      }

      void append_counter_and_finalize() {
         // Compress the remaining data if the final data block does not provide
         // enough space for the counter bytes.
         if(m_buffer.elements_until_alignment() < MD::ctr_bytes) {
            m_buffer.fill_up_with_zeros();
            MD::compress_n(m_digest, m_buffer.consume(), 1);
         }

         // Make sure that any remaining bytes in the very last block are zero.
         BOTAN_ASSERT_NOMSG(m_buffer.elements_until_alignment() >= MD::ctr_bytes);
         m_buffer.fill_up_with_zeros();

         // Replace a bunch of the right-most zero-padding with the counter bytes.
         const uint64_t bit_count = m_count * 8;
         auto last_bytes = m_buffer.directly_modify_last(sizeof(bit_count));
         if constexpr(MD::byte_endianness == MD_Endian::Big) {
            store_be(bit_count, last_bytes.data());
         } else {
            store_le(bit_count, last_bytes.data());
         }

         // Compress the very last block.
         MD::compress_n(m_digest, m_buffer.consume(), 1);
      }

      void copy_output(std::span<uint8_t> output) {
         BOTAN_ASSERT_NOMSG(output.size() >= MD::output_bytes);

         if constexpr(MD::byte_endianness == MD_Endian::Big) {
            copy_out_be(output.first(MD::output_bytes), m_digest);
         } else {
            copy_out_le(output.first(MD::output_bytes), m_digest);
         }
      }

   private:
      typename MD::digest_type m_digest;
      uint64_t m_count;

      AlignmentBuffer<uint8_t, MD::block_bytes> m_buffer;
};

}  // namespace Botan

#endif
