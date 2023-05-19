/*
* (C) 1999-2008,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MDX_HELPER_H_
#define BOTAN_MDX_HELPER_H_

#include <botan/hash.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/loadstor.h>
#include <cstdint>
#include <memory>

namespace Botan {

enum class MD_Endian {
   Little,
   Big,
};

template <typename T>
concept mdx_hash_implementation =
    requires(typename T::digest_type digest, uint8_t input[], size_t blocks, MD_Endian endian) {
        typename T::digest_type;
        T::NAME;
        T::ENDIAN;
        T::BLOCK_BYTES;
        T::FINAL_DIGEST_BYTES;
        T::CTR_BYTES;
        T::init(digest);
        T::compress_n(digest, input, blocks);
    } &&
    T::BLOCK_BYTES >= 64 && is_power_of_2(T::BLOCK_BYTES) &&
    T::CTR_BYTES >= 8 && is_power_of_2(T::CTR_BYTES) &&
    T::CTR_BYTES < T::BLOCK_BYTES &&
    T::FINAL_DIGEST_BYTES >= 16 && T::FINAL_DIGEST_BYTES <= sizeof(typename T::digest_type);

template<mdx_hash_implementation HashImplT>
class MD_Hash final
   {
   private:
      // TODO: remove those aliases. I introduced them to keep the diff lean.
      using digest_type = typename HashImplT::digest_type;
      static constexpr MD_Endian ENDIAN = HashImplT::ENDIAN;
      static constexpr size_t BLOCK_BYTES = HashImplT::BLOCK_BYTES;
      static constexpr size_t CTR_BYTES = HashImplT::CTR_BYTES;
      static constexpr size_t FINAL_DIGEST_BYTES = HashImplT::FINAL_DIGEST_BYTES;

   public:
      static const size_t BLOCK_BITS = ceil_log2(HashImplT::BLOCK_BYTES);

      MD_Hash() :
         m_count(0),
         m_position(0)
         {
         clear_mem(m_buffer, BLOCK_BYTES);
         HashImplT::init(m_digest);
         }

      void add_data(const uint8_t input[], size_t length)
         {
         m_count += length;

         if(m_position > 0)
            {
            const size_t take = std::min(length, BLOCK_BYTES - m_position);

            copy_mem(&m_buffer[m_position], input, take);

            if(m_position + take == BLOCK_BYTES)
               {
               HashImplT::compress_n(m_digest, m_buffer, 1);
               input += (BLOCK_BYTES - m_position);
               length -= (BLOCK_BYTES - m_position);
               m_position = 0;
               }
            }

         const size_t full_blocks = length / BLOCK_BYTES;
         const size_t remaining   = length % BLOCK_BYTES;

         if(full_blocks > 0)
            {
            HashImplT::compress_n(m_digest, input, full_blocks);
            }

         copy_mem(&m_buffer[m_position], input + full_blocks * BLOCK_BYTES, remaining);
         m_position += remaining;
         }

      void final_result(uint8_t output[])
         {
         BOTAN_ASSERT_NOMSG(m_position < BLOCK_BYTES);
         clear_mem(&m_buffer[m_position], BLOCK_BYTES - m_position);
         m_buffer[m_position] = 0x80;

         if(m_position >= BLOCK_BYTES - CTR_BYTES)
            {
            HashImplT::compress_n(m_digest, m_buffer, 1);
            clear_mem(m_buffer, BLOCK_BYTES);
            }

         const uint64_t bit_count = m_count * 8;

         if constexpr(ENDIAN == MD_Endian::Big)
            store_be(bit_count, &m_buffer[BLOCK_BYTES - 8]);
         else
            store_le(bit_count, &m_buffer[BLOCK_BYTES - 8]);

         HashImplT::compress_n(m_digest, m_buffer, 1);

         if constexpr(ENDIAN == MD_Endian::Big)
            copy_out_be(output, FINAL_DIGEST_BYTES, m_digest.data());
         else
            copy_out_le(output, FINAL_DIGEST_BYTES, m_digest.data());

         clear();
         }

      void clear()
         {
         HashImplT::init(m_digest);
         clear_mem(m_buffer, BLOCK_BYTES);
         m_count = 0;
         m_position = 0;
         }

   private:
      uint8_t m_buffer[BLOCK_BYTES];
      digest_type m_digest;
      uint64_t m_count;
      size_t m_position;
   };


template<typename DerivedT, mdx_hash_implementation HashImplT>
class MD_Hash_Adapter : public HashFunction
   {
   public:
      std::string name() const override { return HashImplT::NAME; }
      size_t output_length() const override { return HashImplT::FINAL_DIGEST_BYTES; }
      size_t hash_block_size() const override { return HashImplT::BLOCK_BYTES; }

      std::unique_ptr<HashFunction> new_object() const override { return std::make_unique<DerivedT>(); }
      std::unique_ptr<HashFunction> copy_state() const override { return std::make_unique<DerivedT>(*dynamic_cast<const DerivedT*>(this)); }

      void clear() override { m_md.clear(); }

   private:
      void add_data(const uint8_t input[], size_t length) override { m_md.add_data(input, length); }
      void final_result(uint8_t output[]) override { m_md.final_result(output); }

   private:
      MD_Hash<HashImplT> m_md;
   };

}

#endif
