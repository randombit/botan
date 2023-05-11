/*
* (C) 1999-2008,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MDX_HELPER_H_
#define BOTAN_MDX_HELPER_H_

#include <botan/internal/bit_ops.h>
#include <botan/internal/loadstor.h>

namespace Botan {

enum class MD_Endian {
   Little,
   Big,
};

template<MD_Endian ENDIAN,
         typename DIGEST_T,
         size_t DIGEST_ELEM,
         void init_fn(DIGEST_T[DIGEST_ELEM]),
         void compress_fn(DIGEST_T[DIGEST_ELEM], const uint8_t[], size_t),
         size_t BLOCK_BYTES = 64,
         size_t DIGEST_LENGTH = DIGEST_ELEM * sizeof(DIGEST_T),
         size_t CTR_BYTES = 8>
class MD_Hash final
   {
   public:
      static_assert(BLOCK_BYTES >= 64 && is_power_of_2(BLOCK_BYTES));
      static_assert(CTR_BYTES >= 8 && is_power_of_2(CTR_BYTES));
      static_assert(CTR_BYTES < BLOCK_BYTES);
      static_assert(DIGEST_LENGTH >= 16 && DIGEST_LENGTH <= DIGEST_ELEM * sizeof(DIGEST_T));

      static const size_t BLOCK_BITS = ceil_log2(BLOCK_BYTES);

      MD_Hash() :
         m_count(0),
         m_position(0)
         {
         clear_mem(m_buffer, BLOCK_BYTES);
         init_fn(m_digest);
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
               compress_fn(m_digest, m_buffer, 1);
               input += (BLOCK_BYTES - m_position);
               length -= (BLOCK_BYTES - m_position);
               m_position = 0;
               }
            }

         const size_t full_blocks = length / BLOCK_BYTES;
         const size_t remaining   = length % BLOCK_BYTES;

         if(full_blocks > 0)
            {
            compress_fn(m_digest, input, full_blocks);
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
            compress_fn(m_digest, m_buffer, 1);
            clear_mem(m_buffer, BLOCK_BYTES);
            }

         const uint64_t bit_count = m_count * 8;

         if constexpr(ENDIAN == MD_Endian::Big)
            store_be(bit_count, &m_buffer[BLOCK_BYTES - 8]);
         else
            store_le(bit_count, &m_buffer[BLOCK_BYTES - 8]);

         compress_fn(m_digest, m_buffer, 1);

         if constexpr(ENDIAN == MD_Endian::Big)
            copy_out_be(output, DIGEST_LENGTH, m_digest);
         else
            copy_out_le(output, DIGEST_LENGTH, m_digest);

         clear();
         }

      void clear()
         {
         init_fn(m_digest);
         clear_mem(m_buffer, BLOCK_BYTES);
         m_count = 0;
         m_position = 0;
         }

   private:
      uint8_t m_buffer[BLOCK_BYTES];
      DIGEST_T m_digest[DIGEST_ELEM];
      uint64_t m_count;
      size_t m_position;
   };

}

#endif
