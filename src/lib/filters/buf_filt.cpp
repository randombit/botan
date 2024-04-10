/*
* Buffered Filter
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/filters.h>

#include <botan/exceptn.h>
#include <botan/mem_ops.h>

namespace Botan {

/*
* Buffered_Filter Constructor
*/
Buffered_Filter::Buffered_Filter(size_t b, size_t f) : m_main_block_mod(b), m_final_minimum(f) {
   if(m_main_block_mod == 0) {
      throw Invalid_Argument("m_main_block_mod == 0");
   }

   if(m_final_minimum > m_main_block_mod) {
      throw Invalid_Argument("m_final_minimum > m_main_block_mod");
   }

   m_buffer.resize(2 * m_main_block_mod);
   m_buffer_pos = 0;
}

/*
* Buffer input into blocks, trying to minimize copying
*/
void Buffered_Filter::write(const uint8_t input[], size_t input_size) {
   if(!input_size) {
      return;
   }

   if(m_buffer_pos + input_size >= m_main_block_mod + m_final_minimum) {
      size_t to_copy = std::min<size_t>(m_buffer.size() - m_buffer_pos, input_size);

      copy_mem(&m_buffer[m_buffer_pos], input, to_copy);
      m_buffer_pos += to_copy;

      input += to_copy;
      input_size -= to_copy;

      const size_t available = std::min(m_buffer_pos, m_buffer_pos + input_size - m_final_minimum);

      // Size down to available block size
      const size_t total_to_consume = available - (available % m_main_block_mod);

      buffered_block(m_buffer.data(), total_to_consume);

      m_buffer_pos -= total_to_consume;

      copy_mem(m_buffer.data(), m_buffer.data() + total_to_consume, m_buffer_pos);
   }

   if(input_size >= m_final_minimum) {
      size_t full_blocks = (input_size - m_final_minimum) / m_main_block_mod;
      size_t to_copy = full_blocks * m_main_block_mod;

      if(to_copy) {
         buffered_block(input, to_copy);

         input += to_copy;
         input_size -= to_copy;
      }
   }

   copy_mem(&m_buffer[m_buffer_pos], input, input_size);
   m_buffer_pos += input_size;
}

/*
* Finish/flush operation
*/
void Buffered_Filter::end_msg() {
   if(m_buffer_pos < m_final_minimum) {
      throw Invalid_State("Buffered filter end_msg without enough input");
   }

   size_t spare_blocks = (m_buffer_pos - m_final_minimum) / m_main_block_mod;

   if(spare_blocks) {
      size_t spare_bytes = m_main_block_mod * spare_blocks;
      buffered_block(m_buffer.data(), spare_bytes);
      buffered_final(&m_buffer[spare_bytes], m_buffer_pos - spare_bytes);
   } else {
      buffered_final(m_buffer.data(), m_buffer_pos);
   }

   m_buffer_pos = 0;
}

}  // namespace Botan
