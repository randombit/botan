/*
* Buffered Filter
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/buf_filt.h>
#include <botan/mem_ops.h>
#include <botan/internal/rounding.h>
#include <stdexcept>

namespace Botan {

/*
* Buffered_Filter Constructor
*/
Buffered_Filter::Buffered_Filter(size_t b, size_t f) :
   main_block_mod(b), final_minimum(f)
   {
   if(main_block_mod == 0)
      throw std::invalid_argument("main_block_mod == 0");

   if(final_minimum > main_block_mod)
      throw std::invalid_argument("final_minimum > main_block_mod");

   buffer.resize(2 * main_block_mod);
   buffer_pos = 0;
   }

/*
* Buffer input into blocks, trying to minimize copying
*/
void Buffered_Filter::write(const byte input[], size_t input_size)
   {
   if(!input_size)
      return;

   if(buffer_pos + input_size >= main_block_mod + final_minimum)
      {
      size_t to_copy = std::min<size_t>(buffer.size() - buffer_pos, input_size);

      copy_mem(&buffer[buffer_pos], input, to_copy);
      buffer_pos += to_copy;

      input += to_copy;
      input_size -= to_copy;

      size_t total_to_consume =
         round_down(std::min(buffer_pos,
                             buffer_pos + input_size - final_minimum),
                    main_block_mod);

      buffered_block(&buffer[0], total_to_consume);

      buffer_pos -= total_to_consume;

      copy_mem(&buffer[0], &buffer[total_to_consume], buffer_pos);
      }

   if(input_size >= final_minimum)
      {
      size_t full_blocks = (input_size - final_minimum) / main_block_mod;
      size_t to_copy = full_blocks * main_block_mod;

      if(to_copy)
         {
         buffered_block(input, to_copy);

         input += to_copy;
         input_size -= to_copy;
         }
      }

   copy_mem(&buffer[buffer_pos], input, input_size);
   buffer_pos += input_size;
   }

/*
* Finish/flush operation
*/
void Buffered_Filter::end_msg()
   {
   if(buffer_pos < final_minimum)
      throw std::runtime_error("Buffered filter end_msg without enough input");

   size_t spare_blocks = (buffer_pos - final_minimum) / main_block_mod;

   if(spare_blocks)
      {
      size_t spare_bytes = main_block_mod * spare_blocks;
      buffered_block(&buffer[0], spare_bytes);
      buffered_final(&buffer[spare_bytes], buffer_pos - spare_bytes);
      }
   else
      {
      buffered_final(&buffer[0], buffer_pos);
      }

   buffer_pos = 0;
   }

}
