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

#include <assert.h>

namespace Botan {

namespace {

const size_t BUFFER_MULTIPLE = 2;

//static_assert(BUFFER_MULTIPLE >= 2, "BUFFER_MULTIPLE must be >= 2");

}

/*
* Buffered_Filter Constructor
*/
Buffered_Filter::Buffered_Filter(u32bit b, u32bit f) :
   main_block_mod(b), final_minimum(f)
   {
   if(main_block_mod == 0)
      throw std::invalid_argument("main_block_mod == 0");

   if(final_minimum > main_block_mod)
      throw std::invalid_argument("final_minimum > main_block_mod");

   buffer.resize(BUFFER_MULTIPLE * main_block_mod);
   buffer_pos = 0;
   }

/*
* Buffer input into blocks, trying to minimize copying
*/
void Buffered_Filter::write(const byte input[], u32bit input_size)
   {
   if(!input_size)
      return;

   if(buffer_pos + input_size >= main_block_mod + final_minimum)
      {
      u32bit to_copy = std::min<u32bit>(buffer.size() - buffer_pos, input_size);

      copy_mem(&buffer[buffer_pos], input, to_copy);
      buffer_pos += to_copy;

      input += to_copy;
      input_size -= to_copy;

      if(input_size >= final_minimum)
         {
         u32bit to_proc_blocks = buffer_pos / main_block_mod;
         u32bit to_proc_bytes = to_proc_blocks * main_block_mod;

         buffered_block(&buffer[0], to_proc_bytes);

         buffer_pos -= to_proc_bytes;

         copy_mem(&buffer[0], &buffer[to_proc_bytes], buffer_pos);
         }
      }

   if(input_size >= final_minimum)
      {
      u32bit full_blocks = (input_size - final_minimum) / buffer.size();
      u32bit to_copy = full_blocks * buffer.size();

      if(to_copy)
         {
         buffered_block(input, to_copy);

         input += to_copy;
         input_size -= to_copy;
         }
      }

   assert(input_size + buffer_pos <= buffer.size());

   copy_mem(&buffer[buffer_pos], input, input_size);
   buffer_pos += input_size;
   }

/*
* Finish/flush operation
*/
void Buffered_Filter::end_msg()
   {
   assert(buffer_pos >= final_minimum);

   if(buffer_pos < final_minimum)
      throw std::runtime_error("Buffered_Operation::final - not enough input");

   u32bit spare_blocks = (buffer_pos - final_minimum) / main_block_mod;

   if(spare_blocks)
      {
      u32bit spare_bytes = main_block_mod * spare_blocks;

      assert(spare_bytes <= buffer_pos);

      buffered_block(&buffer[0], spare_bytes);

      assert(buffer_pos - spare_bytes >= final_minimum);
      buffered_final(&buffer[spare_bytes], buffer_pos - spare_bytes);
      }
   else
      {
      buffered_final(&buffer[0], buffer_pos);
      }
   }

}
