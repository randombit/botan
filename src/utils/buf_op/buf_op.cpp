/**
* Buffering Central
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/buf_op.h>
#include <botan/mem_ops.h>
#include <botan/internal/rounding.h>
#include <stdexcept>

#include <stdio.h>
#include <assert.h>

namespace Botan {

namespace {

const size_t BUFFER_MULTIPLE = 2;

//static_assert(BUFFER_MULTIPLE >= 2, "BUFFER_MULTIPLE must be >= 2");

}

Buffered_Operation::Buffered_Operation(callback_fn m_fn,
                                       callback_fn f_fn,
                                       size_t buf_mod,
                                       size_t final_minimum) :
   main_fn(m_fn), final_fn(f_fn),
   final_minimum(final_minimum), main_block_mod(buf_mod),
   buffer(BUFFER_MULTIPLE * buf_mod), buffer_pos(0)
   {
   if(buf_mod == 0)
      throw std::invalid_argument("buf_mod == 0");

   if(final_minimum > buf_mod)
      throw std::invalid_argument("final_minimum > buf_mod");
   }

void Buffered_Operation::reset()
   {
   clear_mem(&buffer[0], buffer.size());
   buffer_pos = 0;
   }

void Buffered_Operation::write(const byte input[],
                               size_t input_size)
   {
   if(!input_size)
      return;

   if(buffer_pos + input_size >= main_block_mod + final_minimum)
      {
      size_t to_copy = std::min(buffer.size() - buffer_pos, input_size);

      copy_mem(&buffer[buffer_pos], input, to_copy);
      buffer_pos += to_copy;

      input += to_copy;
      input_size -= to_copy;

      if(input_size >= final_minimum)
         {
         size_t to_proc = round_down(buffer_pos, main_block_mod);
         main_fn(&buffer[0], to_proc);

         buffer_pos -= to_proc;

         copy_mem(&buffer[0], &buffer[to_proc], buffer_pos);
         }
      }

   if(input_size >= final_minimum)
      {
      size_t full_blocks = (input_size - final_minimum) / buffer.size();
      size_t to_copy = full_blocks * buffer.size();

      if(to_copy)
         {
         main_fn(input, to_copy);

         input += to_copy;
         input_size -= to_copy;
         }
      }

   assert(input_size + buffer_pos <= buffer.size());

   copy_mem(&buffer[buffer_pos], input, input_size);
   buffer_pos += input_size;
   }

void Buffered_Operation::final()
   {
   assert(buffer_pos >= final_minimum);

   if(buffer_pos < final_minimum)
      throw std::runtime_error("Buffered_Operation::final - not enough input");

   size_t spare_blocks = (buffer_pos - final_minimum) / main_block_mod;

   if(spare_blocks)
      {
      size_t spare_bytes = main_block_mod * spare_blocks;

      assert(spare_bytes <= buffer_pos);

      main_fn(&buffer[0], spare_bytes);

      assert(buffer_pos - spare_bytes >= final_minimum);
      final_fn(&buffer[spare_bytes], buffer_pos - spare_bytes);
      }
   else
      {
      final_fn(&buffer[0], buffer_pos);
      }
   }

}
