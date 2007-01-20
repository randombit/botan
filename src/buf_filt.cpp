/*************************************************
* Buffering Filter Source File                   *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/buf_filt.h>
#include <algorithm>

namespace Botan {

/*************************************************
* Buffering_Filter Constructor                   *
*************************************************/
Buffering_Filter::Buffering_Filter(u32bit b, u32bit i) : INITIAL_BLOCK_SIZE(i),
                                                         BLOCK_SIZE(b)
   {
   initial_block_pos = block_pos = 0;
   initial.create(INITIAL_BLOCK_SIZE);
   block.create(BLOCK_SIZE);
   }

/*************************************************
* Reset the Buffering Filter                     *
*************************************************/
void Buffering_Filter::end_msg()
   {
   if(initial_block_pos != INITIAL_BLOCK_SIZE)
      throw Exception("Buffering_Filter: Not enough data for first block");
   final_block(block, block_pos);
   initial_block_pos = block_pos = 0;
   initial.clear();
   block.clear();
   }

/*************************************************
* Buffer input into blocks                       *
*************************************************/
void Buffering_Filter::write(const byte input[], u32bit length)
   {
   if(initial_block_pos != INITIAL_BLOCK_SIZE)
      {
      u32bit copied = std::min(INITIAL_BLOCK_SIZE - initial_block_pos, length);
      initial.copy(initial_block_pos, input, copied);
      input += copied;
      length -= copied;
      initial_block_pos += copied;
      if(initial_block_pos == INITIAL_BLOCK_SIZE)
         initial_block(initial);
      }
   block.copy(block_pos, input, length);
   if(block_pos + length >= BLOCK_SIZE)
      {
      main_block(block);
      input += (BLOCK_SIZE - block_pos);
      length -= (BLOCK_SIZE - block_pos);
      while(length >= BLOCK_SIZE)
         {
         main_block(input);
         input += BLOCK_SIZE;
         length -= BLOCK_SIZE;
         }
      block.copy(input, length);
      block_pos = 0;
      }
   block_pos += length;
   }

}
