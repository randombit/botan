/**
* Entropy Accumulator
* (C) 1999-2009 Jack Lloyd
*/

#include <botan/entropy_src.h>

namespace Botan {

void Entropy_Accumulator::reset_goal(u32bit entropy_goal)
   {
   goal_bits = entropy_goal;
   collected_bits = 0;

   /*
   * The buffer is large enough to hold 2*goal_bits of entropy,
   * or 128 bits, whichever is larger
   */
   entropy_buf.create(std::max<u32bit>(goal_bits / 4, 16));
   io_buffer.destroy();
   }

MemoryRegion<byte>& Entropy_Accumulator::get_io_buffer(u32bit size)
   {
   io_buffer.create(size);
   return io_buffer;
   }

u32bit Entropy_Accumulator::desired_remaining_bits() const
   {
   if(collected_bits >= goal_bits)
      return 0;
   return (goal_bits - collected_bits);
   }

bool Entropy_Accumulator::polling_goal_achieved() const
   {
   return (collected_bits >= goal_bits);
   }

void Entropy_Accumulator::add(const void* in_void,
                              u32bit length,
                              double entropy_bits_per_byte)
   {
   if(length == 0)
      return;

   entropy_bits_per_byte = std::max(0.0, std::min(entropy_bits_per_byte, 8.0));

   const byte* in = static_cast<const byte*>(in_void);

   u32bit buf_i = 0; // write index into entropy_buf
   u32bit bytes_collected = 0;

   byte last = 0;
   byte count = 0;

   for(u32bit i = 0; i != length; ++i)
      {
      if(in[i] != last) // run length encode the input
         {
         entropy_buf[buf_i] ^= last;
         buf_i = (buf_i + 1) % entropy_buf.size();

         if(count > 1)
            {
            entropy_buf[buf_i] ^= count;
            buf_i = (buf_i + 1) % entropy_buf.size();
            }

         ++bytes_collected;

         last = in[i];
         count = 1;
         }
      else
         ++count;
      }

   entropy_buf[0] ^= last;
   entropy_buf[1] ^= count;

   collected_bits += static_cast<u32bit>(entropy_bits_per_byte * bytes_collected);
   collected_bits = std::min(collected_bits, 8 * entropy_buf.size());
   }

}
