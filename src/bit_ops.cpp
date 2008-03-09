/*************************************************
* Bit/Word Operations Source File                *
* (C) 1999-2008 The Botan Project                *
*************************************************/

#include <botan/bit_ops.h>
#include <botan/loadstor.h>

namespace Botan {

/*************************************************
* Return true iff arg is 2**n for some n > 0     *
*************************************************/
bool power_of_2(u64bit arg)
   {
   if(arg == 0 || arg == 1)
      return false;
   if((arg & (arg-1)) == 0)
      return true;
   return false;
   }

/*************************************************
* Return the index of the highest set bit        *
*************************************************/
u32bit high_bit(u64bit n)
   {
   for(u32bit count = 64; count > 0; --count)
      if((n >> (count - 1)) & 0x01)
         return count;
   return 0;
   }

/*************************************************
* Return the index of the lowest set bit         *
*************************************************/
u32bit low_bit(u64bit n)
   {
   for(u32bit count = 0; count != 64; ++count)
      if((n >> count) & 0x01)
         return (count + 1);
   return 0;
   }

/*************************************************
* Return the number of significant bytes in n    *
*************************************************/
u32bit significant_bytes(u64bit n)
   {
   for(u32bit j = 0; j != 8; ++j)
      if(get_byte(j, n))
         return 8-j;
   return 0;
   }

/*************************************************
* Return the Hamming weight of n                 *
*************************************************/
u32bit hamming_weight(u64bit n)
   {
   u32bit weight = 0;
   for(u32bit j = 0; j != 64; ++j)
      if((n >> j) & 0x01)
         ++weight;
   return weight;
   }

}
