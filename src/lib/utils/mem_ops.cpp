/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/mem_ops.h>
#include <cstdlib>

#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
  #include <botan/locking_allocator.h>
#endif

namespace Botan {

void* allocate_memory(size_t elems, size_t elem_size)
   {
#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
   if(void* p = mlock_allocator::instance().allocate(elems, elem_size))
      return p;
#endif

   void* ptr = std::calloc(elems, elem_size);
   if(!ptr)
      throw std::bad_alloc();
   return ptr;
   }

void deallocate_memory(void* p, size_t elems, size_t elem_size)
   {
   if(p == nullptr)
      return;

   secure_scrub_memory(p, elems * elem_size);

#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
   if(mlock_allocator::instance().deallocate(p, elems, elem_size))
      return;
#endif

   std::free(p);
   }

bool constant_time_compare(const uint8_t x[],
                           const uint8_t y[],
                           size_t len)
   {
   volatile uint8_t difference = 0;

   for(size_t i = 0; i != len; ++i)
      difference |= (x[i] ^ y[i]);

   return difference == 0;
   }

void xor_buf(uint8_t x[],
             const uint8_t y[],
             size_t len)
   {
   while(len >= 16)
      {
      x[0] ^= y[0];
      x[1] ^= y[1];
      x[2] ^= y[2];
      x[3] ^= y[3];
      x[4] ^= y[4];
      x[5] ^= y[5];
      x[6] ^= y[6];
      x[7] ^= y[7];
      x[8] ^= y[8];
      x[9] ^= y[9];
      x[10] ^= y[10];
      x[11] ^= y[11];
      x[12] ^= y[12];
      x[13] ^= y[13];
      x[14] ^= y[14];
      x[15] ^= y[15];
      x += 16; y += 16; len -= 16;
      }

   for(size_t i = 0; i != len; ++i)
      {
      x[i] ^= y[i];
      }
   }

void xor_buf(uint8_t out[],
             const uint8_t in[],
             const uint8_t in2[],
             size_t length)
   {
   while(length >= 16)
      {
      out[0] = in[0] ^ in2[0];
      out[1] = in[1] ^ in2[1];
      out[2] = in[2] ^ in2[2];
      out[3] = in[3] ^ in2[3];
      out[4] = in[4] ^ in2[4];
      out[5] = in[5] ^ in2[5];
      out[6] = in[6] ^ in2[6];
      out[7] = in[7] ^ in2[7];
      out[8] = in[8] ^ in2[8];
      out[9] = in[9] ^ in2[9];
      out[10] = in[10] ^ in2[10];
      out[11] = in[11] ^ in2[11];
      out[12] = in[12] ^ in2[12];
      out[13] = in[13] ^ in2[13];
      out[14] = in[14] ^ in2[14];
      out[15] = in[15] ^ in2[15];
      in += 16; in2 += 16; out += 16; length -= 16;
      }

   for(size_t i = 0; i != length; ++i)
      out[i] = in[i] ^ in2[i];
   }

}
