/*
* Pooling Allocator
* (C) 1999-2008 Jack Lloyd
*     2005 Matthew Gregan
*     2005-2006 Matt Johnston
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/mem_pool.h>
#include <botan/internal/rounding.h>
#include <botan/mem_ops.h>
#include <algorithm>
#include <exception>

namespace Botan {

/*
* Memory_Block Constructor
*/
Pooling_Allocator::Memory_Block::Memory_Block(void* buf)
   {
   buffer = static_cast<byte*>(buf);
   bitmap = 0;
   buffer_end = buffer + (BLOCK_SIZE * BITMAP_SIZE);
   }

/*
* See if ptr is contained by this block
*/
bool Pooling_Allocator::Memory_Block::contains(void* ptr,
                                               size_t length) const
   {
   return ((buffer <= ptr) &&
           (buffer_end >= static_cast<byte*>(ptr) + length * BLOCK_SIZE));
   }

/*
* Allocate some memory, if possible
*/
byte* Pooling_Allocator::Memory_Block::alloc(size_t n)
   {
   if(n == 0 || n > BITMAP_SIZE)
      return 0;

   if(n == BITMAP_SIZE)
      {
      if(bitmap)
         return 0;
      else
         {
         bitmap = ~bitmap;
         return buffer;
         }
      }

   bitmap_type mask = (static_cast<bitmap_type>(1) << n) - 1;
   size_t offset = 0;

   while(bitmap & mask)
      {
      mask <<= 1;
      ++offset;

      if((bitmap & mask) == 0)
         break;
      if(mask >> 63)
         break;
      }

   if(bitmap & mask)
      return 0;

   bitmap |= mask;
   return buffer + offset * BLOCK_SIZE;
   }

/*
* Mark this memory as free, if we own it
*/
void Pooling_Allocator::Memory_Block::free(void* ptr, size_t blocks)
   {
   clear_mem(static_cast<byte*>(ptr), blocks * BLOCK_SIZE);

   const size_t offset = (static_cast<byte*>(ptr) - buffer) / BLOCK_SIZE;

   if(offset == 0 && blocks == BITMAP_SIZE)
      bitmap = ~bitmap;
   else
      {
      for(size_t j = 0; j != blocks; ++j)
         bitmap &= ~(static_cast<bitmap_type>(1) << (j+offset));
      }
   }

/*
* Pooling_Allocator Constructor
*/
Pooling_Allocator::Pooling_Allocator(Mutex* m) : mutex(m)
   {
   last_used = blocks.begin();
   }

/*
* Pooling_Allocator Destructor
*/
Pooling_Allocator::~Pooling_Allocator()
   {
   delete mutex;
   if(blocks.size())
      throw Invalid_State("Pooling_Allocator: Never released memory");
   }

/*
* Free all remaining memory
*/
void Pooling_Allocator::destroy()
   {
   Mutex_Holder lock(mutex);

   blocks.clear();

   for(size_t j = 0; j != allocated.size(); ++j)
      dealloc_block(allocated[j].first, allocated[j].second);
   allocated.clear();
   }

/*
* Allocation
*/
void* Pooling_Allocator::allocate(size_t n)
   {
   const size_t BITMAP_SIZE = Memory_Block::bitmap_size();
   const size_t BLOCK_SIZE = Memory_Block::block_size();

   Mutex_Holder lock(mutex);

   if(n <= BITMAP_SIZE * BLOCK_SIZE)
      {
      const size_t block_no = round_up(n, BLOCK_SIZE) / BLOCK_SIZE;

      byte* mem = allocate_blocks(block_no);
      if(mem)
         return mem;

      get_more_core(BOTAN_MEM_POOL_CHUNK_SIZE);

      mem = allocate_blocks(block_no);
      if(mem)
         return mem;

      throw Memory_Exhaustion();
      }

   void* new_buf = alloc_block(n);
   if(new_buf)
      return new_buf;

   throw Memory_Exhaustion();
   }

/*
* Deallocation
*/
void Pooling_Allocator::deallocate(void* ptr, size_t n)
   {
   const size_t BITMAP_SIZE = Memory_Block::bitmap_size();
   const size_t BLOCK_SIZE = Memory_Block::block_size();

   if(ptr == 0 || n == 0)
      return;

   Mutex_Holder lock(mutex);

   if(n > BITMAP_SIZE * BLOCK_SIZE)
      dealloc_block(ptr, n);
   else
      {
      const size_t block_no = round_up(n, BLOCK_SIZE) / BLOCK_SIZE;

      std::vector<Memory_Block>::iterator i =
         std::lower_bound(blocks.begin(), blocks.end(), Memory_Block(ptr));

      if(i == blocks.end() || !i->contains(ptr, block_no))
         throw Invalid_State("Pointer released to the wrong allocator");

      i->free(ptr, block_no);
      }
   }

/*
* Try to get some memory from an existing block
*/
byte* Pooling_Allocator::allocate_blocks(size_t n)
   {
   if(blocks.empty())
      return 0;

   std::vector<Memory_Block>::iterator i = last_used;

   do
      {
      byte* mem = i->alloc(n);
      if(mem)
         {
         last_used = i;
         return mem;
         }

      ++i;
      if(i == blocks.end())
         i = blocks.begin();
      }
   while(i != last_used);

   return 0;
   }

/*
* Allocate more memory for the pool
*/
void Pooling_Allocator::get_more_core(size_t in_bytes)
   {
   const size_t BITMAP_SIZE = Memory_Block::bitmap_size();
   const size_t BLOCK_SIZE = Memory_Block::block_size();

   const size_t TOTAL_BLOCK_SIZE = BLOCK_SIZE * BITMAP_SIZE;

   // upper bound on allocation is 1 MiB
   in_bytes = std::min<size_t>(in_bytes, 1024 * 1024);

   const size_t in_blocks = round_up(in_bytes, BLOCK_SIZE) / TOTAL_BLOCK_SIZE;
   const size_t to_allocate = in_blocks * TOTAL_BLOCK_SIZE;

   void* ptr = alloc_block(to_allocate);
   if(ptr == 0)
      throw Memory_Exhaustion();

   allocated.push_back(std::make_pair(ptr, to_allocate));

   for(size_t j = 0; j != in_blocks; ++j)
      {
      byte* byte_ptr = static_cast<byte*>(ptr);
      blocks.push_back(Memory_Block(byte_ptr + j * TOTAL_BLOCK_SIZE));
      }

   std::sort(blocks.begin(), blocks.end());
   last_used = std::lower_bound(blocks.begin(), blocks.end(),
                                Memory_Block(ptr));
   }

}
