/*
* Pooling Allocator
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_POOLING_ALLOCATOR_H__
#define BOTAN_POOLING_ALLOCATOR_H__

#include <botan/allocate.h>
#include <botan/exceptn.h>
#include <botan/internal/mutex.h>
#include <utility>
#include <vector>

namespace Botan {

/**
* Pooling Allocator
*/
class Pooling_Allocator : public Allocator
   {
   public:
      void* allocate(size_t);
      void deallocate(void*, size_t);

      void destroy();

      /**
      * @param mutex used for internal locking
      */
      Pooling_Allocator(Mutex* mutex);
      ~Pooling_Allocator();
   private:
      void get_more_core(size_t);
      byte* allocate_blocks(size_t);

      virtual void* alloc_block(size_t) = 0;
      virtual void dealloc_block(void*, size_t) = 0;

      class Memory_Block
         {
         public:
            Memory_Block(void*);

            static size_t bitmap_size() { return BITMAP_SIZE; }
            static size_t block_size() { return BLOCK_SIZE; }

            bool contains(void*, size_t) const;
            byte* alloc(size_t);
            void free(void*, size_t);

            bool operator<(const Memory_Block& other) const
               {
               if(buffer < other.buffer && other.buffer < buffer_end)
                  return false;
               return (buffer < other.buffer);
               }
         private:
            typedef u64bit bitmap_type;
            static const size_t BITMAP_SIZE = 8 * sizeof(bitmap_type);
            static const size_t BLOCK_SIZE = 64;

            bitmap_type bitmap;
            byte* buffer, *buffer_end;
         };

      std::vector<Memory_Block> blocks;
      std::vector<Memory_Block>::iterator last_used;
      std::vector<std::pair<void*, size_t> > allocated;
      Mutex* mutex;
   };

}

#endif
