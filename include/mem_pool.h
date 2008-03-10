/*************************************************
* Pooling Allocator Header File                  *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_POOLING_ALLOCATOR_H__
#define BOTAN_POOLING_ALLOCATOR_H__

#include <botan/allocate.h>
#include <botan/exceptn.h>
#include <botan/mutex.h>
#include <utility>
#include <vector>

namespace Botan {

/*************************************************
* Pooling Allocator                              *
*************************************************/
class Pooling_Allocator : public Allocator
   {
   public:
      void* allocate(u32bit);
      void deallocate(void*, u32bit);

      void destroy();

      Pooling_Allocator(u32bit, bool);
      ~Pooling_Allocator();
   private:
      void get_more_core(u32bit);
      byte* allocate_blocks(u32bit);

      virtual void* alloc_block(u32bit) = 0;
      virtual void dealloc_block(void*, u32bit) = 0;

      class Memory_Block
         {
         public:
            Memory_Block(void*);

            static u32bit bitmap_size() { return BITMAP_SIZE; }
            static u32bit block_size() { return BLOCK_SIZE; }

            bool contains(void*, u32bit) const throw();
            byte* alloc(u32bit) throw();
            void free(void*, u32bit) throw();

            bool operator<(const Memory_Block& other) const
               {
               if(buffer < other.buffer && other.buffer < buffer_end)
                  return false;
               return (buffer < other.buffer);
               }
         private:
            typedef u64bit bitmap_type;
            static const u32bit BITMAP_SIZE = 8 * sizeof(bitmap_type);
            static const u32bit BLOCK_SIZE = 64;

            bitmap_type bitmap;
            byte* buffer, *buffer_end;
         };

      const u32bit PREF_SIZE;

      std::vector<Memory_Block> blocks;
      std::vector<Memory_Block>::iterator last_used;
      std::vector<std::pair<void*, u32bit> > allocated;
      Mutex* mutex;
   };

}

#endif
