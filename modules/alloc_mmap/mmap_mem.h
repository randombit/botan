/*************************************************
* Memory Mapping Allocator Header File           *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_EXT_MMAP_ALLOCATOR_H__
#define BOTAN_EXT_MMAP_ALLOCATOR_H__

#include <botan/mem_pool.h>

namespace Botan {

/*************************************************
* Memory Mapping Allocator                       *
*************************************************/
class MemoryMapping_Allocator : public Pooling_Allocator
   {
   public:
      MemoryMapping_Allocator() : Pooling_Allocator(64*1024, false) {}
      std::string type() const { return "mmap"; }
   private:
      void* alloc_block(u32bit);
      void dealloc_block(void*, u32bit);
   };

}

#endif
