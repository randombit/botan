/*
* Memory Mapping Allocator
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MMAP_ALLOCATOR_H__
#define BOTAN_MMAP_ALLOCATOR_H__

#include <botan/mem_pool.h>

namespace Botan {

/*
* Memory Mapping Allocator
*/
class BOTAN_DLL MemoryMapping_Allocator : public Pooling_Allocator
   {
   public:
      MemoryMapping_Allocator(Mutex* m) : Pooling_Allocator(m) {}
      std::string type() const { return "mmap"; }
   private:
      void* alloc_block(u32bit);
      void dealloc_block(void*, u32bit);
   };

}

#endif
