/*************************************************
* Basic Allocators Header File                   *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_BASIC_ALLOC_H__
#define BOTAN_BASIC_ALLOC_H__

#include <botan/mem_pool.h>

namespace Botan {

/*************************************************
* Malloc Allocator                              *
*************************************************/
class Malloc_Allocator : public Pooling_Allocator
   {
   public:
      Malloc_Allocator() : Pooling_Allocator(64*1024, false) {}
      std::string type() const { return "malloc"; }
   private:
      void* alloc_block(u32bit);
      void dealloc_block(void*, u32bit);
   };

/*************************************************
* Locking Allocator                              *
*************************************************/
class Locking_Allocator : public Pooling_Allocator
   {
   public:
      Locking_Allocator() : Pooling_Allocator(64*1024, true) {}
      std::string type() const { return "locking"; }
   private:
      void* alloc_block(u32bit);
      void dealloc_block(void*, u32bit);
   };

}

#endif
