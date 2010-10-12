/*
* Basic Allocators
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_BASIC_ALLOC_H__
#define BOTAN_BASIC_ALLOC_H__

#include <botan/internal/mem_pool.h>

namespace Botan {

/**
* Allocator using malloc
*/
class Malloc_Allocator : public Allocator
   {
   public:
      void* allocate(size_t);
      void deallocate(void*, size_t);

      std::string type() const { return "malloc"; }
   };

/**
* Allocator using malloc plus locking
*/
class Locking_Allocator : public Pooling_Allocator
   {
   public:
      /**
      * @param mutex used for internal locking
      */
      Locking_Allocator(Mutex* mutex) : Pooling_Allocator(mutex) {}

      std::string type() const { return "locking"; }
   private:
      void* alloc_block(size_t);
      void dealloc_block(void*, size_t);
   };

}

#endif
