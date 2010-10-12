/*
* Basic Allocators
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/defalloc.h>
#include <botan/internal/mlock.h>
#include <botan/libstate.h>
#include <cstdlib>
#include <cstring>

namespace Botan {

namespace {

/*
* Perform Memory Allocation
*/
void* do_malloc(size_t n, bool do_lock)
   {
   void* ptr = std::malloc(n);

   if(!ptr)
      return 0;

   if(do_lock)
      lock_mem(ptr, n);

   std::memset(ptr, 0, n);
   return ptr;
   }

/*
* Perform Memory Deallocation
*/
void do_free(void* ptr, size_t n, bool do_lock)
   {
   if(!ptr)
      return;

   std::memset(ptr, 0, n);
   if(do_lock)
      unlock_mem(ptr, n);

   std::free(ptr);
   }

}

/*
* Malloc_Allocator's Allocation
*/
void* Malloc_Allocator::allocate(size_t n)
   {
   void* ptr = do_malloc(n, false);
   if(!ptr)
      throw Memory_Exhaustion();
   return ptr;
   }

/*
* Malloc_Allocator's Deallocation
*/
void Malloc_Allocator::deallocate(void* ptr, size_t n)
   {
   do_free(ptr, n, false);
   }

/*
* Locking_Allocator's Allocation
*/
void* Locking_Allocator::alloc_block(size_t n)
   {
   return do_malloc(n, true);
   }

/*
* Locking_Allocator's Deallocation
*/
void Locking_Allocator::dealloc_block(void* ptr, size_t n)
   {
   do_free(ptr, n, true);
   }

/*
* Get an allocator
*/
Allocator* Allocator::get(bool locking)
   {
   std::string type = "";
   if(!locking)
      type = "malloc";

   Allocator* alloc = global_state().get_allocator(type);
   if(alloc)
      return alloc;

   throw Internal_Error("Couldn't find an allocator to use in get_allocator");
   }

}
