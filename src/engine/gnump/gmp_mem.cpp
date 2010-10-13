/*
* GNU MP Memory Handlers
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/gnump_engine.h>
#include <cstring>
#include <gmp.h>

namespace Botan {

namespace {

/*
* Allocator used by GNU MP
*/
Allocator* gmp_alloc = 0;
size_t gmp_alloc_refcnt = 0;

/*
* Allocation Function for GNU MP
*/
void* gmp_malloc(size_t n)
   {
   return gmp_alloc->allocate(n);
   }

/*
* Reallocation Function for GNU MP
*/
void* gmp_realloc(void* ptr, size_t old_n, size_t new_n)
   {
   void* new_buf = gmp_alloc->allocate(new_n);
   std::memcpy(new_buf, ptr, std::min(old_n, new_n));
   gmp_alloc->deallocate(ptr, old_n);
   return new_buf;
   }

/*
* Deallocation Function for GNU MP
*/
void gmp_free(void* ptr, size_t n)
   {
   gmp_alloc->deallocate(ptr, n);
   }

}

/*
* GMP_Engine Constructor
*/
GMP_Engine::GMP_Engine()
   {
   if(gmp_alloc == 0)
      {
      gmp_alloc = Allocator::get(true);
      mp_set_memory_functions(gmp_malloc, gmp_realloc, gmp_free);
      }

   ++gmp_alloc_refcnt;
   }

GMP_Engine::~GMP_Engine()
   {
   --gmp_alloc_refcnt;

   if(gmp_alloc_refcnt == 0)
      {
      mp_set_memory_functions(NULL, NULL, NULL);
      gmp_alloc = 0;
      }
   }

}
