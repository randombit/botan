/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ALLOCATOR_HELPERS_H_
#define BOTAN_ALLOCATOR_HELPERS_H_

#include <botan/types.h>

namespace Botan {

/*
* Define BOTAN_MALLOC_FN
*/
#if defined(__clang__) || defined(__GNUG__)
   #define BOTAN_MALLOC_FN __attribute__((malloc))
#elif defined(_MSC_VER)
   #define BOTAN_MALLOC_FN __declspec(restrict)
#else
   #define BOTAN_MALLOC_FN
#endif

/**
* Allocate a memory buffer by some method. This should only be used for
* primitive types (uint8_t, uint32_t, etc).
*
* @param elems the number of elements
* @param elem_size the size of each element
* @return pointer to allocated and zeroed memory, or throw std::bad_alloc on failure
*/
BOTAN_PUBLIC_API(2, 3) BOTAN_MALLOC_FN void* allocate_memory(size_t elems, size_t elem_size);

/**
* Free a pointer returned by allocate_memory
* @param p the pointer returned by allocate_memory
* @param elems the number of elements, as passed to allocate_memory
* @param elem_size the size of each element, as passed to allocate_memory
*/
BOTAN_PUBLIC_API(2, 3) void deallocate_memory(void* p, size_t elems, size_t elem_size);

/**
* Ensure the allocator is initialized
*/
void BOTAN_UNSTABLE_API initialize_allocator();

/**
* Initializes the allocator as a side effect of construction
*
* Declare a static instance in a translation unit to ensure the allocator
* is initialized before any other static initialization in that unit.
*/
class Allocator_Initializer final {
   public:
      /// Initialize the allocator
      Allocator_Initializer() { initialize_allocator(); }
};

}  // namespace Botan

#endif
