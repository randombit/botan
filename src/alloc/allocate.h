/*
* Allocator
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ALLOCATOR_H__
#define BOTAN_ALLOCATOR_H__

#include <botan/types.h>
#include <string>

namespace Botan {

/**
* Allocator Interface
*/
class BOTAN_DLL Allocator
   {
   public:
      /**
      * Acquire a pointer to an allocator
      * @param locking is true if the allocator should attempt to
      *                secure the memory (eg for using to store keys)
      * @return pointer to an allocator; ownership remains with library,
      *                 so do not delete
      */
      static Allocator* get(bool locking);

      /**
      * Allocate a block of memory
      * @param n how many bytes to allocate
      * @return pointer to n bytes of memory
      */
      virtual void* allocate(size_t n) = 0;

      /**
      * Deallocate memory allocated with allocate()
      * @param ptr the pointer returned by allocate()
      * @param n the size of the block pointed to by ptr
      */
      virtual void deallocate(void* ptr, size_t n) = 0;

      /**
      * @return name of this allocator type
      */
      virtual std::string type() const = 0;

      /**
      * Initialize the allocator
      */
      virtual void init() {}

      /**
      * Shutdown the allocator
      */
      virtual void destroy() {}

      virtual ~Allocator() {}
   };

}

#endif
