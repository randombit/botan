/*
* External Allocator
* (C) 2022 Oliver Collyer
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EXTERNAL_ALLOCATOR_H_
#define BOTAN_EXTERNAL_ALLOCATOR_H_

#include <botan/types.h>

//BOTAN_FUTURE_INTERNAL_HEADER(external_allocator.h)

namespace Botan {

class BOTAN_PUBLIC_API(2,0) external_allocator final
   {
   public:
      static external_allocator& instance();

      void* allocate(size_t num_elems, size_t elem_size);

      bool deallocate(void* p, size_t num_elems, size_t elem_size) noexcept;

      external_allocator(const external_allocator&) = delete;

      external_allocator& operator=(const external_allocator&) = delete;

   private:
      external_allocator();

      ~external_allocator();
   };

}

#endif

