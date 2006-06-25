/*************************************************
* Allocator Header File                          *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_ALLOCATOR_H__
#define BOTAN_ALLOCATOR_H__

#include <botan/types.h>
#include <string>

namespace Botan {

/*************************************************
* Allocator                                      *
*************************************************/
class Allocator
   {
   public:
      virtual void* allocate(u32bit) = 0;
      virtual void deallocate(void*, u32bit) = 0;

      virtual std::string type() const = 0;

      virtual void init() {}
      virtual void destroy() {}

      virtual ~Allocator() {}
   };

/*************************************************
* Get an allocator                               *
*************************************************/
Allocator* get_allocator(const std::string& = "");

}

#endif
