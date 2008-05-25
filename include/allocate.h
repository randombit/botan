/*************************************************
* Allocator Header File                          *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_ALLOCATOR_H__
#define BOTAN_ALLOCATOR_H__

#include <botan/types.h>
#include <string>
#include <botan/pointers.h>

namespace Botan {

/*************************************************
* Allocator                                      *
*************************************************/
class Allocator
   {
   public:
      static std::tr1::shared_ptr<Allocator> get(bool);

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

}

#endif
