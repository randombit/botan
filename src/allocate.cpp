/*************************************************
* Allocator Factory Source File                  *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/allocate.h>
#include <botan/libstate.h>

namespace Botan {

/*************************************************
* Get an allocator                               *
*************************************************/
Allocator* get_allocator(const std::string& type)
   {
   Allocator* alloc = global_state().get_allocator(type);
   if(alloc)
      return alloc;

   throw Exception("Couldn't find an allocator to use in get_allocator");
   }

}
