/*
* Basic Filters
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/basefilt.h>
#include <botan/key_filt.h>

namespace Botan {

void Keyed_Filter::set_iv(const InitializationVector& iv)
   {
   if(iv.length() != 0)
      throw Invalid_IV_Length(name(), iv.length());
   }

/*
* Chain Constructor
*/
Chain::Chain(Filter* f1, Filter* f2, Filter* f3, Filter* f4)
   {
   if(f1) { attach(f1); incr_owns(); }
   if(f2) { attach(f2); incr_owns(); }
   if(f3) { attach(f3); incr_owns(); }
   if(f4) { attach(f4); incr_owns(); }
   }

/*
* Chain Constructor
*/
Chain::Chain(Filter* filters[], size_t count)
   {
   for(size_t j = 0; j != count; ++j)
      if(filters[j])
         {
         attach(filters[j]);
         incr_owns();
         }
   }

std::string Chain::name() const
   {
   return "Chain";
   }

/*
* Fork Constructor
*/
Fork::Fork(Filter* f1, Filter* f2, Filter* f3, Filter* f4)
   {
   Filter* filters[4] = { f1, f2, f3, f4 };
   set_next(filters, 4);
   }

/*
* Fork Constructor
*/
Fork::Fork(Filter* filters[], size_t count)
   {
   set_next(filters, count);
   }

std::string Fork::name() const
   {
   return "Fork";
   }

}
