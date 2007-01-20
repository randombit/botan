/*************************************************
* Basic Filters Source File                      *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/basefilt.h>

namespace Botan {

/*************************************************
* Chain Constructor                              *
*************************************************/
Chain::Chain(Filter* f1, Filter* f2, Filter* f3, Filter* f4)
   {
   if(f1) { attach(f1); incr_owns(); }
   if(f2) { attach(f2); incr_owns(); }
   if(f3) { attach(f3); incr_owns(); }
   if(f4) { attach(f4); incr_owns(); }
   }

/*************************************************
* Chain Constructor                              *
*************************************************/
Chain::Chain(Filter* filters[], u32bit count)
   {
   for(u32bit j = 0; j != count; ++j)
      if(filters[j])
         {
         attach(filters[j]);
         incr_owns();
         }
   }

/*************************************************
* Fork Constructor                               *
*************************************************/
Fork::Fork(Filter* f1, Filter* f2, Filter* f3, Filter* f4)
   {
   Filter* filters[4] = { f1, f2, f3, f4 };
   set_next(filters, 4);
   }

/*************************************************
* Fork Constructor                               *
*************************************************/
Fork::Fork(Filter* filters[], u32bit count)
   {
   set_next(filters, count);
   }

/*************************************************
* Set the algorithm key                          *
*************************************************/
void Keyed_Filter::set_key(const SymmetricKey& key)
   {
   if(base_ptr)
      base_ptr->set_key(key);
   else
      throw Invalid_State("Keyed_Filter::set_key: No base algorithm set");
   }

/*************************************************
* Check if a keylength is valid                  *
*************************************************/
bool Keyed_Filter::valid_keylength(u32bit n) const
   {
   if(base_ptr)
      return base_ptr->valid_keylength(n);
   throw Invalid_State("Keyed_Filter::valid_keylength: No base algorithm set");
   }

}
