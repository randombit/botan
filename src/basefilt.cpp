/*************************************************
* Basic Filters Source File                      *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/basefilt.h>

namespace Botan {

/*************************************************
* Chain Constructor                              *
*************************************************/
Chain::Chain(SharedFilterPtrConverter const& f1c,
             SharedFilterPtrConverter const& f2c,
             SharedFilterPtrConverter const& f3c,
             SharedFilterPtrConverter const& f4c) :
   Fanout_Filter()
   {
   SharedFilterPtr const& f1(f1c.get_shared());
   if(f1) { attach(f1); incr_owns(); }

   SharedFilterPtr const& f2(f2c.get_shared());
   if(f2) { attach(f2); incr_owns(); }

   SharedFilterPtr const& f3(f3c.get_shared());
   if(f3) { attach(f3); incr_owns(); }

   SharedFilterPtr const& f4(f4c.get_shared());
   if(f4) { attach(f4); incr_owns(); }
   }

/*************************************************
* Fork Constructor                               *
*************************************************/
Fork::Fork(SharedFilterPtrConverter const& f1c,
           SharedFilterPtrConverter const& f2c,
           SharedFilterPtrConverter const& f3c,
           SharedFilterPtrConverter const& f4c) :
   Fanout_Filter()
   {
   Filter* filters[4] = { f1, f2, f3, f4 };

   set_next(filters, 4);
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
