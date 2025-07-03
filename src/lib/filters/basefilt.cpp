/*
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/filters.h>

namespace Botan {

/*
* Chain Constructor
*/
Chain::Chain(Filter* f1, Filter* f2, Filter* f3, Filter* f4) {
   if(f1 != nullptr) {
      attach(f1);
      incr_owns();
   }
   if(f2 != nullptr) {
      attach(f2);
      incr_owns();
   }
   if(f3 != nullptr) {
      attach(f3);
      incr_owns();
   }
   if(f4 != nullptr) {
      attach(f4);
      incr_owns();
   }
}

/*
* Chain Constructor
*/
Chain::Chain(Filter* filters[], size_t count) {
   for(size_t j = 0; j != count; ++j) {
      if(filters[j] != nullptr) {
         attach(filters[j]);
         incr_owns();
      }
   }
}

/*
* Fork Constructor
*/
Fork::Fork(Filter* f1, Filter* f2, Filter* f3, Filter* f4) {
   Filter* filters[4] = {f1, f2, f3, f4};
   set_next(filters, 4);
}

/*
* Fork Constructor
*/
Fork::Fork(Filter* filters[], size_t count) {
   set_next(filters, count);
}

}  // namespace Botan
