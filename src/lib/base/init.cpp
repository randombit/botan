/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/init.h>

namespace Botan {

//static
void LibraryInitializer::initialize(const std::string&)
   {
   // none needed currently
   }

//static
void LibraryInitializer::deinitialize()
   {
   // none needed currently
   }

}
