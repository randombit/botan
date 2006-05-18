/*************************************************
* Library Initialization Header File             *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_INIT_H__
#define BOTAN_INIT_H__

#include <string>

namespace Botan {

namespace Init {

/*************************************************
* Main Library Initialization/Shutdown Functions *
*************************************************/
void initialize(const std::string& = "");
void deinitialize();

}

/*************************************************
* Library Initialization/Shutdown Object         *
*************************************************/
class LibraryInitializer
   {
   public:
      LibraryInitializer(const std::string& = "");
      ~LibraryInitializer();
   };

}

#endif
