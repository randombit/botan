/*
* Library Initialization
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_LIBRARY_INITIALIZER_H__
#define BOTAN_LIBRARY_INITIALIZER_H__

#include <botan/build.h>
#include <string>

namespace Botan {

/**
* This class represents the Library Initialization/Shutdown Object. It
* has to exceed the lifetime of any Botan object used in an application.
*/
class BOTAN_DLL LibraryInitializer
   {
   public:
      LibraryInitializer();
      ~LibraryInitializer();
   private:
      bool m_owned;
   };

}

#endif
