/**
* Library Initialization
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_LIBRARY_INITIALIZER_H__
#define BOTAN_LIBRARY_INITIALIZER_H__

#include <botan/build.h>
#include <string>

namespace Botan {

/**
* This class represents the Library Initialization/Shutdown Object. It
* has to exceed the lifetime of any Botan object used in an
* application.  You can call initialize/deinitialize or use
* LibraryInitializer in the RAII style.
*/
class BOTAN_DLL LibraryInitializer
   {
   public:
      static void initialize(const std::string& options = "");

      static void deinitialize();

      /**
      * Initialize the library
      * @param thread_safe if the library should use a thread-safe mutex
      */
      LibraryInitializer(const std::string& options = "")
         { LibraryInitializer::initialize(options); }

      ~LibraryInitializer() { LibraryInitializer::deinitialize(); }
   };

}

#endif
