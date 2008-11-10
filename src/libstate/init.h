/**
* Library Initialization Header File
* (C) 1999-2008 Jack Lloyd
*/

#ifndef BOTAN_LIBRARY_INITIALIZER_H__
#define BOTAN_LIBRARY_INITIALIZER_H__

#include <botan/libstate.h>

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
      static void initialize(bool thread_safe);

      static void deinitialize();

      /**
      * Initialize the library
      * @param thread_safe if the library should use a thread-safe mutex
      */
      LibraryInitializer(bool thread_safe = false)
         { LibraryInitializer::initialize(thread_safe); }

      ~LibraryInitializer() { LibraryInitializer::deinitialize(); }
   };

}

#endif
