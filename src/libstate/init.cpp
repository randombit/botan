/*
* Default Initialization Function
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/init.h>
#include <botan/libstate.h>
#include <botan/global_state.h>

namespace Botan {

/*
* Library Initialization
*/
void LibraryInitializer::initialize(const std::string&)
   {

   try
      {
      /*
      This two stage initialization process is because Library_State's
      constructor will implicitly refer to global state through the
      allocators and so forth, so global_state() has to be a valid
      reference before initialize() can be called. Yeah, gross.
      */
      Global_State_Management::set_global_state(new Library_State);

      global_state().initialize();
      }
   catch(...)
      {
      deinitialize();
      throw;
      }
   }

/*
* Library Shutdown
*/
void LibraryInitializer::deinitialize()
   {
   Global_State_Management::set_global_state(nullptr);
   }

}
