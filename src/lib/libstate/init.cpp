/*
* Library initialization
* (C) 1999-2009.2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/init.h>
#include <botan/libstate.h>
#include <botan/global_state.h>

namespace Botan {

LibraryInitializer::LibraryInitializer()
   {
   /*
   This two stage initialization process is because Library_State's
   constructor will implicitly refer to global state through the
   allocators and so forth, so global_state() has to be a valid
   reference before initialize() can be called. Yeah, gross.
   */
   m_owned = Global_State_Management::set_global_state_unless_set(new Library_State);

   if(m_owned)
      {
      try
         {
         global_state().initialize();
         }
      catch(...)
         {
         Global_State_Management::set_global_state(nullptr);
         throw;
         }
      }
   }

LibraryInitializer::~LibraryInitializer()
   {
   if(m_owned)
      Global_State_Management::set_global_state(nullptr);
   }

}
