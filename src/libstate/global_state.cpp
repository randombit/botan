/*
* Global State Management
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/global_state.h>
#include <botan/libstate.h>

namespace Botan {

/*
* @todo There should probably be a lock to avoid racy manipulation
* of the state among different threads
*/

namespace Global_State_Management {

/*
* Botan's global state
*/
namespace {

Library_State* global_lib_state = 0;

}

/*
* Access the global state object
*/
Library_State& global_state()
   {
   /* Lazy initialization. Botan still needs to be deinitialized later
      on or memory might leak.
   */
   if(!global_lib_state)
      {
      global_lib_state = new Library_State;
      global_lib_state->initialize(true);
      }

   return (*global_lib_state);
   }

/*
* Set a new global state object
*/
void set_global_state(Library_State* new_state)
   {
   delete swap_global_state(new_state);
   }

/*
* Set a new global state object unless one already existed
*/
bool set_global_state_unless_set(Library_State* new_state)
   {
   if(global_lib_state)
      {
      delete new_state;
      return false;
      }
   else
      {
      delete swap_global_state(new_state);
      return true;
      }
   }

/*
* Swap two global state objects
*/
Library_State* swap_global_state(Library_State* new_state)
   {
   Library_State* old_state = global_lib_state;
   global_lib_state = new_state;
   return old_state;
   }

/*
* Query if library is initialized
*/
bool global_state_exists()
   {
   return (global_lib_state != 0);
   }

}

}
