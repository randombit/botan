/*
* Global State Management
* (C) 2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/global_state.h>
#include <botan/libstate.h>
#include <memory>
#include <mutex>

namespace Botan {

namespace Global_State_Management {

namespace {

std::mutex g_lib_state_mutex;
std::unique_ptr<Library_State> g_lib_state;

}

/*
* Access the global state object
*/
Library_State& global_state()
   {
   // @todo use double checked locking? (Is this safe in C++11 mm?)
   std::lock_guard<std::mutex> lock(g_lib_state_mutex);

   /* Lazy initialization. Botan still needs to be deinitialized later
      on or memory might leak.
   */
   if(!g_lib_state)
      {
      g_lib_state.reset(new Library_State);
      g_lib_state->initialize();
      }

   return (*g_lib_state);
   }

/*
* Set a new global state object
*/
void set_global_state(Library_State* state)
   {
   std::lock_guard<std::mutex> lock(g_lib_state_mutex);
   g_lib_state.reset(state);
   }

/*
* Set a new global state object unless one already existed
*/
bool set_global_state_unless_set(Library_State* state)
   {
   std::lock_guard<std::mutex> lock(g_lib_state_mutex);

   if(g_lib_state)
      return false;

   g_lib_state.reset(state);
   return true;
   }

/*
* Swap two global state objects
*/
Library_State* swap_global_state(Library_State* new_state)
   {
   std::lock_guard<std::mutex> lock(g_lib_state_mutex);
   Library_State* old_state = g_lib_state.release();
   g_lib_state.reset(new_state);
   return old_state;
   }

/*
* Query if library is initialized
*/
bool global_state_exists()
   {
   return (g_lib_state != nullptr);
   }

}

}
