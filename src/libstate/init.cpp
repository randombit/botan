/*
* Default Initialization Function
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/init.h>
#include <botan/parsing.h>
#include <botan/libstate.h>
#include <botan/global_state.h>

namespace Botan {

/*
* Library Initialization
*/
void LibraryInitializer::initialize(const std::string& arg_string)
   {
   bool thread_safe = false;

   const std::vector<std::string> arg_list = split_on(arg_string, ' ');
   for(size_t i = 0; i != arg_list.size(); ++i)
      {
      if(arg_list[i].size() == 0)
         continue;

      std::string name, value;

      if(arg_list[i].find('=') == std::string::npos)
         {
         name = arg_list[i];
         value = "true";
         }
      else
         {
         std::vector<std::string> name_and_value = split_on(arg_list[i], '=');
         name = name_and_value[0];
         value = name_and_value[1];
         }

      bool is_on =
         (value == "1" || value == "true" || value == "yes" || value == "on");

      if(name == "thread_safe")
         thread_safe = is_on;
      }

   try
      {
      /*
      This two stage initialization process is because Library_State's
      constructor will implicitly refer to global state through the
      allocators and so forth, so global_state() has to be a valid
      reference before initialize() can be called. Yeah, gross.
      */
      Global_State_Management::set_global_state(new Library_State);

      global_state().initialize(thread_safe);
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
   Global_State_Management::set_global_state(0);
   }

}
