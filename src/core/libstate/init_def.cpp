/*************************************************
* Default Initialization Function Source File    *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/init.h>
#include <botan/libstate.h>
#include <botan/modules.h>

namespace Botan {

/*************************************************
* Library Initialization                         *
*************************************************/
void LibraryInitializer::initialize(const InitializerOptions& args,
                                    Modules& modules)
   {
   try
      {
      set_global_state(new Library_State);

      global_state().initialize(args, modules);
      }
   catch(...)
      {
      deinitialize();
      throw;
      }
   }

/*************************************************
* Library Shutdown                               *
*************************************************/
void LibraryInitializer::deinitialize()
   {
   set_global_state(0);
   }

/*************************************************
* Library Initialization                         *
*************************************************/
void LibraryInitializer::initialize(const std::string& arg_string)
   {
   InitializerOptions args(arg_string);
   Builtin_Modules modules(args);

   initialize(args, modules);
   }

/*************************************************
* Library Initialization                         *
*************************************************/
void LibraryInitializer::initialize(const InitializerOptions& args)
   {
   Builtin_Modules modules(args);

   initialize(args, modules);
   }

}
