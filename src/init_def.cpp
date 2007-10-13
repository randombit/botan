/*************************************************
* Default Initialization Function Source File    *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/init.h>
#include <botan/libstate.h>
#include <botan/modules.h>
#include <botan/fips140.h>

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

      if(args.fips_mode() || args.self_test())
         {
         if(!FIPS140::passes_self_tests())
            throw Self_Test_Failure("FIPS-140 startup tests");
         }
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
