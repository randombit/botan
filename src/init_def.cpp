/*************************************************
* Default Initialization Function Source File    *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/init.h>
#include <botan/libstate.h>
#include <botan/modules.h>
#include <botan/config.h>
#include <botan/defalloc.h>
#include <botan/fips140.h>
#include <botan/x931_rng.h>
#include <botan/def_char.h>

namespace Botan {

/*************************************************
* Library Initialization                         *
*************************************************/
void LibraryInitializer::initialize(const std::string& arg_string)
   {
   InitializerOptions args(arg_string);
   initialize(args);
   }

/*************************************************
* Library Initialization                         *
*************************************************/
void LibraryInitializer::initialize(const InitializerOptions& args)
   {
   Builtin_Modules modules(args);
   initialize(args, modules);
   }

/*************************************************
* Library Initialization                         *
*************************************************/
void LibraryInitializer::initialize(const InitializerOptions& args,
                                    Modules& modules)
   {
   try
      {
      set_global_state(
         new Library_State(
            args.thread_safe() ?
               modules.mutex_factory() :
               new Default_Mutex_Factory
            )
         );

      global_state().config().load_defaults();
      if(args.config_file() != "")
         global_config().load_inifile(args.config_file());

      global_state().load(modules);
      global_state().set_prng(new ANSI_X931_RNG);

      if(args.seed_rng())
         {
         for(u32bit j = 0; j != 4; ++j)
            {
            global_state().seed_prng(true, 384);
            if(global_state().rng_is_seeded())
               break;
            }

         if(!global_state().rng_is_seeded())
            throw PRNG_Unseeded("Unable to collect sufficient entropy");
         }

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

}
