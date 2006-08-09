/*************************************************
* Default Initialization Function Source File    *
* (C) 1999-2006 The Botan Project                *
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
LibraryInitializer::LibraryInitializer(const std::string& arg_string)
   {
   InitializerOptions args(arg_string);
   Init::initialize(args);
   }

/*************************************************
* Library Initialization                         *
*************************************************/
LibraryInitializer::LibraryInitializer(const InitializerOptions& args)
   {
   Init::initialize(args);
   }

/*************************************************
* Library Shutdown                               *
*************************************************/
LibraryInitializer::~LibraryInitializer()
   {
   Init::deinitialize();
   }

namespace Init {

/*************************************************
* Library Initialization                         *
*************************************************/
void initialize(const InitializerOptions& args)
   {
   try
      {
      Builtin_Modules modules(args);

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
         const u32bit min_entropy =
            global_config().option_as_u32bit("rng/min_entropy");

         if(min_entropy != 0)
            {
            u32bit bits_so_far = 0;

            for(u32bit j = 0; j != 4; ++j)
               {
               u32bit to_get = min_entropy - bits_so_far;

               bits_so_far += global_state().seed_prng(true, to_get);

               if(bits_so_far >= min_entropy)
                  break;
               }

            if(bits_so_far < min_entropy)
               throw PRNG_Unseeded("Unable to collect sufficient entropy");
            }
         }

      if(args.fips_mode() || args.self_test())
         {
         if(!FIPS140::passes_self_tests())
            throw Self_Test_Failure("FIPS-140 startup tests");
         }
      }
   catch(std::exception)
      {
      deinitialize();
      throw;
      }
   }

/*************************************************
* Library Shutdown                               *
*************************************************/
void deinitialize()
   {
   set_global_state(0);
   }

}

}
