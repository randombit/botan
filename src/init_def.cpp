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
   Init::initialize(arg_string);
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
void initialize(const std::string& arg_string)
   {
   InitializerOptions args(arg_string);
   Builtin_Modules modules(false);

   Mutex_Factory* mutex_factory = 0;

   if(args.thread_safe())
      {
      mutex_factory = modules.mutex_factory();
      if(!mutex_factory)
         throw Exception("LibraryInitializer: thread safety impossible");
      }

   set_global_state(new Library_State(mutex_factory));
   global_state().set_default_policy();

   global_state().load(modules);

   if(args.config_file() != "")
      global_config().load_inifile(args.config_file());

   global_state().set_transcoder(new Default_Charset_Transcoder);
   global_state().set_prng(new ANSI_X931_RNG);

   const u32bit min_entropy =
      global_config().option_as_u32bit("rng/min_entropy");

   if(min_entropy != 0 && args.seed_rng())
      {
      u32bit total_bits = 0;
      for(u32bit j = 0; j != 4; ++j)
         {
         total_bits += global_state().seed_prng(true,
                                                min_entropy - total_bits);
         if(total_bits >= min_entropy)
            break;
         }

      if(total_bits < min_entropy)
         throw PRNG_Unseeded("Unable to collect sufficient entropy");
      }

   if(!FIPS140::passes_self_tests())
      {
      set_global_state(0);
      throw Self_Test_Failure("FIPS-140 startup tests");
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
