/*************************************************
* Default Initialization Function Source File    *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/init.h>
#include <botan/libstate.h>
#include <botan/modules.h>
#include <botan/conf.h>
#include <botan/parsing.h>
#include <botan/defalloc.h>
#include <botan/eng_def.h>
#include <botan/fips140.h>
#include <botan/x931_rng.h>

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

namespace {

/*************************************************
* Parse the options string                       *
*************************************************/
std::map<std::string, std::string> parse_args(const std::string& arg_string)
   {
   std::map<std::string, std::string> arg_map;
   std::vector<std::string> args = split_on(arg_string, ' ');
   for(u32bit j = 0; j != args.size(); ++j)
      {
      if(args[j].find('=') == std::string::npos)
         arg_map[args[j]] = "";
      else
         {
         std::vector<std::string> name_and_value = split_on(args[j], '=');
         arg_map[name_and_value[0]] = name_and_value[1];
         }
      }

   return arg_map;
   }

/*************************************************
* Check if an option is set in the argument      *
*************************************************/
bool arg_set(const std::map<std::string, std::string>& args,
             const std::string& option)
   {
   return (args.find(option) != args.end());
   }

}

/*************************************************
* Library Initialization                         *
*************************************************/
void initialize(const std::string& arg_string)
   {
   std::map<std::string, std::string> args = parse_args(arg_string);

   Mutex_Factory* mutex_factory = 0;
   if(arg_set(args, "thread_safe"))
      {
      mutex_factory = Modules::get_mutex_factory();
      if(!mutex_factory)
         throw Exception("LibraryInitializer: thread safety impossible");
      }

   set_global_state(new Library_State(mutex_factory,
                                      Modules::get_timer()));

   global_state().add_allocator("malloc", new Malloc_Allocator);
   global_state().add_allocator("locking", new Locking_Allocator);

   if(arg_set(args, "secure_memory"))
      {
      std::map<std::string, Allocator*> allocators = Modules::get_allocators();
      for(std::map<std::string, Allocator*>::iterator i = allocators.begin();
          i != allocators.end(); ++i)
         global_state().add_allocator(i->first, i->second);
      }

   if(arg_set(args, "config") && args["config"] != "")
      Config::load(args["config"], global_state());

   if(arg_set(args, "use_engines"))
      {
      std::vector<Engine*> engines = Modules::get_engines();
      for(u32bit j = 0; j != engines.size(); ++j)
         global_state().add_engine(engines[j]);
      }
   global_state().add_engine(new Default_Engine);

   global_state().set_prng(new ANSI_X931_RNG);
   std::vector<EntropySource*> sources = Modules::get_entropy_sources();
   for(u32bit j = 0; j != sources.size(); ++j)
      global_state().add_entropy_source(sources[j], true);

   const u32bit min_entropy = Config::get_u32bit("rng/min_entropy");

   if(min_entropy != 0 && !arg_set(args, "no_rng_seed"))
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
