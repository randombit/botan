/*************************************************
* Library Internal/Global State Source File      *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/libstate.h>
#include <botan/config.h>
#include <botan/modules.h>
#include <botan/engine.h>
#include <botan/x509stat.h>
#include <botan/stl_util.h>
#include <botan/mutex.h>
#include <botan/charset.h>
#include <botan/x931_rng.h>
#include <botan/fips140.h>
#include <algorithm>

namespace Botan {

/*************************************************
* Botan's global state                           *
*************************************************/
namespace {

Library_State* global_lib_state = 0;

}

/*************************************************
* Access the global state object                 *
*************************************************/
Library_State& global_state()
   {
   if(!global_lib_state)
      LibraryInitializer::initialize();
   return (*global_lib_state);
   }

/*************************************************
* Set a new global state object                  *
*************************************************/
void set_global_state(Library_State* new_state)
   {
   delete swap_global_state(new_state);
   }

/*************************************************
* Swap two global state objects                  *
*************************************************/
Library_State* swap_global_state(Library_State* new_state)
   {
   Library_State* old_state = global_lib_state;
   global_lib_state = new_state;
   return old_state;
   }

/*************************************************
* Increment the Engine iterator                  *
*************************************************/
Engine* Library_State::Engine_Iterator::next()
   {
   return lib.get_engine_n(n++);
   }

/*************************************************
* Get a new mutex object                         *
*************************************************/
Mutex* Library_State::get_mutex() const
   {
   return mutex_factory->make();
   }

/*************************************************
* Get an allocator by its name                   *
*************************************************/
Allocator* Library_State::get_allocator(const std::string& type) const
   {
   Mutex_Holder lock(allocator_lock);

   if(type != "")
      return search_map<std::string, Allocator*>(alloc_factory, type, 0);

   if(!cached_default_allocator)
      {
      std::string chosen = config().option("base/default_allocator");

      if(chosen == "")
         chosen = "malloc";

      cached_default_allocator =
         search_map<std::string, Allocator*>(alloc_factory, chosen, 0);
      }

   return cached_default_allocator;
   }

/*************************************************
* Create a new name to object mapping            *
*************************************************/
void Library_State::add_allocator(Allocator* allocator)
   {
   Mutex_Holder lock(allocator_lock);

   allocator->init();

   allocators.push_back(allocator);
   alloc_factory[allocator->type()] = allocator;
   }

/*************************************************
* Set the default allocator type                 *
*************************************************/
void Library_State::set_default_allocator(const std::string& type) const
   {
   Mutex_Holder lock(allocator_lock);

   if(type == "")
      return;

   config().set("conf", "base/default_allocator", type);
   cached_default_allocator = 0;
   }

/*************************************************
* Set the global PRNG                            *
*************************************************/
void Library_State::set_prng(RandomNumberGenerator* new_rng)
   {
   Mutex_Holder lock(rng_lock);

   delete rng;
   rng = new_rng;
   }

/*************************************************
* Get bytes from the global PRNG                 *
*************************************************/
void Library_State::randomize(byte out[], u32bit length)
   {
   Mutex_Holder lock(rng_lock);

   rng->randomize(out, length);
   }

/*************************************************
* Add a new entropy source to use                *
*************************************************/
void Library_State::add_entropy_source(EntropySource* src, bool last_in_list)
   {
   Mutex_Holder lock(rng_lock);

   if(last_in_list)
      entropy_sources.push_back(src);
   else
      entropy_sources.insert(entropy_sources.begin(), src);
   }

/*************************************************
* Add some bytes of entropy to the global PRNG   *
*************************************************/
void Library_State::add_entropy(const byte in[], u32bit length)
   {
   Mutex_Holder lock(rng_lock);

   rng->add_entropy(in, length);
   }

/*************************************************
* Add some bytes of entropy to the global PRNG   *
*************************************************/
void Library_State::add_entropy(EntropySource& source, bool slow_poll)
   {
   Mutex_Holder lock(rng_lock);

   rng->add_entropy(source, slow_poll);
   }

/*************************************************
* Gather entropy for our PRNG object             *
*************************************************/
u32bit Library_State::seed_prng(bool slow_poll, u32bit bits_to_get)
   {
   Mutex_Holder lock(rng_lock);

   u32bit bits = 0;
   for(u32bit j = 0; j != entropy_sources.size(); ++j)
      {
      bits += rng->add_entropy(*(entropy_sources[j]), slow_poll);

      if(bits_to_get && bits >= bits_to_get)
         return bits;
      }

   return bits;
   }

/*************************************************
* Get an engine out of the list                  *
*************************************************/
Engine* Library_State::get_engine_n(u32bit n) const
   {
   Mutex_Holder lock(engine_lock);

   if(n >= engines.size())
      return 0;
   return engines[n];
   }

/*************************************************
* Add a new engine to the list                   *
*************************************************/
void Library_State::add_engine(Engine* engine)
   {
   Mutex_Holder lock(engine_lock);
   engines.insert(engines.begin(), engine);
   }

/*************************************************
* Set the character set transcoder object        *
*************************************************/
void Library_State::set_transcoder(class Charset_Transcoder* transcoder)
   {
   if(this->transcoder)
      delete this->transcoder;
   this->transcoder = transcoder;
   }

/*************************************************
* Transcode a string from one charset to another *
*************************************************/
std::string Library_State::transcode(const std::string str,
                                     Character_Set to,
                                     Character_Set from) const
   {
   if(!transcoder)
      throw Invalid_State("Library_State::transcode: No transcoder set");

   return transcoder->transcode(str, to, from);
   }

/*************************************************
* Set the X509 global state class                *
*************************************************/
void Library_State::set_x509_state(X509_GlobalState* new_x509_state_obj)
   {
   delete x509_state_obj;
   x509_state_obj = new_x509_state_obj;
   }

/*************************************************
* Get the X509 global state class                *
*************************************************/
X509_GlobalState& Library_State::x509_state()
   {
   if(!x509_state_obj)
      x509_state_obj = new X509_GlobalState();

   return (*x509_state_obj);
   }

/*************************************************
* Set the configuration object                   *
*************************************************/
Config& Library_State::config() const
   {
   if(!config_obj)
      {
      config_obj = new Config();
      config_obj->load_defaults();
      }

   return (*config_obj);
   }

/*************************************************
* Load a set of modules                          *
*************************************************/
void Library_State::initialize(const InitializerOptions& args,
                               Modules& modules)
   {
   if(mutex_factory)
      throw Invalid_State("Library_State has already been initialized");

   if(args.thread_safe())
      mutex_factory = modules.mutex_factory();
   else
      mutex_factory = new Default_Mutex_Factory;

   allocator_lock = get_mutex();
   engine_lock = get_mutex();
   rng_lock = get_mutex();

   cached_default_allocator = 0;
   x509_state_obj = 0;

   transcoder = modules.transcoder();

   std::vector<Allocator*> mod_allocs = modules.allocators();
   for(u32bit j = 0; j != mod_allocs.size(); ++j)
      add_allocator(mod_allocs[j]);

   set_default_allocator(modules.default_allocator());

   std::vector<Engine*> mod_engines = modules.engines();
   for(u32bit j = 0; j != mod_engines.size(); ++j)
      engines.push_back(mod_engines[j]);

   std::vector<EntropySource*> sources = modules.entropy_sources();
   for(u32bit j = 0; j != sources.size(); ++j)
      add_entropy_source(sources[j]);

   set_prng(new ANSI_X931_RNG);

   if(args.seed_rng())
      {
      for(u32bit j = 0; j != 4; ++j)
         {
         seed_prng(true, 384);
         if(rng_is_seeded())
            break;
         }

      if(!rng_is_seeded())
         throw PRNG_Unseeded("Unable to collect sufficient entropy");
      }

   if(args.fips_mode() || args.self_test())
      {
      if(!FIPS140::passes_self_tests())
         throw Self_Test_Failure("FIPS-140 startup tests");
      }
   }

/*************************************************
* Library_State Constructor                      *
*************************************************/
Library_State::Library_State()
   {
   mutex_factory = 0;

   allocator_lock = engine_lock = rng_lock = 0;

   config_obj = 0;
   x509_state_obj = 0;

   transcoder = 0;
   rng = 0;
   cached_default_allocator = 0;
   }

/*************************************************
* Library_State Destructor                       *
*************************************************/
Library_State::~Library_State()
   {
   delete x509_state_obj;
   delete transcoder;
   delete rng;
   delete config_obj;

   std::for_each(entropy_sources.begin(), entropy_sources.end(),
                 del_fun<EntropySource>());
   std::for_each(engines.begin(), engines.end(), del_fun<Engine>());

   cached_default_allocator = 0;

   for(u32bit j = 0; j != allocators.size(); ++j)
      {
      allocators[j]->destroy();
      delete allocators[j];
      }

   delete mutex_factory;
   }

}
