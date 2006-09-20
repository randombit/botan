/*************************************************
* Library Internal/Global State Source File      *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/libstate.h>
#include <botan/config.h>
#include <botan/modules.h>
#include <botan/engine.h>
#include <botan/x509stat.h>
#include <botan/stl_util.h>
#include <botan/mutex.h>
#include <botan/timers.h>
#include <botan/charset.h>
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
      {
      abort();
      throw Invalid_State("Library was not initialized correctly");
      }
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
* Get a persistent named mutex object            *
*************************************************/
Mutex* Library_State::get_named_mutex(const std::string& name)
   {
   Mutex* mux = search_map<std::string, Mutex*>(locks, name, 0);
   if(mux)
      return mux;
   return (locks[name] = get_mutex());
   }

/*************************************************
* Get an allocator by its name                   *
*************************************************/
Allocator* Library_State::get_allocator(const std::string& type) const
   {
   Named_Mutex_Holder lock("allocator");

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
   Named_Mutex_Holder lock("allocator");

   allocator->init();

   allocators.push_back(allocator);
   alloc_factory[allocator->type()] = allocator;
   }

/*************************************************
* Set the default allocator type                 *
*************************************************/
void Library_State::set_default_allocator(const std::string& type) const
   {
   Named_Mutex_Holder lock("allocator");

   if(type == "")
      return;

   config().set("conf", "base/default_allocator", type);
   cached_default_allocator = 0;
   }

/*************************************************
* Set the high resolution clock implementation   *
*************************************************/
void Library_State::set_timer(Timer* new_timer)
   {
   if(new_timer)
      {
      delete timer;
      timer = new_timer;
      }
   }

/*************************************************
* Read a high resolution clock                   *
*************************************************/
u64bit Library_State::system_clock() const
   {
   return (timer) ? timer->clock() : 0;
   }

/*************************************************
* Set the global PRNG                            *
*************************************************/
void Library_State::set_prng(RandomNumberGenerator* new_rng)
   {
   Named_Mutex_Holder lock("rng");

   delete rng;
   rng = new_rng;
   }

/*************************************************
* Get bytes from the global PRNG                 *
*************************************************/
void Library_State::randomize(byte out[], u32bit length)
   {
   Named_Mutex_Holder lock("rng");

   rng->randomize(out, length);
   }

/*************************************************
* Add a new entropy source to use                *
*************************************************/
void Library_State::add_entropy_source(EntropySource* src, bool last_in_list)
   {
   Named_Mutex_Holder lock("rng");

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
   Named_Mutex_Holder lock("rng");

   rng->add_entropy(in, length);
   }

/*************************************************
* Add some bytes of entropy to the global PRNG   *
*************************************************/
void Library_State::add_entropy(EntropySource& source, bool slow_poll)
   {
   Named_Mutex_Holder lock("rng");

   rng->add_entropy(source, slow_poll);
   }

/*************************************************
* Gather entropy for our PRNG object             *
*************************************************/
u32bit Library_State::seed_prng(bool slow_poll, u32bit bits_to_get)
   {
   Named_Mutex_Holder lock("rng");

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
   Named_Mutex_Holder lock("engine");

   if(n >= engines.size())
      return 0;
   return engines[n];
   }

/*************************************************
* Add a new engine to the list                   *
*************************************************/
void Library_State::add_engine(Engine* engine)
   {
   Named_Mutex_Holder lock("engine");
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
      throw Invalid_State("Library_State::config(): No config set");

   return (*config_obj);
   }

/*************************************************
* Load modules                                   *
*************************************************/
void Library_State::load(Modules& modules)
   {
   set_timer(modules.timer());
   set_transcoder(modules.transcoder());

   std::vector<Allocator*> mod_allocs = modules.allocators();
   for(u32bit j = 0; j != mod_allocs.size(); j++)
      add_allocator(mod_allocs[j]);

   set_default_allocator(modules.default_allocator());

   std::vector<Engine*> mod_engines = modules.engines();
   for(u32bit j = 0; j != mod_engines.size(); ++j)
      {
      Named_Mutex_Holder lock("engine");
      engines.push_back(mod_engines[j]);
      }

   std::vector<EntropySource*> sources = modules.entropy_sources();
   for(u32bit j = 0; j != sources.size(); ++j)
      add_entropy_source(sources[j]);
   }

/*************************************************
* Library_State Constructor                      *
*************************************************/
Library_State::Library_State(Mutex_Factory* mutex_factory)
   {
   if(!mutex_factory)
      throw Exception("Library_State: no mutex found");

   this->mutex_factory = mutex_factory;
   this->timer = new Timer();
   this->transcoder = 0;
   this->config_obj = new Config();

   locks["settings"] = get_mutex();
   locks["allocator"] = get_mutex();
   locks["rng"] = get_mutex();
   locks["engine"] = get_mutex();
   rng = 0;
   cached_default_allocator = 0;
   x509_state_obj = 0;
   }

/*************************************************
* Library_State Destructor                       *
*************************************************/
Library_State::~Library_State()
   {
   delete x509_state_obj;
   delete transcoder;
   delete rng;
   delete timer;
   delete config_obj;

   std::for_each(entropy_sources.begin(), entropy_sources.end(),
                 del_fun<EntropySource>());
   std::for_each(engines.begin(), engines.end(), del_fun<Engine>());

   cached_default_allocator = 0;

   for(u32bit j = 0; j != allocators.size(); j++)
      {
      allocators[j]->destroy();
      delete allocators[j];
      }

   std::for_each(locks.begin(), locks.end(),
                 delete2nd<std::map<std::string, Mutex*>::value_type>);

   delete mutex_factory;
   }

}
