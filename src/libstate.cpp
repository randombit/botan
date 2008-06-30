/*************************************************
* Library Internal/Global State Source File      *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#include <botan/libstate.h>
#include <botan/modules.h>
#include <botan/engine.h>
#include <botan/stl_util.h>
#include <botan/mutex.h>
#include <botan/charset.h>
#include <botan/selftest.h>
#include <botan/lookup.h>
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
      std::string chosen = this->option("base/default_allocator");

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
void Library_State::set_default_allocator(const std::string& type)
   {
   Mutex_Holder lock(allocator_lock);

   if(type == "")
      return;

   this->set("conf", "base/default_allocator", type);
   cached_default_allocator = 0;
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
* Get a configuration value                      *
*************************************************/
std::string Library_State::get(const std::string& section,
                               const std::string& key) const
   {
   Mutex_Holder lock(config_lock);

   return search_map<std::string, std::string>(config,
                                               section + "/" + key, "");
   }

/*************************************************
* See if a particular option has been set        *
*************************************************/
bool Library_State::is_set(const std::string& section,
                           const std::string& key) const
   {
   Mutex_Holder lock(config_lock);

   return search_map(config, section + "/" + key, false, true);
   }

/*************************************************
* Set a configuration value                      *
*************************************************/
void Library_State::set(const std::string& section, const std::string& key,
                        const std::string& value, bool overwrite)
   {
   Mutex_Holder lock(config_lock);

   std::string full_key = section + "/" + key;

   std::map<std::string, std::string>::const_iterator i =
      config.find(full_key);

   if(overwrite || i == config.end() || i->second == "")
      config[full_key] = value;
   }

/*************************************************
* Add an alias                                   *
*************************************************/
void Library_State::add_alias(const std::string& key, const std::string& value)
   {
   set("alias", key, value);
   }

/*************************************************
* Dereference an alias to a fixed name           *
*************************************************/
std::string Library_State::deref_alias(const std::string& key) const
   {
   std::string result = key;
   while(is_set("alias", result))
      result = get("alias", result);
   return result;
   }

/*************************************************
* Set/Add an option                              *
*************************************************/
void Library_State::set_option(const std::string key,
                               const std::string& value)
   {
   set("conf", key, value);
   }

/*************************************************
* Get an option value                            *
*************************************************/
std::string Library_State::option(const std::string& key) const
   {
   return get("conf", key);
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
   config_lock = get_mutex();

   cached_default_allocator = 0;

   std::vector<Allocator*> mod_allocs = modules.allocators();
   for(u32bit j = 0; j != mod_allocs.size(); ++j)
      add_allocator(mod_allocs[j]);

   set_default_allocator(modules.default_allocator());

   load_default_config();

   std::vector<Engine*> mod_engines = modules.engines();
   for(u32bit j = 0; j != mod_engines.size(); ++j)
      engines.push_back(mod_engines[j]);

   if(args.fips_mode() || args.self_test())
      {
      if(!passes_self_tests())
         throw Self_Test_Failure("Initialization self-tests");
      }
   }

/*************************************************
* Library_State Constructor                      *
*************************************************/
Library_State::Library_State()
   {
   mutex_factory = 0;
   allocator_lock = engine_lock = config_lock = 0;
   cached_default_allocator = 0;
   }

/*************************************************
* Library_State Destructor                       *
*************************************************/
Library_State::~Library_State()
   {
   std::for_each(engines.begin(), engines.end(), del_fun<Engine>());

   cached_default_allocator = 0;

   for(u32bit j = 0; j != allocators.size(); ++j)
      {
      allocators[j]->destroy();
      delete allocators[j];
      }

   delete allocator_lock;
   delete engine_lock;
   delete mutex_factory;
   delete config_lock;
   }

}
