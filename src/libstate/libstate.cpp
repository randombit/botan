/*
* Library Internal/Global State
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/libstate.h>
#include <botan/init.h>
#include <botan/selftest.h>
#include <botan/engine.h>
#include <botan/stl_util.h>
#include <botan/charset.h>
#include <botan/defalloc.h>
#include <botan/def_eng.h>
#include <algorithm>

#if defined(BOTAN_HAS_ALLOC_MMAP)
  #include <botan/mmap_mem.h>
#endif

#if defined(BOTAN_HAS_ENGINE_IA32_ASSEMBLER)
  #include <botan/eng_ia32.h>
#endif

#if defined(BOTAN_HAS_ENGINE_AMD64_ASSEMBLER)
  #include <botan/eng_amd64.h>
#endif

#if defined(BOTAN_HAS_ENGINE_AES_ISA)
  #include <botan/aes_isa_engine.h>
#endif

#if defined(BOTAN_HAS_ENGINE_SIMD)
  #include <botan/simd_engine.h>
#endif

#if defined(BOTAN_HAS_ENGINE_GNU_MP)
  #include <botan/eng_gmp.h>
#endif

#if defined(BOTAN_HAS_ENGINE_OPENSSL)
  #include <botan/eng_ossl.h>
#endif

namespace Botan {

/*
* Botan's global state
*/
namespace {

Library_State* global_lib_state = 0;

}

/*
* Access the global state object
*/
Library_State& global_state()
   {
   /* Lazy initialization. Botan still needs to be deinitialized later
      on or memory might leak.
   */
   if(!global_lib_state)
      LibraryInitializer::initialize("thread_safe=true");

   return (*global_lib_state);
   }

/*
* Set a new global state object
*/
void set_global_state(Library_State* new_state)
   {
   delete swap_global_state(new_state);
   }

/*
* Swap two global state objects
*/
Library_State* swap_global_state(Library_State* new_state)
   {
   auto old_state = global_lib_state;
   global_lib_state = new_state;
   return old_state;
   }

/*
* Get an allocator by its name
*/
Allocator* Library_State::get_allocator(const std::string& type)
   {
   std::lock_guard<std::mutex> lock(allocator_lock);

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

/*
* Create a new name to object mapping
*/
void Library_State::add_allocator(Allocator* allocator)
   {
   std::lock_guard<std::mutex> lock(allocator_lock);

   allocator->init();

   allocators.push_back(allocator);
   alloc_factory[allocator->type()] = allocator;
   }

/*
* Set the default allocator type
*/
void Library_State::set_default_allocator(const std::string& type)
   {
   if(type == "")
      return;

   std::lock_guard<std::mutex> lock(allocator_lock);

   this->set("conf", "base/default_allocator", type);
   cached_default_allocator = 0;
   }

/*
* Get a configuration value
*/
std::string Library_State::get(const std::string& section,
                               const std::string& key)
   {
   std::lock_guard<std::mutex> lock(config_lock);

   return search_map<std::string, std::string>(config,
                                               section + "/" + key, "");
   }

/*
* See if a particular option has been set
*/
bool Library_State::is_set(const std::string& section,
                           const std::string& key)
   {
   std::lock_guard<std::mutex> lock(config_lock);

   return search_map(config, section + "/" + key, false, true);
   }

/*
* Set a configuration value
*/
void Library_State::set(const std::string& section, const std::string& key,
                        const std::string& value, bool overwrite)
   {
   std::lock_guard<std::mutex> lock(config_lock);

   std::string full_key = section + "/" + key;

   std::map<std::string, std::string>::const_iterator i =
      config.find(full_key);

   if(overwrite || i == config.end() || i->second == "")
      config[full_key] = value;
   }

/*
* Add an alias
*/
void Library_State::add_alias(const std::string& key, const std::string& value)
   {
   set("alias", key, value);
   }

/*
* Dereference an alias to a fixed name
*/
std::string Library_State::deref_alias(const std::string& key)
   {
   std::string result = key;
   while(is_set("alias", result))
      result = get("alias", result);
   return result;
   }

/*
* Set/Add an option
*/
void Library_State::set_option(const std::string& key,
                               const std::string& value)
   {
   set("conf", key, value);
   }

/*
* Get an option value
*/
std::string Library_State::option(const std::string& key)
   {
   return get("conf", key);
   }

/**
Return a reference to the Algorithm_Factory
*/
Algorithm_Factory& Library_State::algorithm_factory()
   {
   if(!m_algorithm_factory)
      throw Invalid_State("Uninitialized in Library_State::algorithm_factory");
   return *m_algorithm_factory;
   }

/*
* Load a set of modules
*/
void Library_State::initialize()
   {
   if(m_algorithm_factory)
      throw Invalid_State("Library_State has already been initialized");

   cached_default_allocator = 0;

   add_allocator(new Malloc_Allocator);
   add_allocator(new Locking_Allocator);

#if defined(BOTAN_HAS_ALLOC_MMAP)
   add_allocator(new MemoryMapping_Allocator);
#endif

   set_default_allocator("locking");

   load_default_config();

   std::vector<Engine*> engines = {

#if defined(BOTAN_HAS_ENGINE_GNU_MP)
      new GMP_Engine,
#endif

#if defined(BOTAN_HAS_ENGINE_OPENSSL)
      new OpenSSL_Engine,
#endif

#if defined(BOTAN_HAS_ENGINE_AES_ISA)
   new AES_ISA_Engine,
#endif

#if defined(BOTAN_HAS_ENGINE_SIMD)
      new SIMD_Engine,
#endif

#if defined(BOTAN_HAS_ENGINE_AMD64_ASSEMBLER)
      new AMD64_Assembler_Engine,
#endif

#if defined(BOTAN_HAS_ENGINE_IA32_ASSEMBLER)
      new IA32_Assembler_Engine,
#endif

      new Default_Engine
   };

   m_algorithm_factory = new Algorithm_Factory(engines);

   if(!passes_self_tests(algorithm_factory()))
      throw Self_Test_Failure("Startup self tests failed");
   }

/*
* Library_State Constructor
*/
Library_State::Library_State()
   {
   cached_default_allocator = 0;
   m_algorithm_factory = 0;
   }

/*
* Library_State Destructor
*/
Library_State::~Library_State()
   {
   delete m_algorithm_factory;
   m_algorithm_factory = 0;

   cached_default_allocator = 0;

   for(u32bit j = 0; j != allocators.size(); ++j)
      {
      allocators[j]->destroy();
      delete allocators[j];
      }
   }

}
