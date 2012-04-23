/*
* Library Internal/Global State
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/libstate.h>
#include <botan/charset.h>
#include <botan/engine.h>
#include <botan/cpuid.h>
#include <botan/internal/defalloc.h>
#include <botan/internal/core_engine.h>
#include <botan/internal/mutex.h>
#include <botan/internal/mux_noop.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/mlock.h>
#include <algorithm>

#if defined(BOTAN_HAS_SELFTESTS)
  #include <botan/selftest.h>
#endif

#if defined(BOTAN_HAS_MUTEX_PTHREAD)
  #include <botan/internal/mux_pthr.h>
#elif defined(BOTAN_HAS_MUTEX_WIN32)
  #include <botan/internal/mux_win32.h>
#endif

#if defined(BOTAN_HAS_ALLOC_MMAP)
  #include <botan/internal/mmap_mem.h>
#endif

#if defined(BOTAN_HAS_ENGINE_ASSEMBLER)
  #include <botan/internal/asm_engine.h>
#endif

#if defined(BOTAN_HAS_ENGINE_AES_ISA)
  #include <botan/internal/aes_isa_engine.h>
#endif

#if defined(BOTAN_HAS_ENGINE_SIMD)
  #include <botan/internal/simd_engine.h>
#endif

#if defined(BOTAN_HAS_ENGINE_GNU_MP)
  #include <botan/internal/gnump_engine.h>
#endif

#if defined(BOTAN_HAS_ENGINE_OPENSSL)
  #include <botan/internal/openssl_engine.h>
#endif

namespace Botan {

/*
* Get a new mutex object
*/
Mutex* Library_State::get_mutex() const
   {
   return mutex_factory->make();
   }

/*
* Get an allocator by its name
*/
Allocator* Library_State::get_allocator(const std::string& type) const
   {
   Mutex_Holder lock(allocator_lock);

   if(type != "")
      return search_map<std::string, Allocator*>(alloc_factory, type, 0);

   if(!cached_default_allocator)
      {
      cached_default_allocator =
         search_map<std::string, Allocator*>(alloc_factory,
                                             default_allocator_name, 0);
      }

   return cached_default_allocator;
   }

/*
* Create a new name to object mapping
*/
void Library_State::add_allocator(Allocator* allocator)
   {
   Mutex_Holder lock(allocator_lock);

   allocator->init();

   allocators.push_back(allocator);
   alloc_factory[allocator->type()] = allocator;
   }

/*
* Set the default allocator type
*/
void Library_State::set_default_allocator(const std::string& type)
   {
   Mutex_Holder lock(allocator_lock);

   if(type == "")
      return;

   default_allocator_name = type;
   cached_default_allocator = 0;
   }

/*
* Get a configuration value
*/
std::string Library_State::get(const std::string& section,
                               const std::string& key) const
   {
   Mutex_Holder lock(config_lock);

   return search_map<std::string, std::string>(config,
                                               section + "/" + key, "");
   }

/*
* See if a particular option has been set
*/
bool Library_State::is_set(const std::string& section,
                           const std::string& key) const
   {
   Mutex_Holder lock(config_lock);

   return config.count(section + "/" + key) != 0;
   }

/*
* Set a configuration value
*/
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
std::string Library_State::deref_alias(const std::string& key) const
   {
   std::string result = key;
   while(is_set("alias", result))
      result = get("alias", result);
   return result;
   }

/*
* Return a reference to the Algorithm_Factory
*/
Algorithm_Factory& Library_State::algorithm_factory() const
   {
   if(!m_algorithm_factory)
      throw Invalid_State("Uninitialized in Library_State::algorithm_factory");
   return *m_algorithm_factory;
   }

/*
* Return a reference to the global PRNG
*/
RandomNumberGenerator& Library_State::global_rng()
   {
   Mutex_Holder lock(global_rng_lock);

   if(!global_rng_ptr)
      global_rng_ptr = make_global_rng(algorithm_factory(),
                                       global_rng_lock);

   return *global_rng_ptr;
   }

/*
* Load a set of modules
*/
void Library_State::initialize(bool thread_safe)
   {
   CPUID::initialize();

   if(mutex_factory)
      throw Invalid_State("Library_State has already been initialized");

   if(!thread_safe)
      {
      mutex_factory = new Noop_Mutex_Factory;
      }
   else
      {
#if defined(BOTAN_HAS_MUTEX_PTHREAD)
      mutex_factory = new Pthread_Mutex_Factory;
#elif defined(BOTAN_HAS_MUTEX_WIN32)
      mutex_factory = new Win32_Mutex_Factory;
#else
      throw Invalid_State("Could not find a thread-safe mutex object to use");
#endif
      }

   allocator_lock = get_mutex();
   config_lock = get_mutex();
   global_rng_lock = get_mutex();

   default_allocator_name = has_mlock() ? "locking" : "malloc";

   add_allocator(new Malloc_Allocator);
   add_allocator(new Locking_Allocator(get_mutex()));

#if defined(BOTAN_HAS_ALLOC_MMAP)
   add_allocator(new MemoryMapping_Allocator(get_mutex()));
#endif

   load_default_config();

   m_algorithm_factory = new Algorithm_Factory(*mutex_factory);

#if defined(BOTAN_HAS_ENGINE_GNU_MP)
   algorithm_factory().add_engine(new GMP_Engine);
#endif

#if defined(BOTAN_HAS_ENGINE_OPENSSL)
   algorithm_factory().add_engine(new OpenSSL_Engine);
#endif

#if defined(BOTAN_HAS_ENGINE_AES_ISA)
   algorithm_factory().add_engine(new AES_ISA_Engine);
#endif

#if defined(BOTAN_HAS_ENGINE_SIMD)
   algorithm_factory().add_engine(new SIMD_Engine);
#endif

#if defined(BOTAN_HAS_ENGINE_ASSEMBLER)
   algorithm_factory().add_engine(new Assembler_Engine);
#endif

   algorithm_factory().add_engine(new Core_Engine);

#if defined(BOTAN_HAS_SELFTESTS)
   confirm_startup_self_tests(algorithm_factory());
#endif
   }

/*
* Library_State Constructor
*/
Library_State::Library_State()
   {
   mutex_factory = 0;
   allocator_lock = config_lock = 0;
   cached_default_allocator = 0;
   m_algorithm_factory = 0;

   global_rng_lock = 0;
   global_rng_ptr = 0;
   }

/*
* Library_State Destructor
*/
Library_State::~Library_State()
   {
   delete m_algorithm_factory;
   delete global_rng_ptr;

   cached_default_allocator = 0;

   for(size_t i = 0; i != allocators.size(); ++i)
      {
      allocators[i]->destroy();
      delete allocators[i];
      }

   delete global_rng_lock;
   delete allocator_lock;
   delete mutex_factory;
   delete config_lock;
   }

}
