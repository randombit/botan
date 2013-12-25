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
#include <botan/internal/core_engine.h>
#include <botan/internal/stl_util.h>
#include <algorithm>

#if defined(BOTAN_HAS_SELFTESTS)
  #include <botan/selftest.h>
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

   return config.count(section + "/" + key) != 0;
   }

/*
* Set a configuration value
*/
void Library_State::set(const std::string& section, const std::string& key,
                        const std::string& value, bool overwrite)
   {
   std::lock_guard<std::mutex> lock(config_lock);

   std::string full_key = section + "/" + key;

   auto i = config.find(full_key);

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
   return *m_global_prng;
   }

void Library_State::initialize()
   {
   if(m_algorithm_factory.get())
      throw Invalid_State("Library_State has already been initialized");

   CPUID::initialize();

   load_default_config();

   m_algorithm_factory.reset(new Algorithm_Factory());

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

   m_sources = entropy_sources();

   m_global_prng.reset(new Serialized_RNG());

#if defined(BOTAN_HAS_SELFTESTS)
   confirm_startup_self_tests(algorithm_factory());
#endif
   }

}
