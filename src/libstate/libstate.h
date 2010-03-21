/*
* Library Internal/Global State
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_LIB_STATE_H__
#define BOTAN_LIB_STATE_H__

#include <botan/allocate.h>
#include <botan/algo_factory.h>
#include <botan/rng.h>

#include <mutex>
#include <string>
#include <vector>
#include <map>

namespace Botan {

/*
* Global State Container Base
*/
class BOTAN_DLL Library_State
   {
   public:
      Library_State();
      ~Library_State();

      Library_State(const Library_State&) = delete;
      Library_State& operator=(const Library_State&) = delete;

      void initialize();

      /**
      * @return the global Algorithm_Factory
      */
      Algorithm_Factory& algorithm_factory() const;

      /**
      * @return the global RandomNumberGenerator
      */
      RandomNumberGenerator& global_rng();

      /**
      * @param name the name of the allocator
      * @return allocator matching this name, or NULL
      */
      Allocator* get_allocator(const std::string& name = "");

      /**
      * Add a new allocator to the list of available ones
      * @param alloc the allocator to add
      */
      void add_allocator(Allocator* alloc);

      /**
      * Set the default allocator
      * @param name the name of the allocator to use as the default
      */
      void set_default_allocator(const std::string& name);

      /**
      * Get a parameter value as std::string.
      * @param section the section of the desired key
      * @param key the desired keys name
      * @result the value of the parameter
      */
      std::string get(const std::string& section,
                      const std::string& key);

      /**
      * Check whether a certain parameter is set
      * or not.
      * @param section the section of the desired key
      * @param key the desired keys name
      * @result true if the parameters value is set,
      * false otherwise
      */
      bool is_set(const std::string& section,
                  const std::string& key);

      /**
      * Set a configuration parameter.
      * @param section the section of the desired key
      * @param key the desired keys name
      * @param overwrite if set to true, the parameters value
      * will be overwritten even if it is already set, otherwise
      * no existing values will be overwritten.
      */
      void set(const std::string& section,
               const std::string& key,
               const std::string& value,
               bool overwrite = true);

      /**
      * Add a parameter value to the "alias" section.
      * @param key the name of the parameter which shall have a new alias
      * @param value the new alias
      */
      void add_alias(const std::string& key,
                     const std::string& value);

      /**
      * Resolve an alias.
      * @param alias the alias to resolve.
      * @return what the alias stands for
      */
      std::string deref_alias(const std::string&);
   private:
      static RandomNumberGenerator* make_global_rng(Algorithm_Factory& af,
                                                    Mutex* mutex);

      void load_default_config();

      std::mutex global_rng_lock;
      RandomNumberGenerator* global_rng_ptr;

      std::mutex config_lock;
      std::map<std::string, std::string> config;

      std::mutex allocator_lock;
      std::string default_allocator_name;
      std::map<std::string, Allocator*> alloc_factory;
      mutable Allocator* cached_default_allocator;
      std::vector<Allocator*> allocators;

      Algorithm_Factory* m_algorithm_factory;
   };

/**
* Access the global library state
* @return reference to the global library state
*/
BOTAN_DLL Library_State& global_state();

/**
* Set the global state object
* @param state the new global state to use
*/
BOTAN_DLL void set_global_state(Library_State* state);

/**
* Swap the current state for another
* @param new_state the new state object to use
* @return the previous state (or NULL if none)
*/
BOTAN_DLL Library_State* swap_global_state(Library_State* new_state);

}

#endif
