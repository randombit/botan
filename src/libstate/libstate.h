/*
* Library Internal/Global State
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_LIB_STATE_H__
#define BOTAN_LIB_STATE_H__

#include <botan/types.h>
#include <botan/allocate.h>
#include <botan/algo_factory.h>

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

      void initialize(bool thread_safe);

      Algorithm_Factory& algorithm_factory();

      Allocator* get_allocator(const std::string& = "") const;
      void add_allocator(Allocator*);
      void set_default_allocator(const std::string&);

      /**
      * Get a parameter value as std::string.
      * @param section the section of the desired key
      * @param key the desired keys name
      * @result the value of the parameter
      */
      std::string get(const std::string& section,
                      const std::string& key) const;

      /**
      * Check whether a certain parameter is set
      * or not.
      * @param section the section of the desired key
      * @param key the desired keys name
      * @result true if the parameters value is set,
      * false otherwise
      */
      bool is_set(const std::string& section, const std::string& key) const;

      /**
      * Set a configuration parameter.
      * @param section the section of the desired key
      * @param key the desired keys name
      * @param overwrite if set to true, the parameters value
      * will be overwritten even if it is already set, otherwise
      * no existing values will be overwritten.
      */
      void set(const std::string& section, const std::string& key,
                 const std::string& value, bool overwrite = true);

      /**
      * Get a parameters value out of the "conf" section (
      * referred to as option).
      * @param key the desired keys name
      */
      std::string option(const std::string& key) const;

      /**
      * Set an option.
      * @param key the key of the option to set
      * @param value the value to set
      */
      void set_option(const std::string key, const std::string& value);

      /**
      * Add a parameter value to the "alias" section.
      * @param key the name of the parameter which shall have a new alias
      * @param value the new alias
      */
      void add_alias(const std::string&, const std::string&);

      /**
      * Resolve an alias.
      * @param alias the alias to resolve.
      * @return what the alias stands for
      */
      std::string deref_alias(const std::string&) const;

      class Mutex* get_mutex() const;
   private:
      void load_default_config();

      Library_State(const Library_State&) {}
      Library_State& operator=(const Library_State&) { return (*this); }

      class Mutex_Factory* mutex_factory;

      std::map<std::string, std::string> config;
      class Mutex* config_lock;

      class Mutex* allocator_lock;
      std::map<std::string, Allocator*> alloc_factory;
      mutable Allocator* cached_default_allocator;
      std::vector<Allocator*> allocators;

      Algorithm_Factory* m_algorithm_factory;
   };

/*
* Global State
*/
BOTAN_DLL Library_State& global_state();
BOTAN_DLL void set_global_state(Library_State*);
BOTAN_DLL Library_State* swap_global_state(Library_State*);

}

#endif
