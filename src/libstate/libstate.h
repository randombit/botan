/*
* Library Internal/Global State
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_LIB_STATE_H__
#define BOTAN_LIB_STATE_H__

#include <botan/global_state.h>
#include <botan/algo_factory.h>
#include <botan/rng.h>
#include <mutex>
#include <string>
#include <vector>
#include <map>
#include <memory>

namespace Botan {

/**
* Global Library State
*/
class BOTAN_DLL Library_State
   {
   public:
      Library_State() {}

      Library_State(const Library_State&) = delete;
      Library_State& operator=(const Library_State&) = delete;

      void initialize();

      /**
      * @return global Algorithm_Factory
      */
      Algorithm_Factory& algorithm_factory() const;

      /**
      * @return global RandomNumberGenerator
      */
      RandomNumberGenerator& global_rng();

      void poll_available_sources(class Entropy_Accumulator& accum);

      /**
      * Get a parameter value as std::string.
      * @param section the section of the desired key
      * @param key the desired keys name
      * @result the value of the parameter
      */
      std::string get(const std::string& section,
                      const std::string& key);

      /**
      * Check whether a certain parameter is set or not.
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
      * @param value the new value
      * @param overwrite if set to true, the parameters value
      * will be overwritten even if it is already set, otherwise
      * no existing values will be overwritten.
      */
      void set(const std::string& section,
               const std::string& key,
               const std::string& value,
               bool overwrite = true);

   private:
      static std::vector<std::unique_ptr<EntropySource>> entropy_sources();

      void load_default_config();

      std::unique_ptr<Serialized_RNG> m_global_prng;

      std::mutex m_entropy_src_mutex;
      std::vector<std::unique_ptr<EntropySource>> m_sources;

      std::mutex config_lock;
      std::map<std::string, std::string> config;

      std::unique_ptr<Algorithm_Factory> m_algorithm_factory;
   };

}

#endif
