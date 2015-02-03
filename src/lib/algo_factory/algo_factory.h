/*
* Algorithm Factory
* (C) 2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ALGORITHM_FACTORY_H__
#define BOTAN_ALGORITHM_FACTORY_H__

#include <botan/types.h>
#include <string>
#include <vector>

namespace Botan {

/**
* Forward declarations (don't need full definitions here)
*/
class BlockCipher;
class StreamCipher;
class HashFunction;
class MessageAuthenticationCode;
class PBKDF;

template<typename T> class Algorithm_Cache;

class Engine;

/**
* Algorithm Factory
*/
class BOTAN_DLL Algorithm_Factory
   {
   public:
      /**
      * Constructor
      */
      Algorithm_Factory();

      /**
      * Destructor
      */
      ~Algorithm_Factory();

      /**
      * @param engine to add (Algorithm_Factory takes ownership)
      */
      void add_engine(Engine* engine);

      /**
      * Clear out any cached objects
      */
      void clear_caches();

      /**
      * @param algo_spec the algorithm we are querying
      * @returns list of providers of this algorithm
      */
      std::vector<std::string> providers_of(const std::string& algo_spec);

      /**
      * @param algo_spec the algorithm we are setting a provider for
      * @param provider the provider we would like to use
      */
      void set_preferred_provider(const std::string& algo_spec,
                                  const std::string& provider);

      /**
      * @param algo_spec the algorithm we want
      * @param provider the provider we would like to use
      * @returns pointer to const prototype object, ready to clone(), or NULL
      */
      const BlockCipher*
         prototype_block_cipher(const std::string& algo_spec,
                                const std::string& provider = "");

      /**
      * @param algo_spec the algorithm we want
      * @param provider the provider we would like to use
      * @returns pointer to freshly created instance of the request algorithm
      */
      BlockCipher* make_block_cipher(const std::string& algo_spec,
                                     const std::string& provider = "");

      /**
      * @param algo_spec the algorithm we want
      * @param provider the provider we would like to use
      * @returns pointer to const prototype object, ready to clone(), or NULL
      */
      const StreamCipher*
         prototype_stream_cipher(const std::string& algo_spec,
                                 const std::string& provider = "");

      /**
      * @param algo_spec the algorithm we want
      * @param provider the provider we would like to use
      * @returns pointer to freshly created instance of the request algorithm
      */
      StreamCipher* make_stream_cipher(const std::string& algo_spec,
                                       const std::string& provider = "");

      /**
      * @param algo_spec the algorithm we want
      * @param provider the provider we would like to use
      * @returns pointer to const prototype object, ready to clone(), or NULL
      */
      const HashFunction*
         prototype_hash_function(const std::string& algo_spec,
                                 const std::string& provider = "");

      /**
      * @param algo_spec the algorithm we want
      * @param provider the provider we would like to use
      * @returns pointer to freshly created instance of the request algorithm
      */
      HashFunction* make_hash_function(const std::string& algo_spec,
                                       const std::string& provider = "");

      /**
      * @param algo_spec the algorithm we want
      * @param provider the provider we would like to use
      * @returns pointer to const prototype object, ready to clone(), or NULL
      */
      const MessageAuthenticationCode*
         prototype_mac(const std::string& algo_spec,
                       const std::string& provider = "");

      /**
      * @param algo_spec the algorithm we want
      * @param provider the provider we would like to use
      * @returns pointer to freshly created instance of the request algorithm
      */
      MessageAuthenticationCode* make_mac(const std::string& algo_spec,
                                          const std::string& provider = "");

      /**
      * @param algo_spec the algorithm we want
      * @param provider the provider we would like to use
      * @returns pointer to const prototype object, ready to clone(), or NULL
      */
      const PBKDF* prototype_pbkdf(const std::string& algo_spec,
                                   const std::string& provider = "");

      /**
      * @param algo_spec the algorithm we want
      * @param provider the provider we would like to use
      * @returns pointer to freshly created instance of the request algorithm
      */
      PBKDF* make_pbkdf(const std::string& algo_spec,
                        const std::string& provider = "");

   private:
      std::vector<Engine*> engines;

      std::unique_ptr<Algorithm_Cache<BlockCipher>> block_cipher_cache;
      std::unique_ptr<Algorithm_Cache<StreamCipher>> stream_cipher_cache;
      std::unique_ptr<Algorithm_Cache<HashFunction>> hash_cache;
      std::unique_ptr<Algorithm_Cache<MessageAuthenticationCode>> mac_cache;
      std::unique_ptr<Algorithm_Cache<PBKDF>> pbkdf_cache;
   };

}

#endif
