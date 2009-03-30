/**
* Algorithm Factory
* (C) 2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ALGORITHM_FACTORY_H__
#define BOTAN_ALGORITHM_FACTORY_H__

#include <botan/mutex.h>
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
      * @param engines_in the list of engines to use
      * @param mf a mutex factory
      */
      Algorithm_Factory(const std::vector<Engine*>& engines_in,
                        Mutex_Factory& mf);

      /**
      * Destructor
      */
      ~Algorithm_Factory();

      /*
      * Provider management
      */
      std::vector<std::string> providers_of(const std::string& algo_spec);

      void set_preferred_provider(const std::string& algo_spec,
                                  const std::string& provider);

      /*
      * Block cipher operations
      */
      const BlockCipher*
         prototype_block_cipher(const std::string& algo_spec,
                                const std::string& provider = "");

      BlockCipher* make_block_cipher(const std::string& algo_spec,
                                     const std::string& provider = "");

      void add_block_cipher(BlockCipher* hash, const std::string& provider);

      /*
      * Stream cipher operations
      */
      const StreamCipher*
         prototype_stream_cipher(const std::string& algo_spec,
                                 const std::string& provider = "");

      StreamCipher* make_stream_cipher(const std::string& algo_spec,
                                       const std::string& provider = "");

      void add_stream_cipher(StreamCipher* hash, const std::string& provider);

      /*
      * Hash function operations
      */
      const HashFunction*
         prototype_hash_function(const std::string& algo_spec,
                                 const std::string& provider = "");

      HashFunction* make_hash_function(const std::string& algo_spec,
                                       const std::string& provider = "");

      void add_hash_function(HashFunction* hash, const std::string& provider);

      /*
      * MAC operations
      */
      const MessageAuthenticationCode*
         prototype_mac(const std::string& algo_spec,
                       const std::string& provider = "");

      MessageAuthenticationCode* make_mac(const std::string& algo_spec,
                                          const std::string& provider = "");

      void add_mac(MessageAuthenticationCode* mac,
                   const std::string& provider);

      /*
      * Deprecated
      */
      class BOTAN_DLL Engine_Iterator
         {
         public:
            class Engine* next() { return af.get_engine_n(n++); }
            Engine_Iterator(const Algorithm_Factory& a) : af(a) { n = 0; }
         private:
            const Algorithm_Factory& af;
            u32bit n;
         };
      friend class Engine_Iterator;

   private:
      class Engine* get_engine_n(u32bit) const;

      std::vector<class Engine*> engines;

      Algorithm_Cache<BlockCipher>* block_cipher_cache;
      Algorithm_Cache<StreamCipher>* stream_cipher_cache;
      Algorithm_Cache<HashFunction>* hash_cache;
      Algorithm_Cache<MessageAuthenticationCode>* mac_cache;
   };

}

#endif
