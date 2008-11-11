/**
* Algorithm Factory
* (C) 2008 Jack Lloyd
*/

#ifndef BOTAN_ALGORITHM_FACTORY_H__
#define BOTAN_ALGORITHM_FACTORY_H__

#include <botan/algo_cache.h>
#include <botan/scan_name.h>
#include <botan/mutex.h>
#include <string>
#include <vector>
#include <map>

namespace Botan {

/**
* Forward declarations (don't need full definitions here)
*/
class BlockCipher;
class StreamCipher;
class HashFunction;
class MessageAuthenticationCode;

/**
* Algorithm Factory
*/
class BOTAN_DLL Algorithm_Factory
   {
   public:
      Algorithm_Factory(Mutex_Factory& mf);
      ~Algorithm_Factory();

      void add_engine(class Engine*);

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

      std::vector<std::string> providers_of(const std::string& algo_spec);

      // Block cipher operations
      const BlockCipher* prototype_block_cipher(const SCAN_Name& request);
      BlockCipher* make_block_cipher(const SCAN_Name& request);
      void add_block_cipher(BlockCipher* hash, const std::string& provider);

      // Stream cipher operations
      const StreamCipher* prototype_stream_cipher(const SCAN_Name& request);
      StreamCipher* make_stream_cipher(const SCAN_Name& request);
      void add_stream_cipher(StreamCipher* hash, const std::string& provider);

      // Hash function operations
      const HashFunction* prototype_hash_function(const SCAN_Name& request);
      HashFunction* make_hash_function(const SCAN_Name& request);
      void add_hash_function(HashFunction* hash, const std::string& provider);

      // MAC operations
      const MessageAuthenticationCode* prototype_mac(const SCAN_Name& request);
      MessageAuthenticationCode* make_mac(const SCAN_Name& request);
      void add_mac(MessageAuthenticationCode* mac,
                   const std::string& provider);
   private:
      class Engine* get_engine_n(u32bit) const;

      std::vector<class Engine*> engines;

      Algorithm_Cache<BlockCipher> block_cipher_cache;
      Algorithm_Cache<StreamCipher> stream_cipher_cache;
      Algorithm_Cache<HashFunction> hash_cache;
      Algorithm_Cache<MessageAuthenticationCode> mac_cache;
   };

}

#endif
