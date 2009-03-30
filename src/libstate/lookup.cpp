/*
* Algorithm Retrieval
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/lookup.h>
#include <botan/libstate.h>
#include <botan/engine.h>

namespace Botan {

/**
* Acquire a block cipher
*/
const BlockCipher* retrieve_block_cipher(const std::string& algo_spec)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();
   return af.prototype_block_cipher(algo_spec);
   }

/**
* Get a block cipher by name
*/
BlockCipher* get_block_cipher(const std::string& algo_spec)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();
   return af.make_block_cipher(algo_spec);
   }

/**
* Acquire a stream cipher
*/
const StreamCipher* retrieve_stream_cipher(const std::string& algo_spec)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();
   return af.prototype_stream_cipher(algo_spec);
   }

/**
* Get a stream cipher by name
*/
StreamCipher* get_stream_cipher(const std::string& algo_spec)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();
   return af.make_stream_cipher(algo_spec);
   }

/**
* Acquire a hash function
*/
const HashFunction* retrieve_hash(const std::string& algo_spec)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();
   return af.prototype_hash_function(algo_spec);
   }

/**
* Get a hash function by name
*/
HashFunction* get_hash(const std::string& algo_spec)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();
   return af.make_hash_function(algo_spec);
   }

/**
* Query if Botan has the named hash function
*/
bool have_hash(const std::string& algo_spec)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();
   return af.prototype_hash_function(algo_spec);
   }

/**
* Acquire an authentication code
*/
const MessageAuthenticationCode* retrieve_mac(const std::string& algo_spec)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();
   return af.prototype_mac(algo_spec);
   }

/**
* Get a MAC by name
*/
MessageAuthenticationCode* get_mac(const std::string& algo_spec)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();
   return af.make_mac(algo_spec);
   }

/**
* Query if Botan has the named MAC
*/
bool have_mac(const std::string& algo_spec)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();
   return af.prototype_mac(algo_spec);
   }

/**
* Query if an algorithm exists
*/
bool have_algorithm(const std::string& name)
   {
   if(retrieve_block_cipher(name))
      return true;
   if(retrieve_stream_cipher(name))
      return true;
   if(retrieve_hash(name))
      return true;
   if(retrieve_mac(name))
      return true;
   return false;
   }

/**
* Query if Botan has the named block cipher
*/
bool have_block_cipher(const std::string& name)
   {
   return (retrieve_block_cipher(name) != 0);
   }

/**
* Query if Botan has the named stream cipher
*/
bool have_stream_cipher(const std::string& name)
   {
   return (retrieve_stream_cipher(name) != 0);
   }

/**
* Query the block size of a cipher or hash
*/
u32bit block_size_of(const std::string& name)
   {
   const BlockCipher* cipher = retrieve_block_cipher(name);
   if(cipher)
      return cipher->BLOCK_SIZE;

   const HashFunction* hash = retrieve_hash(name);
   if(hash)
      return hash->HASH_BLOCK_SIZE;

   throw Algorithm_Not_Found(name);
   }

/**
* Query the OUTPUT_LENGTH of a hash or MAC
*/
u32bit output_length_of(const std::string& name)
   {
   const HashFunction* hash = retrieve_hash(name);
   if(hash)
      return hash->OUTPUT_LENGTH;

   const MessageAuthenticationCode* mac = retrieve_mac(name);
   if(mac)
      return mac->OUTPUT_LENGTH;

   throw Algorithm_Not_Found(name);
   }

/**
* Check if a keylength is valid for this algo
*/
bool valid_keylength_for(u32bit key_len, const std::string& name)
   {
   const BlockCipher* bc = retrieve_block_cipher(name);
   if(bc)
      return bc->valid_keylength(key_len);

   const StreamCipher* sc = retrieve_stream_cipher(name);
   if(sc)
      return sc->valid_keylength(key_len);

   const MessageAuthenticationCode* mac = retrieve_mac(name);
   if(mac)
      return mac->valid_keylength(key_len);

   throw Algorithm_Not_Found(name);
   }

/**
* Query the MINIMUM_KEYLENGTH of an algorithm
*/
u32bit min_keylength_of(const std::string& name)
   {
   const BlockCipher* bc = retrieve_block_cipher(name);
   if(bc)
      return bc->MINIMUM_KEYLENGTH;

   const StreamCipher* sc = retrieve_stream_cipher(name);
   if(sc)
      return sc->MINIMUM_KEYLENGTH;

   const MessageAuthenticationCode* mac = retrieve_mac(name);
   if(mac)
      return mac->MINIMUM_KEYLENGTH;

   throw Algorithm_Not_Found(name);
   }

/**
* Query the MAXIMUM_KEYLENGTH of an algorithm
*/
u32bit max_keylength_of(const std::string& name)
   {
   const BlockCipher* bc = retrieve_block_cipher(name);
   if(bc)
      return bc->MAXIMUM_KEYLENGTH;

   const StreamCipher* sc = retrieve_stream_cipher(name);
   if(sc)
      return sc->MAXIMUM_KEYLENGTH;

   const MessageAuthenticationCode* mac = retrieve_mac(name);
   if(mac)
      return mac->MAXIMUM_KEYLENGTH;

   throw Algorithm_Not_Found(name);
   }

/**
* Query the KEYLENGTH_MULTIPLE of an algorithm
*/
u32bit keylength_multiple_of(const std::string& name)
   {
   const BlockCipher* bc = retrieve_block_cipher(name);
   if(bc)
      return bc->KEYLENGTH_MULTIPLE;

   const StreamCipher* sc = retrieve_stream_cipher(name);
   if(sc)
      return sc->KEYLENGTH_MULTIPLE;

   const MessageAuthenticationCode* mac = retrieve_mac(name);
   if(mac)
      return mac->KEYLENGTH_MULTIPLE;

   throw Algorithm_Not_Found(name);
   }

/**
* Get a cipher object
*/
Keyed_Filter* get_cipher(const std::string& algo_spec,
                         Cipher_Dir direction)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();

   Algorithm_Factory::Engine_Iterator i(af);

   while(Engine* engine = i.next())
      {
      Keyed_Filter* algo = engine->get_cipher(algo_spec, direction, af);
      if(algo)
         return algo;
      }

   throw Algorithm_Not_Found(algo_spec);
   }

/**
* Get a cipher object
*/
Keyed_Filter* get_cipher(const std::string& algo_spec,
                         const SymmetricKey& key,
                         const InitializationVector& iv,
                         Cipher_Dir direction)
   {
   Keyed_Filter* cipher = get_cipher(algo_spec, direction);
   cipher->set_key(key);

   if(iv.length())
      cipher->set_iv(iv);

   return cipher;
   }

/**
* Get a cipher object
*/
Keyed_Filter* get_cipher(const std::string& algo_spec,
                         const SymmetricKey& key,
                         Cipher_Dir direction)
   {
   return get_cipher(algo_spec,
                     key, InitializationVector(), direction);
   }

}
