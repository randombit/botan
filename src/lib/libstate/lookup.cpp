/*
* Algorithm Retrieval
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/lookup.h>
#include <botan/cipher_mode.h>
#include <botan/filters.h>
#include <botan/libstate.h>
#include <botan/parsing.h>
#include <botan/transform_filter.h>

#if defined(BOTAN_HAS_OFB)
  #include <botan/ofb.h>
#endif

#if defined(BOTAN_HAS_CTR_BE)
  #include <botan/ctr.h>
#endif

namespace Botan {

/*
* Get a PBKDF algorithm by name
*/
PBKDF* get_pbkdf(const std::string& algo_spec)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();

   if(PBKDF* pbkdf = af.make_pbkdf(algo_spec))
      return pbkdf;

   throw Algorithm_Not_Found(algo_spec);
   }

/*
* Query if an algorithm exists
*/
bool have_algorithm(const std::string& name)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();

   if(af.prototype_block_cipher(name))
      return true;
   if(af.prototype_stream_cipher(name))
      return true;
   if(af.prototype_hash_function(name))
      return true;
   if(af.prototype_mac(name))
      return true;
   return false;
   }

/*
* Query the block size of a cipher or hash
*/
size_t block_size_of(const std::string& name)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();

   if(const BlockCipher* cipher = af.prototype_block_cipher(name))
      return cipher->block_size();

   if(const HashFunction* hash = af.prototype_hash_function(name))
      return hash->hash_block_size();

   throw Algorithm_Not_Found(name);
   }

/*
* Query the output_length() of a hash or MAC
*/
size_t output_length_of(const std::string& name)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();

   if(const HashFunction* hash = af.prototype_hash_function(name))
      return hash->output_length();

   if(const MessageAuthenticationCode* mac = af.prototype_mac(name))
      return mac->output_length();

   throw Algorithm_Not_Found(name);
   }

/*
* Get a cipher object
*/
Keyed_Filter* get_cipher(const std::string& algo_spec,
                         Cipher_Dir direction)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();

   std::unique_ptr<Cipher_Mode> c(get_cipher_mode(algo_spec, direction));
   if(c)
      return new Transform_Filter(c.release());

   std::vector<std::string> algo_parts = split_on(algo_spec, '/');
   if(algo_parts.empty())
      throw Invalid_Algorithm_Name(algo_spec);

   const std::string cipher_name = algo_parts[0];

   // check if it is a stream cipher first (easy case)
   const StreamCipher* stream_cipher = af.prototype_stream_cipher(cipher_name);
   if(stream_cipher)
      return new StreamCipher_Filter(stream_cipher->clone());

   const BlockCipher* block_cipher = af.prototype_block_cipher(cipher_name);
   if(!block_cipher)
      return nullptr;

   if(algo_parts.size() >= 4)
      return nullptr; // 4 part mode, not something we know about

   if(algo_parts.size() < 2)
      throw Lookup_Error("Cipher specification '" + algo_spec +
                         "' is missing mode identifier");

   const std::string mode = algo_parts[1];


#if defined(BOTAN_HAS_OFB)
   if(mode == "OFB")
      return new StreamCipher_Filter(new OFB(block_cipher->clone()));
#endif

#if defined(BOTAN_HAS_CTR_BE)
   if(mode == "CTR-BE")
      return new StreamCipher_Filter(new CTR_BE(block_cipher->clone()));
#endif

   throw Algorithm_Not_Found(algo_spec);
   }

/*
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

/*
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
