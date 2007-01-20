/*************************************************
* Algorithm Retrieval Source File                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/lookup.h>

namespace Botan {

/*************************************************
* Get a block cipher by name                     *
*************************************************/
BlockCipher* get_block_cipher(const std::string& name)
   {
   const BlockCipher* cipher = retrieve_block_cipher(name);
   if(cipher)
      return cipher->clone();
   throw Algorithm_Not_Found(name);
   }

/*************************************************
* Get a stream cipher by name                    *
*************************************************/
StreamCipher* get_stream_cipher(const std::string& name)
   {
   const StreamCipher* cipher = retrieve_stream_cipher(name);
   if(cipher)
      return cipher->clone();
   throw Algorithm_Not_Found(name);
   }

/*************************************************
* Get a hash function by name                    *
*************************************************/
HashFunction* get_hash(const std::string& name)
   {
   const HashFunction* hash = retrieve_hash(name);
   if(hash)
      return hash->clone();
   throw Algorithm_Not_Found(name);
   }

/*************************************************
* Get a MAC by name                              *
*************************************************/
MessageAuthenticationCode* get_mac(const std::string& name)
   {
   const MessageAuthenticationCode* mac = retrieve_mac(name);
   if(mac)
      return mac->clone();
   throw Algorithm_Not_Found(name);
   }

/*************************************************
* Get a S2K algorithm by name                    *
*************************************************/
S2K* get_s2k(const std::string& name)
   {
   const S2K* s2k = retrieve_s2k(name);
   if(s2k)
      return s2k->clone();
   throw Algorithm_Not_Found(name);
   }

/*************************************************
* Get a block cipher padding method by name      *
*************************************************/
const BlockCipherModePaddingMethod* get_bc_pad(const std::string& name)
   {
   const BlockCipherModePaddingMethod* pad = retrieve_bc_pad(name);
   if(pad)
      return pad;
   throw Algorithm_Not_Found(name);
   }

/*************************************************
* Query if an algorithm exists                   *
*************************************************/
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

/*************************************************
* Query if Botan has the named block cipher      *
*************************************************/
bool have_block_cipher(const std::string& name)
   {
   return (retrieve_block_cipher(name) != 0);
   }

/*************************************************
* Query if Botan has the named stream cipher     *
*************************************************/
bool have_stream_cipher(const std::string& name)
   {
   return (retrieve_stream_cipher(name) != 0);
   }

/*************************************************
* Query if Botan has the named hash function     *
*************************************************/
bool have_hash(const std::string& name)
   {
   return (retrieve_hash(name) != 0);
   }

/*************************************************
* Query if Botan has the named MAC               *
*************************************************/
bool have_mac(const std::string& name)
   {
   return (retrieve_mac(name) != 0);
   }

/*************************************************
* Query the block size of a cipher or hash       *
*************************************************/
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

/*************************************************
* Query the OUTPUT_LENGTH of a hash or MAC       *
*************************************************/
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

/*************************************************
* Check if a keylength is valid for this algo    *
*************************************************/
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

/*************************************************
* Query the MINIMUM_KEYLENGTH of an algorithm    *
*************************************************/
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

/*************************************************
* Query the MAXIMUM_KEYLENGTH of an algorithm    *
*************************************************/
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

/*************************************************
* Query the KEYLENGTH_MULTIPLE of an algorithm   *
*************************************************/
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

}
