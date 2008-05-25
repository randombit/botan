/*************************************************
* Algorithm Retrieval Source File                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/lookup.h>

namespace Botan {

/*************************************************
* Get a block cipher by name                     *
*************************************************/
std::auto_ptr<BlockCipher> get_block_cipher(const std::string& name)
   {
   std::tr1::shared_ptr<BlockCipher const> cipher = retrieve_block_cipher(name);
   if(cipher.get())
      return cipher->clone();
   throw Algorithm_Not_Found(name);
   }

/*************************************************
* Get a stream cipher by name                    *
*************************************************/
std::auto_ptr<StreamCipher> get_stream_cipher(const std::string& name)
   {
   std::tr1::shared_ptr<StreamCipher const> cipher = retrieve_stream_cipher(name);
   if(cipher.get())
      return cipher->clone();
   throw Algorithm_Not_Found(name);
   }

/*************************************************
* Get a hash function by name                    *
*************************************************/
std::auto_ptr<HashFunction> get_hash(const std::string& name)
   {
   std::tr1::shared_ptr<HashFunction const> hash = retrieve_hash(name);
   if(hash.get())
      return hash->clone();
   throw Algorithm_Not_Found(name);
   }

/*************************************************
* Get a MAC by name                              *
*************************************************/
std::auto_ptr<MessageAuthenticationCode> get_mac(const std::string& name)
   {
   std::tr1::shared_ptr<MessageAuthenticationCode const> mac = retrieve_mac(name);
   if(mac.get())
      return mac->clone();
   throw Algorithm_Not_Found(name);
   }

/*************************************************
* Get a S2K algorithm by name                    *
*************************************************/
std::auto_ptr<S2K> get_s2k(const std::string& name)
   {
   std::tr1::shared_ptr<S2K const> s2k = retrieve_s2k(name);
   if(s2k.get())
      return s2k->clone();
   throw Algorithm_Not_Found(name);
   }
/*************************************************
* Get a block cipher padding method by name      *
*************************************************/
std::tr1::shared_ptr<BlockCipherModePaddingMethod const> get_bc_pad(const std::string& name)
   {
   std::tr1::shared_ptr<BlockCipherModePaddingMethod const> pad = retrieve_bc_pad(name);
   if(pad.get())
      return pad;
   throw Algorithm_Not_Found(name);
   }

/*************************************************
* Query if an algorithm exists                   *
*************************************************/
bool have_algorithm(const std::string& name)
   {
   if(retrieve_block_cipher(name).get())
      return true;
   if(retrieve_stream_cipher(name).get())
      return true;
   if(retrieve_hash(name).get())
      return true;
   if(retrieve_mac(name).get())
      return true;
   return false;
   }

/*************************************************
* Query if Botan has the named block cipher      *
*************************************************/
bool have_block_cipher(const std::string& name)
   {
   return (retrieve_block_cipher(name).get() != 0);
   }

/*************************************************
* Query if Botan has the named stream cipher     *
*************************************************/
bool have_stream_cipher(const std::string& name)
   {
   return (retrieve_stream_cipher(name).get() != 0);
   }

/*************************************************
* Query if Botan has the named hash function     *
*************************************************/
bool have_hash(const std::string& name)
   {
   return (retrieve_hash(name).get() != 0);
   }

/*************************************************
* Query if Botan has the named MAC               *
*************************************************/
bool have_mac(const std::string& name)
   {
   return (retrieve_mac(name).get() != 0);
   }

/*************************************************
* Query the block size of a cipher or hash       *
*************************************************/
u32bit block_size_of(const std::string& name)
   {
   std::tr1::shared_ptr<BlockCipher const> cipher = retrieve_block_cipher(name);
   if(cipher.get())
      return cipher->BLOCK_SIZE;

   std::tr1::shared_ptr<HashFunction const> hash = retrieve_hash(name);
   if(hash.get())
      return hash->HASH_BLOCK_SIZE;

   throw Algorithm_Not_Found(name);
   }

/*************************************************
* Query the OUTPUT_LENGTH of a hash or MAC       *
*************************************************/
u32bit output_length_of(const std::string& name)
   {
   std::tr1::shared_ptr<HashFunction const> hash = retrieve_hash(name);
   if(hash.get())
      return hash->OUTPUT_LENGTH;

   std::tr1::shared_ptr<MessageAuthenticationCode const> mac = retrieve_mac(name);
   if(mac.get())
      return mac->OUTPUT_LENGTH;

   throw Algorithm_Not_Found(name);
   }

/*************************************************
* Check if a keylength is valid for this algo    *
*************************************************/
bool valid_keylength_for(u32bit key_len, const std::string& name)
   {
   std::tr1::shared_ptr<BlockCipher const> bc = retrieve_block_cipher(name);
   if(bc.get())
      return bc->valid_keylength(key_len);

   std::tr1::shared_ptr<StreamCipher const> sc = retrieve_stream_cipher(name);
   if(sc.get())
      return sc->valid_keylength(key_len);

   std::tr1::shared_ptr<MessageAuthenticationCode const> mac = retrieve_mac(name);
   if(mac.get())
      return mac->valid_keylength(key_len);

   throw Algorithm_Not_Found(name);
   }

/*************************************************
* Query the MINIMUM_KEYLENGTH of an algorithm    *
*************************************************/
u32bit min_keylength_of(const std::string& name)
   {
   std::tr1::shared_ptr<BlockCipher const> bc = retrieve_block_cipher(name);
   if(bc.get())
      return bc->MINIMUM_KEYLENGTH;

   std::tr1::shared_ptr<StreamCipher const> sc = retrieve_stream_cipher(name);
   if(sc.get())
      return sc->MINIMUM_KEYLENGTH;

   std::tr1::shared_ptr<MessageAuthenticationCode const> mac = retrieve_mac(name);
   if(mac.get())
      return mac->MINIMUM_KEYLENGTH;

   throw Algorithm_Not_Found(name);
   }

/*************************************************
* Query the MAXIMUM_KEYLENGTH of an algorithm    *
*************************************************/
u32bit max_keylength_of(const std::string& name)
   {
   std::tr1::shared_ptr<BlockCipher const> bc = retrieve_block_cipher(name);
   if(bc.get())
      return bc->MAXIMUM_KEYLENGTH;

   std::tr1::shared_ptr<StreamCipher const> sc = retrieve_stream_cipher(name);
   if(sc.get())
      return sc->MAXIMUM_KEYLENGTH;

   std::tr1::shared_ptr<MessageAuthenticationCode const> mac = retrieve_mac(name);
   if(mac.get())
      return mac->MAXIMUM_KEYLENGTH;

   throw Algorithm_Not_Found(name);
   }

/*************************************************
* Query the KEYLENGTH_MULTIPLE of an algorithm   *
*************************************************/
u32bit keylength_multiple_of(const std::string& name)
   {
   std::tr1::shared_ptr<BlockCipher const> bc = retrieve_block_cipher(name);
   if(bc.get())
      return bc->KEYLENGTH_MULTIPLE;

   std::tr1::shared_ptr<StreamCipher const> sc = retrieve_stream_cipher(name);
   if(sc.get())
      return sc->KEYLENGTH_MULTIPLE;

   std::tr1::shared_ptr<MessageAuthenticationCode const> mac = retrieve_mac(name);
   if(mac.get())
      return mac->KEYLENGTH_MULTIPLE;

   throw Algorithm_Not_Found(name);
   }

}
