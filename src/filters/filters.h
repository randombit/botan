/*
* Filters
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_FILTERS_H__
#define BOTAN_FILTERS_H__

#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/hash.h>
#include <botan/mac.h>

#include <botan/pipe.h>
#include <botan/basefilt.h>
#include <botan/key_filt.h>
#include <botan/data_snk.h>

#include <botan/scan_name.h>

#if defined(BOTAN_HAS_BASE64_CODEC)
  #include <botan/base64.h>
#endif

#if defined(BOTAN_HAS_HEX_CODEC)
  #include <botan/hex.h>
#endif

namespace Botan {

/**
* Stream Cipher Filter.
*/
class BOTAN_DLL StreamCipher_Filter : public Keyed_Filter
   {
   public:

      /**
      * Write input data
      * @param input data
      * @param input_len length of input in bytes
      */
      void write(const byte input[], u32bit input_len);

      bool valid_iv_length(u32bit iv_len)
         { return cipher->valid_iv_length(iv_len); }

      /**
      * Set the initialization vector for this filter.
      * @param iv the initialization vector to set
      */
      void set_iv(const InitializationVector& iv);

      /**
      * Set the key of this filter.
      * @param key the key to set
      */
      void set_key(const SymmetricKey& key) { cipher->set_key(key); }

      /**
      * Check whether a key length is valid for this filter.
      * @param length the key length to be checked for validity
      * @return true if the key length is valid, false otherwise
      */
      bool valid_keylength(u32bit length) const
         { return cipher->valid_keylength(length); }

      /**
      * Construct a stream cipher filter.
      * @param cipher_obj a cipher object to use
      */
      StreamCipher_Filter(StreamCipher* cipher_obj);

      /**
      * Construct a stream cipher filter.
      * @param cipher_obj a cipher object to use
      * @param key the key to use inside this filter
      */
      StreamCipher_Filter(StreamCipher* cipher_obj, const SymmetricKey& key);

      /**
      * Construct a stream cipher filter.
      * @param cipher the name of the desired cipher
      */
      StreamCipher_Filter(const std::string& cipher);

      /**
      * Construct a stream cipher filter.
      * @param cipher the name of the desired cipher
      * @param key the key to use inside this filter
      */
      StreamCipher_Filter(const std::string& cipher, const SymmetricKey& key);

      ~StreamCipher_Filter() { delete cipher; }
   private:
      SecureVector<byte> buffer;
      StreamCipher* cipher;
   };

/**
* Hash Filter.
*/
class BOTAN_DLL Hash_Filter : public Filter
   {
   public:
      void write(const byte input[], u32bit len) { hash->update(input, len); }
      void end_msg();

      /**
      * Construct a hash filter.
      * @param hash_fun the hash function to use
      * @param len the output length of this filter. Leave the default
      * value 0 if you want to use the full output of the hashfunction
      * hash. Otherwise, specify a smaller value here so that the
      * output of the hash algorithm will be cut off.
      */
      Hash_Filter(HashFunction* hash_fun, u32bit len = 0) :
         OUTPUT_LENGTH(len), hash(hash_fun) {}

      /**
      * Construct a hash filter.
      * @param request the name of the hash algorithm to use
      * @param len the output length of this filter. Leave the default
      * value 0 if you want to use the full output of the hashfunction
      * hash. Otherwise, specify a smaller value here so that the
      * output of the hash algorithm will be cut off.
      */
      Hash_Filter(const std::string& request, u32bit len = 0);

      ~Hash_Filter() { delete hash; }
   private:
      const u32bit OUTPUT_LENGTH;
      HashFunction* hash;
   };

/**
* MessageAuthenticationCode Filter.
*/
class BOTAN_DLL MAC_Filter : public Keyed_Filter
   {
   public:
      void write(const byte input[], u32bit len) { mac->update(input, len); }
      void end_msg();

      /**
      * Set the key of this filter.
      * @param key the key to set
      */
      void set_key(const SymmetricKey& key) { mac->set_key(key); }

      /**
      * Check whether a key length is valid for this filter.
      * @param length the key length to be checked for validity
      * @return true if the key length is valid, false otherwise
      */
      bool valid_keylength(u32bit length) const
         { return mac->valid_keylength(length); }

      /**
      * Construct a MAC filter. The MAC key will be left empty.
      * @param mac_obj the MAC to use
      * @param out_len the output length of this filter. Leave the default
      * value 0 if you want to use the full output of the
      * MAC. Otherwise, specify a smaller value here so that the
      * output of the MAC will be cut off.
      */
      MAC_Filter(MessageAuthenticationCode* mac_obj,
                 u32bit out_len = 0) : OUTPUT_LENGTH(out_len)
         {
         mac = mac_obj;
         }

      /**
      * Construct a MAC filter.
      * @param mac_obj the MAC to use
      * @param key the MAC key to use
      * @param out_len the output length of this filter. Leave the default
      * value 0 if you want to use the full output of the
      * MAC. Otherwise, specify a smaller value here so that the
      * output of the MAC will be cut off.
      */
      MAC_Filter(MessageAuthenticationCode* mac_obj,
                 const SymmetricKey& key,
                 u32bit out_len = 0) : OUTPUT_LENGTH(out_len)
         {
         mac = mac_obj;
         mac->set_key(key);
         }

      /**
      * Construct a MAC filter. The MAC key will be left empty.
      * @param mac the name of the MAC to use
      * @param len the output length of this filter. Leave the default
      * value 0 if you want to use the full output of the
      * MAC. Otherwise, specify a smaller value here so that the
      * output of the MAC will be cut off.
      */
      MAC_Filter(const std::string& mac, u32bit len = 0);

      /**
      * Construct a MAC filter.
      * @param mac the name of the MAC to use
      * @param key the MAC key to use
      * @param len the output length of this filter. Leave the default
      * value 0 if you want to use the full output of the
      * MAC. Otherwise, specify a smaller value here so that the
      * output of the MAC will be cut off.
      */
      MAC_Filter(const std::string& mac, const SymmetricKey& key,
                 u32bit len = 0);

      ~MAC_Filter() { delete mac; }
   private:
      const u32bit OUTPUT_LENGTH;
      MessageAuthenticationCode* mac;
   };

}

#endif
