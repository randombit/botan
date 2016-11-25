/*
 * XMSS Hash
 * (C) 2016 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_XMSS_HASH_H__
#define BOTAN_XMSS_HASH_H__

#include <cstddef>
#include <string>
#include <botan/assert.h>
#include <botan/hash.h>
#include <botan/secmem.h>
#include <botan/types.h>

namespace Botan {

/**
 * A collection of pseudorandom hash functions required for XMSS and WOTS
 * computations.
 **/
class XMSS_Hash
   {
   public:
      XMSS_Hash(const std::string& h_func_name);
      XMSS_Hash(const XMSS_Hash& hash);

      /**
       * Pseudoranom function creating a hash out of a key and data using
       * a cryptographic hash function.
       *
       * @param[out] result The hash calculated using key and data.
       * @param[in] key An n-byte key value.
       * @param[in] data A 32-byte XMSS_Address data value
       **/
      inline void prf(secure_vector<byte>& result,
                      const secure_vector<byte>& key,
                      const secure_vector<byte>& data)
         {
         m_hash->update(m_zero_padding);
         m_hash->update(m_id_prf);
         m_hash->update(key);
         m_hash->update(data);
         m_hash->final(result);
         }

      /**
       * Pseudoranom function creating a hash out of a key and data using
       * a cryptographic hash function.
       *
       * @param[in] key An n-byte key value.
       * @param[in] data A 32-byte XMSS_Address data value
       * @return result The hash calculated using key and data.
       **/
      inline secure_vector<byte> prf(const secure_vector<byte>& key,
                                     const secure_vector<byte>& data)
         {
         m_hash->update(m_zero_padding);
         m_hash->update(m_id_prf);
         m_hash->update(key);
         m_hash->update(data);
         return m_hash->final();
         }

      /**
       * F is a keyed cryptographic hash function used by the WOTS+ algorithm.
       *
       * @param[out] result The hash calculated using key and data.
       * @param[in] key key of length n bytes.
       * @param[in] data string of arbitrary length.
       **/
      void f(secure_vector<byte>& result,
             const secure_vector<byte>& key,
             const secure_vector<byte>& data)
         {
         m_hash->update(m_zero_padding);
         m_hash->update(m_id_f);
         m_hash->update(key);
         m_hash->update(data);
         m_hash->final(result);
         }

      /**
       * Cryptographic hash function h accepting n byte keys and 2n byte
       * strings of data.
       *
       * @param[out] result The hash calculated using key and data.
       * @param[in] key key of length n bytes.
       * @param[in] data string of 2n bytes length.
       **/
      void h(secure_vector<byte>& result,
             const secure_vector<byte>& key,
             const secure_vector<byte>& data);

      /**
       * Cryptographic hash function h accepting 3n byte keys and data
       * strings of arbitrary length.
       *
       * @param randomness n-byte value.
       * @param root n-byte root node.
       * @param index_bytes Index value padded with leading zeros.
       * @param data string of arbitrary length.
       *
       * @return hash value of n-bytes length.
       **/
      secure_vector<byte> h_msg(const secure_vector<byte>& randomness,
                                const secure_vector<byte>& root,
                                const secure_vector<byte>& index_bytes,
                                const secure_vector<byte>& data);

      /**
       * Initializes buffered h_msg computation with prefix data.
       *
       * @param randomness random n-byte value.
       * @param root n-byte root node.
       * @param index_bytes Index value padded with leading zeros.
       **/
      void h_msg_init(const secure_vector<byte>& randomness,
                      const secure_vector<byte>& root,
                      const secure_vector<byte>& index_bytes);

      /**
       * Adds a message block to buffered h_msg computation.
       *
       * @param data A message block
       **/
      void h_msg_update(const secure_vector<byte>& data);

      /**
       * Adds a message block to buffered h_msg computation.
       *
       * @param data A message block
       * @param size Length of the message block in bytes.
       **/
      void h_msg_update(const byte data[], size_t size);

      /**
       * Finalizes buffered h_msg computation and retrieves the result.
       *
       * @return Hash calculated using the prefix set by h_msg_init() and
       *         message blocks provided through calls to h_msg_update().
       **/
      secure_vector<byte> h_msg_final();

      size_t output_length() const { return m_output_length; };

   private:
      static const byte m_id_f = 0x00;
      static const byte m_id_h = 0x01;
      static const byte m_id_hmsg = 0x02;
      static const byte m_id_prf = 0x03;

      const std::string m_hash_func_name;
      std::unique_ptr<HashFunction> m_hash;
      std::unique_ptr<HashFunction> m_msg_hash;
      size_t m_output_length;

      //32 byte id prefixes prepended to the hash input.
      std::vector<byte> m_zero_padding;
   };

}

#endif
