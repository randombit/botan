/*
 * XMSS Hash
 * (C) 2016,2017 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_XMSS_HASH_H_
#define BOTAN_XMSS_HASH_H_

#include <botan/hash.h>

#include <span>

namespace Botan {

/**
 * A collection of pseudorandom hash functions required for XMSS and WOTS
 * computations.
 **/
class XMSS_Hash final
   {
   public:
      XMSS_Hash(const std::string& h_func_name);
      XMSS_Hash(const XMSS_Hash& hash);

      /**
       * Pseudorandom function creating a hash out of a key and data using
       * a cryptographic hash function.
       *
       * @param[out] result The hash calculated using key and data.
       * @param[in] key An n-byte key value.
       * @param[in] data A 32-byte XMSS_Address data value
       **/
      inline void prf(secure_vector<uint8_t>& result,
                      std::span<const uint8_t> key,
                      std::span<const uint8_t> data)
         {
         m_hash->update(m_zero_padding);
         m_hash->update(m_id_prf);
         m_hash->update(key.data(), key.size());
         m_hash->update(data.data(), data.size());
         m_hash->final(result);
         }

      /**
       * Pseudorandom function creating a hash out of a key and data using
       * a cryptographic hash function.
       *
       * @param[in] key An n-byte key value.
       * @param[in] data A 32-byte XMSS_Address data value
       * @return result The hash calculated using key and data.
       **/
      inline secure_vector<uint8_t> prf(std::span<const uint8_t> key,
                                        std::span<const uint8_t> data)
         {
         m_hash->update(m_zero_padding);
         m_hash->update(m_id_prf);
         m_hash->update(key.data(), key.size());
         m_hash->update(data.data(), data.size());
         return m_hash->final();
         }

      /**
       * Pseudoranom function creating a hash out of a key and data using
       * a cryptographic hash function for key derivation.
       *
       * This function is described in NIST SP.800-208 Section 6.2 as a
       * separate PRF to avoid a multi-target attack vector.
       *
       * @param[in] key An n-byte key value.
       * @param[in] data A 32-byte XMSS_Address data value
       * @return result The hash calculated using key and data.
       **/
      inline secure_vector<uint8_t> prf_keygen(std::span<const uint8_t> key,
                                               std::span<const uint8_t> data)
         {
         secure_vector<uint8_t> result;
         m_hash->update(m_zero_padding);
         m_hash->update(m_id_prf_keygen);
         m_hash->update(key.data(), key.size());
         m_hash->update(data.data(), data.size());
         return m_hash->final();
         }

      /**
       * Pseudoranom function creating a hash out of a key and data using
       * a cryptographic hash function for key derivation.
       *
       * This function is described in NIST SP.800-208 Section 5 as a
       * separate PRF to avoid a multi-target attack vector.
       *
       * @param[out] result The hash calculated using key and data.
       * @param[in] key An n-byte key value.
       * @param[in] data A 32-byte XMSS_Address data value
       **/
      inline void prf_keygen(secure_vector<uint8_t>& result,
                             std::span<const uint8_t> key,
                             std::span<const uint8_t> data)
         {
         m_hash->update(m_zero_padding);
         m_hash->update(m_id_prf_keygen);
         m_hash->update(key.data(), key.size());
         m_hash->update(data.data(), data.size());
         m_hash->final(result);
         }

      /**
       * F is a keyed cryptographic hash function used by the WOTS+ algorithm.
       *
       * @param[out] result The hash calculated using key and data.
       * @param[in] key key of length n bytes.
       * @param[in] data string of arbitrary length.
       **/
      void f(secure_vector<uint8_t>& result,
             std::span<const uint8_t> key,
             std::span<const uint8_t> data)
         {
         m_hash->update(m_zero_padding);
         m_hash->update(m_id_f);
         m_hash->update(key.data(), key.size());
         m_hash->update(data.data(), data.size());
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
      void h(secure_vector<uint8_t>& result,
             const secure_vector<uint8_t>& key,
             const secure_vector<uint8_t>& data);

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
      secure_vector<uint8_t> h_msg(const secure_vector<uint8_t>& randomness,
                                   const secure_vector<uint8_t>& root,
                                   const secure_vector<uint8_t>& index_bytes,
                                   const secure_vector<uint8_t>& data);

      /**
       * Initializes buffered h_msg computation with prefix data.
       *
       * @param randomness random n-byte value.
       * @param root n-byte root node.
       * @param index_bytes Index value padded with leading zeros.
       **/
      void h_msg_init(const secure_vector<uint8_t>& randomness,
                      const secure_vector<uint8_t>& root,
                      const secure_vector<uint8_t>& index_bytes);

      /**
       * Adds a message block to buffered h_msg computation.
       *
       * @param data A message block
       * @param size Length of the message block in bytes.
       **/
      void h_msg_update(const uint8_t data[], size_t size);

      /**
       * Finalizes buffered h_msg computation and retrieves the result.
       *
       * @return Hash calculated using the prefix set by h_msg_init() and
       *         message blocks provided through calls to h_msg_update().
       **/
      secure_vector<uint8_t> h_msg_final();

      size_t output_length() const { return m_output_length; }

   private:
      static const uint8_t m_id_f = 0x00;
      static const uint8_t m_id_h = 0x01;
      static const uint8_t m_id_hmsg = 0x02;
      static const uint8_t m_id_prf = 0x03;
      static const uint8_t m_id_prf_keygen = 0x04;

      std::unique_ptr<HashFunction> m_hash;
      std::unique_ptr<HashFunction> m_msg_hash;
      //32 byte id prefixes prepended to the hash input.
      std::vector<uint8_t> m_zero_padding;
      size_t m_output_length;
      const std::string m_hash_func_name;

   };

}

#endif
