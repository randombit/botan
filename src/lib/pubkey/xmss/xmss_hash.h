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

class XMSS_Parameters;

/**
 * A collection of pseudorandom hash functions required for XMSS and WOTS
 * computations.
 **/
class XMSS_Hash final {
   public:
      XMSS_Hash(const XMSS_Parameters& params);

      XMSS_Hash(const XMSS_Hash& hash);
      XMSS_Hash(XMSS_Hash&& hash) = default;
      ~XMSS_Hash() = default;

      XMSS_Hash& operator=(const XMSS_Hash&) = delete;
      XMSS_Hash& operator=(XMSS_Hash&&) = default;

      std::string hash_function() const { return m_hash->name(); }

   private:
      inline void calculate_hash(const uint8_t hash_id,
                                 secure_vector<uint8_t>& result,
                                 std::span<const uint8_t> key,
                                 std::span<const uint8_t> data) {
         m_hash->update(m_zero_padding);
         m_hash->update(hash_id);
         m_hash->update(key.data(), key.size());
         m_hash->update(data.data(), data.size());
         m_hash->final(result);
      }

   public:
      /**
       * Pseudorandom function creating a hash out of a key and data using
       * a cryptographic hash function.
       *
       * @param[out] result The hash calculated using key and data.
       * @param[in] key An n-byte key value.
       * @param[in] data A 32-byte XMSS_Address data value
       **/
      inline void prf(secure_vector<uint8_t>& result, std::span<const uint8_t> key, std::span<const uint8_t> data) {
         calculate_hash(0x03, result, key, data);
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
                             std::span<const uint8_t> data) {
         calculate_hash(0x04, result, key, data);
      }

      /**
       * F is a keyed cryptographic hash function used by the WOTS+ algorithm.
       *
       * @param[out] result The hash calculated using key and data.
       * @param[in] key key of length n bytes.
       * @param[in] data string of arbitrary length.
       **/
      void f(secure_vector<uint8_t>& result, std::span<const uint8_t> key, std::span<const uint8_t> data) {
         calculate_hash(0x00, result, key, data);
      }

      /**
       * Cryptographic hash function h accepting n byte keys and 2n byte
       * strings of data.
       *
       * @param[out] result The hash calculated using key and data.
       * @param[in] key key of length n bytes.
       * @param[in] data string of 2n bytes length.
       **/
      void h(secure_vector<uint8_t>& result, std::span<const uint8_t> key, std::span<const uint8_t> data) {
         calculate_hash(0x01, result, key, data);
      }

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
      secure_vector<uint8_t> h_msg(std::span<const uint8_t> randomness,
                                   std::span<const uint8_t> root,
                                   std::span<const uint8_t> index_bytes,
                                   std::span<const uint8_t> data) {
         h_msg_init(randomness, root, index_bytes);
         h_msg_update(data);
         return m_msg_hash->final();
      }

      /**
       * Initializes buffered h_msg computation with prefix data.
       *
       * @param randomness random n-byte value.
       * @param root n-byte root node.
       * @param index_bytes Index value padded with leading zeros.
       **/
      void h_msg_init(std::span<const uint8_t> randomness,
                      std::span<const uint8_t> root,
                      std::span<const uint8_t> index_bytes);

      /**
       * Adds a message block to buffered h_msg computation.
       *
       * @param data A message block
       **/
      void h_msg_update(std::span<const uint8_t> data);

      /**
       * Finalizes buffered h_msg computation and retrieves the result.
       *
       * @return Hash calculated using the prefix set by h_msg_init() and
       *         message blocks provided through calls to h_msg_update().
       **/
      secure_vector<uint8_t> h_msg_final();

      size_t output_length() const { return m_hash->output_length(); }

   private:
      std::unique_ptr<HashFunction> m_hash;
      std::unique_ptr<HashFunction> m_msg_hash;

      /// Hash id prefixes (for domain separation) prepended to the hash input
      /// are big-endian representations with `hash_id_length` bytes. See the
      /// definition of the `toByte` function in RFC 8391 and truncated hash
      /// parameter sets in NIST SP-800-208.
      std::vector<uint8_t> m_zero_padding;
};

}  // namespace Botan

#endif
