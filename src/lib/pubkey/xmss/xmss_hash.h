/*
 * XMSS Hash
 * (C) 2016,2017 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_XMSS_HASH_H_
#define BOTAN_XMSS_HASH_H_

#include <botan/hash.h>
#include <botan/internal/hash_engine.h>

#include <algorithm>
#include <span>

namespace Botan {

class XMSS_Parameters;

/**
 * A collection of pseudorandom hash functions required for XMSS and WOTS
 * computations.
 **/
class XMSS_Hash final {
   public:
      explicit XMSS_Hash(const XMSS_Parameters& params);

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

      /**
       * Batched variant of prf with a shared key: outputs[i] = prf(key, data[i])
       **/
      void prf_batch(std::span<std::span<uint8_t>> outputs,
                     std::span<const uint8_t> key,
                     std::span<std::span<const uint8_t>> data) {
         keyed_engine(0x03, key, m_prf_engine).batch_hash(outputs, data);
      }

      /**
       * Batched variant of prf_keygen with a shared key: outputs[i] = prf_keygen(key, data[i])
       **/
      void prf_keygen_batch(std::span<std::span<uint8_t>> outputs,
                            std::span<const uint8_t> key,
                            std::span<std::span<const uint8_t>> data) {
         keyed_engine(0x04, key, m_prf_keygen_engine).batch_hash(outputs, data);
      }

      /**
       * Batched variant of f: outputs[i] = f(keys[i], data[i])
       **/
      void f_batch(std::span<std::span<uint8_t>> outputs,
                   std::span<std::span<const uint8_t>> keys,
                   std::span<std::span<const uint8_t>> data) {
         if(!m_f_engine) {
            std::vector<uint8_t> prefix(m_zero_padding);
            prefix.push_back(0x00);
            m_f_engine = Hash_Engine::create_or_throw(m_hash->name(), prefix);
         }
         m_f_engine->batch_hash(outputs, keys, data);
      }

      /**
       * Batched variant of h: outputs[i] = h(keys[i], data[i])
       **/
      void h_batch(std::span<std::span<uint8_t>> outputs,
                   std::span<std::span<const uint8_t>> keys,
                   std::span<std::span<const uint8_t>> data) {
         if(!m_h_engine) {
            std::vector<uint8_t> prefix(m_zero_padding);
            prefix.push_back(0x01);
            m_h_engine = Hash_Engine::create_or_throw(m_hash->name(), prefix);
         }
         m_h_engine->batch_hash(outputs, keys, data);
      }

      size_t output_length() const { return m_hash->output_length(); }

   private:
      /// A batch engine whose prefix bakes in the (usually fixed) key,
      /// making the prefix exactly one hash block for the n=32 parameter
      /// sets, which allows a precomputed midstate
      struct Keyed_Engine {
            secure_vector<uint8_t> key;
            std::unique_ptr<Hash_Engine> engine;
      };

      Hash_Engine& keyed_engine(uint8_t hash_id, std::span<const uint8_t> key, Keyed_Engine& slot) {
         if(!slot.engine || slot.key.size() != key.size() || !std::equal(key.begin(), key.end(), slot.key.begin())) {
            secure_vector<uint8_t> prefix(m_zero_padding.begin(), m_zero_padding.end());
            prefix.push_back(hash_id);
            prefix.insert(prefix.end(), key.begin(), key.end());
            slot.key.assign(key.begin(), key.end());
            slot.engine = Hash_Engine::create_or_throw(m_hash->name(), prefix);
         }
         return *slot.engine;
      }

      std::unique_ptr<HashFunction> m_hash;
      std::unique_ptr<HashFunction> m_msg_hash;

      /// Batch engines for prf, prf_keygen, f and h, created on first use.
      /// Note that these are not copied by the copy constructor.
      Keyed_Engine m_prf_engine;
      Keyed_Engine m_prf_keygen_engine;
      std::unique_ptr<Hash_Engine> m_f_engine;
      std::unique_ptr<Hash_Engine> m_h_engine;

      /// Hash id prefixes (for domain separation) prepended to the hash input
      /// are big-endian representations with `hash_id_length` bytes. See the
      /// definition of the `toByte` function in RFC 8391 and truncated hash
      /// parameter sets in NIST SP-800-208.
      std::vector<uint8_t> m_zero_padding;
};

}  // namespace Botan

#endif
