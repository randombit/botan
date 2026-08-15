/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HASH_ENGINE_H_
#define BOTAN_HASH_ENGINE_H_

#include <botan/secmem.h>
#include <botan/types.h>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Botan {

class BOTAN_TEST_API Hash_Engine {
   public:
      /**
      * @return name of the hash
      */
      virtual std::string name() const = 0;

      /**
      * @return provider of the engine (eg "base", "avx2", "avx512")
      */
      virtual std::string provider() const = 0;

      /**
      * @return output length of the hash function
      */
      virtual size_t output_length() const = 0;

      /**
      * @return native parallelism of this implementation
      */
      virtual size_t parallelism() const = 0;

      /**
      * Hash many inputs
      *
      * Computes H(common_prefix || inputs[i]) into outputs[i]. Each input
      * must be exactly identical length.
      *
      * outputs[i] may alias inputs[i], but must not otherwise overlap any
      * other input or output.
      */
      void batch_hash(std::span<std::span<uint8_t>> outputs, std::span<std::span<const uint8_t>> inputs) {
         batch_hash(outputs, inputs, {});
      }

      /**
      * Hash many inputs, each formed from two parts
      *
      * Computes H(common_prefix || inputs1[i] || inputs2[i]) into
      * outputs[i]. All inputs1 must be exactly identical length, as must all
      * inputs2. Alternately inputs2 may be an empty list.
      *
      * outputs[i] may alias inputs1[i] and/or inputs2[i], but must not
      * otherwise overlap any other input or output.
      */
      virtual void batch_hash(std::span<std::span<uint8_t>> outputs,
                              std::span<std::span<const uint8_t>> inputs1,
                              std::span<std::span<const uint8_t>> inputs2) = 0;

      /**
      * Create a new Hash_Engine
      *
      * @param hash_fn the hash function to compute
      * @param common_prefix implicitly prepended to each message hashed;
      *        implementations may precompute the resulting hash state
      * @param provider if set, use this specific implementation
      *
      * Throws Lookup_Error if the hash function or requested provider is
      * not available
      */
      static std::unique_ptr<Hash_Engine> create_or_throw(std::string_view hash_fn,
                                                          std::span<const uint8_t> common_prefix = {},
                                                          std::string_view provider = "");

      /**
      * Create a new Hash_Engine
      *
      * @param hash_fn the hash function to compute
      * @param common_prefix implicitly prepended to each message hashed;
      *        implementations may precompute the resulting hash state
      * @param provider if set, use this specific implementation
      * @return new object or nullptr if not available
      */
      static std::unique_ptr<Hash_Engine> create_or_null(std::string_view hash_fn,
                                                         std::span<const uint8_t> common_prefix = {},
                                                         std::string_view provider = "");

      /**
      * Return a list of possible providers for this hash function
      */
      static std::vector<std::string> possible_providers(std::string_view hash_fn);

      Hash_Engine(const Hash_Engine& other) = delete;
      Hash_Engine(Hash_Engine&& other) = delete;

      Hash_Engine& operator=(const Hash_Engine& other) = delete;
      Hash_Engine& operator=(Hash_Engine&& other) = delete;

      virtual ~Hash_Engine() = default;

   protected:
      explicit Hash_Engine(std::span<const uint8_t> common_prefix) :
            m_common_prefix(common_prefix.begin(), common_prefix.end()) {}

      /**
      * @return the prefix implicitly prepended to each message
      */
      std::span<const uint8_t> common_prefix() const { return m_common_prefix; }

      /**
      * Verify the batch_hash argument contract, throwing Invalid_Argument
      * if violated
      */
      void check_batch_args(std::span<std::span<uint8_t>> outputs,
                            std::span<std::span<const uint8_t>> inputs1,
                            std::span<std::span<const uint8_t>> inputs2) const;

   private:
      secure_vector<uint8_t> m_common_prefix;
};

}  // namespace Botan

#endif
