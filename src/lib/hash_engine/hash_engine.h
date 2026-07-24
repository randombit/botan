/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HASH_ENGINE_H_
#define BOTAN_HASH_ENGINE_H_

#include <botan/types.h>
#include <memory>
#include <span>
#include <string>

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
      * Each message must be exactly identical length
      */
      virtual void batch_hash(std::span<std::span<uint8_t>> outputs, std::span<std::span<const uint8_t>> inputs) = 0;

      /**
      * Create a new Hash_Engine or throw Not_Implemented
      */
      static std::unique_ptr<Hash_Engine> create_or_throw(std::string_view hash_fn);

      Hash_Engine(const Hash_Engine& other) = delete;
      Hash_Engine(Hash_Engine&& other) = delete;

      Hash_Engine& operator=(const Hash_Engine& other) = delete;
      Hash_Engine& operator=(Hash_Engine&& other) = delete;

      virtual ~Hash_Engine() = default;

   protected:
      Hash_Engine() = default;
};

}  // namespace Botan

#endif
