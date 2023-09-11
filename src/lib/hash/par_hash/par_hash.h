/*
* Parallel Hash
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PARALLEL_HASH_H_
#define BOTAN_PARALLEL_HASH_H_

#include <botan/hash.h>
#include <vector>

namespace Botan {

/**
* Parallel Hashes
*/
class Parallel final : public HashFunction {
   public:
      void clear() override;
      std::string name() const override;
      std::unique_ptr<HashFunction> new_object() const override;
      std::unique_ptr<HashFunction> copy_state() const override;

      size_t output_length() const override;

      /**
      * @param hashes a set of hashes to compute in parallel
      * Takes ownership of all pointers
      */
      explicit Parallel(std::vector<std::unique_ptr<HashFunction>>& hashes);

      Parallel(const Parallel&) = delete;
      Parallel& operator=(const Parallel&) = delete;

   private:
      void add_data(std::span<const uint8_t>) override;
      void final_result(std::span<uint8_t>) override;

      std::vector<std::unique_ptr<HashFunction>> m_hashes;
};

}  // namespace Botan

#endif
