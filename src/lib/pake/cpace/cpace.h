/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PAKE_CPACE_H_
#define BOTAN_PAKE_CPACE_H_

#include <botan/pake.h>
#include <botan/ec_group.h>
#include <memory>
#include <optional>

namespace Botan {

class HashFunction;

class PAKE_Cpace final : public PasswordAuthenticatedKeyExchange {
   public:
      PAKE_Cpace(std::string_view group_id, std::string_view hash_fn);

      ~PAKE_Cpace();

      PasswordAuthenticatedKeyExchange::Status status() const override;

      std::vector<uint8_t>
      initiate(std::string_view password,
               std::span<const uint8_t> channel_id,
               std::span<const uint8_t> session_id,
               std::span<const uint8_t> assoc_a,
               std::span<const uint8_t> assoc_b);

      std::optional<std::vector<uint8_t>> step(std::span<const uint8_t> peer_message);

      std::vector<uint8_t> shared_secret() const;

   private:
      // pimpl this?
      std::unique_ptr<HashFunction> m_hash;
      EC_Group m_group;
      std::optional<EC_Point> m_generator;
      std::optional<BigInt> m_x;
};

}  // namespace Botan

#endif
