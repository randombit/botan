/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PAKE_H_
#define BOTAN_PAKE_H_

#include <botan/types.h>

namespace Botan {

class PasswordAuthenticatedKeyExchange {
   public:
      enum class Role {
         Initiator,
         Responder
      };

      enum class Status {
         Initialized,
         Running,
         Completed,
      };

      static std::unique_ptr<PasswordAuthenticatedKeyExchange> create(std::string_view algo_name,
                                                                      std::string_view group_type,
                                                                      std::string_view hash_fn);

      virtual Status status() const = 0;

      virtual ~PasswordAuthenticatedKeyExchange() = default;

#if 0
      /**
      * Begin
      */
      virtual std::vector<uint8_t> begin(
         std::span<const uint8_t> our_ad,
         std::span<const uint8_t> their_ad) = 0;

      /**
      */
      virtual std::optional<std::vector<uint8_t>> step(std::span<const uint8_t> msg) = 0;
#endif
};

}  // namespace Botan

#endif
