/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PCURVES_H_
#define BOTAN_PCURVES_H_

#include <botan/types.h>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace Botan {

class OID;

}

namespace Botan::PCurve {

/// Identifier for a named prime order curve
class PrimeOrderCurveId {
   public:
      enum class Id {
         /// secp256r1 aka P-256
         secp256r1,
         /// secp384r1 aka P-384
         secp384r1,
         /// secp521r1 aka P-521
         secp521r1,
         /// secp256k1
         secp256k1,
      };

      using enum Id;

      Id code() const { return m_id; }

      PrimeOrderCurveId(Id id) : m_id(id) {}

      /// Map a string to a curve identifier
      BOTAN_TEST_API
      static std::optional<PrimeOrderCurveId> from_string(std::string_view name);

      /// Map an OID to a curve identifier
      ///
      /// Uses the internal OID table
      static std::optional<PrimeOrderCurveId> from_oid(const OID& oid);

      std::string to_string() const;

   private:
      const Id m_id;
};

std::vector<uint8_t> hash_to_curve(PrimeOrderCurveId curve,
                                   std::string_view hash,
                                   bool random_oracle,
                                   std::span<const uint8_t> input,
                                   std::span<const uint8_t> domain_sep);

std::vector<uint8_t> BOTAN_TEST_API mul_by_g(PrimeOrderCurveId curve, std::span<const uint8_t> scalar);

}  // namespace Botan::PCurve

#endif
