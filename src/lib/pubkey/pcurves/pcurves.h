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
         /// P-256 aka secp256r1
         P256,
         /// P-384 aka secp384r1
         P384,
         /// P-521 aka secp521r1
         P521,
      };

      using enum Id;

      Id code() const { return m_id; }

      PrimeOrderCurveId(Id id) : m_id(id) {}

      /// Map a string to a curve identifier
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

}  // namespace Botan::PCurve

#endif
