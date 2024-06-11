/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PCURVES_ID_H_
#define BOTAN_PCURVES_ID_H_

#include <botan/secmem.h>
#include <botan/types.h>
#include <optional>
#include <string_view>
#include <vector>

namespace Botan {

#if defined(BOTAN_HAS_ASN1)
class OID;
#endif

}  // namespace Botan

namespace Botan::PCurve {

/// Identifier for a named prime order curve
class BOTAN_TEST_API PrimeOrderCurveId final {
   public:
      enum class Code : uint8_t {
         /// secp256r1 aka P-256
         secp256r1,
         /// secp384r1 aka P-384
         secp384r1,
         /// secp521r1 aka P-521
         secp521r1,
         /// secp256k1
         secp256k1,
         /// brainpool256r1
         brainpool256r1,
         brainpool384r1,
         brainpool512r1,
         frp256v1,
         sm2p256v1,
      };

      using enum Code;

      Code code() const { return m_code; }

      /// Return a list of all of the defined PrimeOrderCurveId
      ///
      /// Note this list always includes all curves, even if some were
      /// disabled at build time.
      static std::vector<PrimeOrderCurveId> all();

      /// Convert the ID to it's commonly used name (inverse of from_string)
      std::string to_string() const;

      PrimeOrderCurveId(Code id) : m_code(id) {}

      /// Map a string to a curve identifier
      static std::optional<PrimeOrderCurveId> from_string(std::string_view name);

#if defined(BOTAN_HAS_ASN1)
      /// Map an OID to a curve identifier
      ///
      /// Uses the internal OID table
      static std::optional<PrimeOrderCurveId> from_oid(const OID& oid);
#endif

   private:
      const Code m_code;
};

}  // namespace Botan::PCurve

#endif
