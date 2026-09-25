/*
 * HQC parameter sets
 *
 * (C) 2026 Falko Strenzke
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_HQC_MODE_H_
#define BOTAN_HQC_MODE_H_

#include <botan/asn1_obj.h>

namespace Botan {

/**
 * The HQC parameter sets as defined in the HQC specification of 2025-08-22
 * (NIST security categories 1, 3 and 5).
 */
class BOTAN_PUBLIC_API(3, 14) HQC_Mode final {
   public:
      enum Mode : uint8_t /* NOLINT(*-use-enum-class) */ {
         HQC_1,
         HQC_3,
         HQC_5,
      };

      // NOLINTNEXTLINE(*-explicit-conversions)
      HQC_Mode(Mode mode);

      explicit HQC_Mode(const OID& oid);
      explicit HQC_Mode(std::string_view str);

      OID object_identifier() const;
      std::string to_string() const;

      Mode mode() const { return m_mode; }

      /// Estimated classical security strength in bits (128, 192 or 256)
      size_t estimated_strength() const;

      /// The code length n (the number of bits of a vector in F_2[X]/(X^n - 1))
      size_t code_length() const;

      /**
       * The parameter set discriminant expected by the C API of the Rust
       * crate (1, 3 or 5)
       */
      uint8_t parameter_set_byte() const;

      bool operator==(const HQC_Mode& other) const { return m_mode == other.m_mode; }

   private:
      Mode m_mode;
};

}  // namespace Botan

#endif
