/*
 * HQC parameter sets
 *
 * (C) 2026 Falko Strenzke
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/hqc_mode.h>

#include <botan/assert.h>
#include <botan/internal/fmt.h>

namespace Botan {

namespace {

HQC_Mode::Mode hqc_mode_from_string(std::string_view str) {
   if(str == "HQC-1") {
      return HQC_Mode::HQC_1;
   }
   if(str == "HQC-3") {
      return HQC_Mode::HQC_3;
   }
   if(str == "HQC-5") {
      return HQC_Mode::HQC_5;
   }

   throw Invalid_Argument(fmt("'{}' is not a valid HQC mode name", str));
}

HQC_Mode::Mode hqc_mode_from_oid(const OID& oid) {
   if(const auto name = oid.registered_name()) {
      return hqc_mode_from_string(*name);
   }

   throw Invalid_Argument(fmt("OID '{}' is not registered as an HQC mode", oid));
}

}  // anonymous namespace

HQC_Mode::HQC_Mode(Mode mode) : m_mode(mode) {}

HQC_Mode::HQC_Mode(const OID& oid) : m_mode(hqc_mode_from_oid(oid)) {}

HQC_Mode::HQC_Mode(std::string_view str) : m_mode(hqc_mode_from_string(str)) {}

OID HQC_Mode::object_identifier() const {
   return OID::from_string(to_string());
}

std::string HQC_Mode::to_string() const {
   switch(m_mode) {
      case HQC_1:
         return "HQC-1";
      case HQC_3:
         return "HQC-3";
      case HQC_5:
         return "HQC-5";
   }

   BOTAN_ASSERT_UNREACHABLE();
}

size_t HQC_Mode::estimated_strength() const {
   switch(m_mode) {
      case HQC_1:
         return 128;
      case HQC_3:
         return 192;
      case HQC_5:
         return 256;
   }

   BOTAN_ASSERT_UNREACHABLE();
}

size_t HQC_Mode::code_length() const {
   // Table 6 of the HQC specification of 2025-08-22. The C API of the crate
   // does not expose n; the relation ek_bytes == 32 + ceil(n / 8) is asserted
   // when a public key is constructed.
   switch(m_mode) {
      case HQC_1:
         return 17669;
      case HQC_3:
         return 35851;
      case HQC_5:
         return 57637;
   }

   BOTAN_ASSERT_UNREACHABLE();
}

uint8_t HQC_Mode::parameter_set_byte() const {
   switch(m_mode) {
      case HQC_1:
         return 1;
      case HQC_3:
         return 3;
      case HQC_5:
         return 5;
   }

   BOTAN_ASSERT_UNREACHABLE();
}

}  // namespace Botan
