/*
 * FrodoKEM modes and constants
 *
 * The Fellowship of the FrodoKEM:
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/frodo_mode.h>

#include <botan/assert.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>

#include <memory>
#include <tuple>
#include <vector>

namespace Botan {

namespace {

FrodoKEMMode::Mode FrodoKEM_mode_from_string(std::string_view str) {
   if(str == "FrodoKEM-640-SHAKE") {
      return FrodoKEMMode::FrodoKEM640_SHAKE;
   }
   if(str == "FrodoKEM-976-SHAKE") {
      return FrodoKEMMode::FrodoKEM976_SHAKE;
   }
   if(str == "FrodoKEM-1344-SHAKE") {
      return FrodoKEMMode::FrodoKEM1344_SHAKE;
   }
   if(str == "eFrodoKEM-640-SHAKE") {
      return FrodoKEMMode::eFrodoKEM640_SHAKE;
   }
   if(str == "eFrodoKEM-976-SHAKE") {
      return FrodoKEMMode::eFrodoKEM976_SHAKE;
   }
   if(str == "eFrodoKEM-1344-SHAKE") {
      return FrodoKEMMode::eFrodoKEM1344_SHAKE;
   }

   if(str == "FrodoKEM-640-AES") {
      return FrodoKEMMode::FrodoKEM640_AES;
   }
   if(str == "FrodoKEM-976-AES") {
      return FrodoKEMMode::FrodoKEM976_AES;
   }
   if(str == "FrodoKEM-1344-AES") {
      return FrodoKEMMode::FrodoKEM1344_AES;
   }
   if(str == "eFrodoKEM-640-AES") {
      return FrodoKEMMode::eFrodoKEM640_AES;
   }
   if(str == "eFrodoKEM-976-AES") {
      return FrodoKEMMode::eFrodoKEM976_AES;
   }
   if(str == "eFrodoKEM-1344-AES") {
      return FrodoKEMMode::eFrodoKEM1344_AES;
   }

   throw Invalid_Argument(fmt("'{}' is not a valid FrodoKEM mode name", str));
}

}  // anonymous namespace

FrodoKEMMode::FrodoKEMMode(Mode mode) : m_mode(mode) {}

FrodoKEMMode::FrodoKEMMode(const OID& oid) : m_mode(FrodoKEM_mode_from_string(oid.to_formatted_string())) {}

FrodoKEMMode::FrodoKEMMode(std::string_view str) : m_mode(FrodoKEM_mode_from_string(str)) {}

OID FrodoKEMMode::object_identifier() const {
   return OID::from_string(to_string());
}

std::string FrodoKEMMode::to_string() const {
   switch(m_mode) {
      case FrodoKEM640_SHAKE:
         return "FrodoKEM-640-SHAKE";
      case FrodoKEM976_SHAKE:
         return "FrodoKEM-976-SHAKE";
      case FrodoKEM1344_SHAKE:
         return "FrodoKEM-1344-SHAKE";
      case eFrodoKEM640_SHAKE:
         return "eFrodoKEM-640-SHAKE";
      case eFrodoKEM976_SHAKE:
         return "eFrodoKEM-976-SHAKE";
      case eFrodoKEM1344_SHAKE:
         return "eFrodoKEM-1344-SHAKE";

      case FrodoKEM640_AES:
         return "FrodoKEM-640-AES";
      case FrodoKEM976_AES:
         return "FrodoKEM-976-AES";
      case FrodoKEM1344_AES:
         return "FrodoKEM-1344-AES";
      case eFrodoKEM640_AES:
         return "eFrodoKEM-640-AES";
      case eFrodoKEM976_AES:
         return "eFrodoKEM-976-AES";
      case eFrodoKEM1344_AES:
         return "eFrodoKEM-1344-AES";
   }

   BOTAN_ASSERT_UNREACHABLE();
}

}  // namespace Botan
