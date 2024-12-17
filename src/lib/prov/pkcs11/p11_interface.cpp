/*
* PKCS #11 Interface Wrapper Implementation
* (C) 2025 Jack Lloyd
*     2025 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include <botan/p11.h>
#include <ranges>

namespace Botan::PKCS11 {

namespace {

auto operator<=>(const Version& left, const Version& right) {
   // Compare both versions by concatenating their bytes
   auto get_version_value = [](const Version& v) -> uint16_t {
      return static_cast<uint16_t>(v.major) << 8 | static_cast<uint16_t>(v.minor);
   };

   uint16_t left_val = get_version_value(left);
   uint16_t right_val = get_version_value(right);

   return left_val <=> right_val;
}

auto operator==(const Version& left, const Version& right) {
   return left.major == right.major && left.minor == right.minor;
}

constexpr std::string_view PKCS11_INTERFACE_NAME = "PKCS 11";

}  // namespace

Version InterfaceWrapperBase::version() const {
   return *reinterpret_cast<Version*>(m_interface.pFunctionList);
}

std::string_view InterfaceWrapperBase::name() const {
   return std::string_view(reinterpret_cast<const char*>(m_interface.pInterfaceName));
}

const CK_FUNCTION_LIST& InterfaceWrapperBase::func_2_40() const {
   throw Not_Implemented("PKCS #11 version 2.40 interface not overridden in this interface wrapper.");
}

const CK_FUNCTION_LIST_3_0& InterfaceWrapperBase::func_3_0() const {
   throw Not_Implemented("PKCS #11 version 3.0 interface not overridden in this interface wrapper.");
}

const CK_FUNCTION_LIST_3_2& InterfaceWrapperBase::func_3_2() const {
   throw Not_Implemented("PKCS #11 version 3.2 interface not overridden in this interface wrapper.");
}

std::unique_ptr<InterfaceWrapperDefault> InterfaceWrapperDefault::latest_p11_interface(
   Dynamically_Loaded_Library& library) {
   Ulong count;
   auto rv = LowLevel::C_GetInterfaceList(library, nullptr, &count, nullptr);
   if(!rv) {
      // Method could not be executed. Probably due to a cryptoki library with PKCS #11 < 3.0.
      // Try the legacy C_GetFunctionList method (for PKCS#11 version 2.40).
      CK_FUNCTION_LIST* func_list;
      rv = LowLevel::C_GetFunctionList(library, &func_list, nullptr);
      if(!rv) {
         throw Invalid_Argument("Failed to load function list for PKCS#11 library.");
      }

      return std::make_unique<InterfaceWrapperDefault>(Interface{
         .pInterfaceName = InterfaceWrapperDefault::p11_interface_name_ptr(),
         .pFunctionList = func_list,
         .flags = 0,
      });
   }
   std::vector<Interface> interfaceList(count);
   rv = LowLevel::C_GetInterfaceList(library, interfaceList.data(), &count, nullptr);
   if(!rv) {
      // The interface list count could be computed but the interface list cannot be received. This should not happen.
      throw Invalid_Argument("Unexpected error while loading PKCS#11 interface list.");
   }

   auto version_of = [](const Interface& i) -> Version { return *reinterpret_cast<Version*>(i.pFunctionList); };
   auto name_of = [](const Interface& i) -> std::string_view {
      return std::string_view(reinterpret_cast<const char*>(i.pInterfaceName));
   };

   // We only load interfaces named "PKCS 11" (which are the pure ones defined in the spec) with
   // 2.40 <= version <= 3.2
   auto is_valid_interface = [&](const Interface& i) {
      if(name_of(i) != PKCS11_INTERFACE_NAME) {
         return false;
      }
      // This is also done by the example in PKCS #11 (version >= 3.0) spec.
      Version version = version_of(i);
      return version >= Version{2, 40} && version <= Version{3, 2};
   };

   // We prioritize valid interfaces the following way:
   // Higher versions are prefered over lower ones. If multiple interfaces of
   // the highest version exist, fork safe interfaces are prefered.
   auto priority_comparator = [&](const Interface& a, const Interface& b) {
      Version a_version = version_of(a);
      Version b_version = version_of(b);

      if(a_version == b_version) {
         return (a.flags & static_cast<CK_FLAGS>(Flag::InterfaceForkSafe)) <
                (b.flags & static_cast<CK_FLAGS>(Flag::InterfaceForkSafe));
      }
      return a_version < b_version;
   };

   auto valid_interfaces = interfaceList | std::ranges::views::filter(is_valid_interface);

   if(valid_interfaces.empty()) {
      throw Invalid_Argument("No supported PKCS #11 interfaces found.");
   }

   auto best_interface = std::ranges::max_element(valid_interfaces, priority_comparator);
   return std::make_unique<InterfaceWrapperDefault>(*best_interface);
}

const CK_FUNCTION_LIST& InterfaceWrapperDefault::func_2_40() const {
   if(name() != PKCS11_INTERFACE_NAME) {
      throw Botan::Invalid_State("Vendor defined PKCS #11 interfaces are not supported.");
   }
   return *reinterpret_cast<CK_FUNCTION_LIST*>(get().pFunctionList);
}

const CK_FUNCTION_LIST_3_0& InterfaceWrapperDefault::func_3_0() const {
   if(name() != PKCS11_INTERFACE_NAME) {
      throw Botan::Invalid_State("Vendor defined PKCS #11 interfaces are not supported.");
   }
   if(version() < Version{3, 0}) {
      throw Botan::Invalid_State("Loaded interface does not support PKCS #11 v3.0 features");
   }
   return *reinterpret_cast<CK_FUNCTION_LIST_3_0*>(get().pFunctionList);
}

const CK_FUNCTION_LIST_3_2& InterfaceWrapperDefault::func_3_2() const {
   if(name() != PKCS11_INTERFACE_NAME) {
      throw Botan::Invalid_State("Vendor defined PKCS #11 interfaces are not supported.");
   }
   if(version() < Version{3, 2}) {
      throw Botan::Invalid_State("Loaded interface does not support PKCS #11 v3.2 features");
   }
   return *reinterpret_cast<CK_FUNCTION_LIST_3_2*>(get().pFunctionList);
}

uint8_t* InterfaceWrapperDefault::p11_interface_name_ptr() {
   static std::array<uint8_t, 8> PKCS11_INTERFACE_NAME_ARR = {'P', 'K', 'C', 'S', ' ', '1', '1', '\0'};
   return PKCS11_INTERFACE_NAME_ARR.data();
}

}  // namespace Botan::PKCS11
