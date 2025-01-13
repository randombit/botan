/*
* PKCS #11 Interface Wrapper Implementation
* (C) 2025 Jack Lloyd
*     2025 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include <botan/p11.h>
#include <array>
#include <ranges>
#include <vector>

namespace Botan::PKCS11 {

namespace {

auto operator<=>(const Version& left, const Version& right) {
   // Compare both versions by concatenating their bytes: major || minor
   auto version_value = [](const Version& v) -> uint16_t {
      return static_cast<uint16_t>(v.major) << 8 | static_cast<uint16_t>(v.minor);
   };
   return version_value(left) <=> version_value(right);
}

auto operator==(const Version& left, const Version& right) {
   return left.major == right.major && left.minor == right.minor;
}

constexpr std::string_view PKCS11_INTERFACE_NAME = "PKCS 11";

}  // namespace

Version InterfaceWrapper::version() const {
   return *reinterpret_cast<Version*>(m_interface.pFunctionList);
}

std::string_view InterfaceWrapper::name() const {
   return std::string_view(reinterpret_cast<const char*>(m_interface.pInterfaceName));
}

std::unique_ptr<InterfaceWrapper> InterfaceWrapper::latest_p11_interface(Dynamically_Loaded_Library& library) {
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

      return std::make_unique<InterfaceWrapper>(Interface{
         .pInterfaceName = InterfaceWrapper::p11_interface_name_ptr(),
         .pFunctionList = func_list,
         .flags = 0,
      });
   }
   std::vector<Interface> interface_list(count);
   rv = LowLevel::C_GetInterfaceList(library, interface_list.data(), &count, nullptr);
   if(!rv) {
      // The interface list count could be computed but the interface list cannot be received. This should not happen.
      throw Invalid_Argument("Unexpected error while loading PKCS#11 interface list.");
   }

   auto version_of = [](const Interface& i) -> Version { return *reinterpret_cast<Version*>(i.pFunctionList); };
   auto name_of = [](const Interface& i) -> std::string_view {
      return std::string_view(reinterpret_cast<const char*>(i.pInterfaceName));
   };

   // We only load interfaces named "PKCS 11" (which are the pure ones defined in the spec) with
   // version >= 2.40.
   auto is_valid_interface = [&](const Interface& i) {
      if(name_of(i) != PKCS11_INTERFACE_NAME) {
         return false;
      }
      // This is also done by the example in PKCS #11 (version >= 3.0) spec.
      // Note that version above the currently supported maximal version should
      // be compatible too.
      Version version = version_of(i);
      return version >= Version{2, 40};
   };
   std::vector<Interface> valid_interfaces;
   std::copy_if(interface_list.begin(), interface_list.end(), std::back_inserter(valid_interfaces), is_valid_interface);

   if(valid_interfaces.empty()) {
      throw Invalid_Argument("No supported PKCS #11 interfaces found.");
   }

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
   auto best_interface = std::max_element(valid_interfaces.begin(), valid_interfaces.end(), priority_comparator);
   return std::make_unique<InterfaceWrapper>(*best_interface);
}

const FunctionList& InterfaceWrapper::func_2_40() const {
   if(name() != PKCS11_INTERFACE_NAME) {
      throw Botan::Invalid_State("Vendor defined PKCS #11 interfaces are not supported.");
   }
   return *reinterpret_cast<FunctionList*>(get().pFunctionList);
}

const FunctionList30& InterfaceWrapper::func_3_0() const {
   if(name() != PKCS11_INTERFACE_NAME) {
      throw Botan::Invalid_State("Vendor defined PKCS #11 interfaces are not supported.");
   }
   if(version() < Version{3, 0}) {
      throw Botan::Invalid_State("Loaded interface does not support PKCS #11 v3.0 features");
   }
   return *reinterpret_cast<FunctionList30*>(get().pFunctionList);
}

const FunctionList32& InterfaceWrapper::func_3_2() const {
   if(name() != PKCS11_INTERFACE_NAME) {
      throw Botan::Invalid_State("Vendor defined PKCS #11 interfaces are not supported.");
   }
   if(version() < Version{3, 2}) {
      throw Botan::Invalid_State("Loaded interface does not support PKCS #11 v3.2 features");
   }
   return *reinterpret_cast<FunctionList32*>(get().pFunctionList);
}

uint8_t* InterfaceWrapper::p11_interface_name_ptr() {
   static std::array<uint8_t, 8> PKCS11_INTERFACE_NAME_ARR = {'P', 'K', 'C', 'S', ' ', '1', '1', '\0'};
   return PKCS11_INTERFACE_NAME_ARR.data();
}

}  // namespace Botan::PKCS11
