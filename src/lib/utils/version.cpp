/*
* Version Information
* (C) 1999-2013,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/version.h>

#include <botan/internal/fmt.h>
#include <botan/internal/target_info.h>
#include <botan/internal/version_info.h>

namespace Botan {

const char* short_version_cstr() {
   return BOTAN_SHORT_VERSION_STRING;
}

const char* version_cstr() {
   return BOTAN_FULL_VERSION_STRING;
}

std::string version_string() {
   return std::string(version_cstr());
}

std::string short_version_string() {
   return std::string(short_version_cstr());
}

uint32_t version_datestamp() {
   return BOTAN_VERSION_DATESTAMP;
}

std::optional<std::string> version_vc_revision() {
#if defined(BOTAN_VC_REVISION)
   return std::string(BOTAN_VC_REVISION);
#else
   return std::nullopt;
#endif
}

std::optional<std::string> version_distribution_info() {
#if defined(BOTAN_DISTRIBUTION_INFO_STRING)
   return std::string(BOTAN_DISTRIBUTION_INFO_STRING);
#else
   return std::nullopt;
#endif
}

/*
* Return parts of the version as integers
*/
uint32_t version_major() {
   return BOTAN_VERSION_MAJOR;
}

uint32_t version_minor() {
   return BOTAN_VERSION_MINOR;
}

uint32_t version_patch() {
   return BOTAN_VERSION_PATCH;
}

bool unsafe_for_production_build() {
#if defined(BOTAN_UNSAFE_FUZZER_MODE) || defined(BOTAN_TERMINATE_ON_ASSERTS)
   return true;
#else
   return false;
#endif
}

std::string runtime_version_check(uint32_t major, uint32_t minor, uint32_t patch) {
   if(major != version_major() || minor != version_minor() || patch != version_patch()) {
      return fmt("Warning: linked version ({}) does not match version built against ({}.{}.{})\n",
                 short_version_cstr(),
                 major,
                 minor,
                 patch);
   }

   return "";
}

}  // namespace Botan
