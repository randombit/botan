/*
* Runtime CPU detection
* (C) 2009,2010,2013,2017,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpuid.h>

#include <botan/internal/parsing.h>

#if defined(BOTAN_HAS_OS_UTILS)
   #include <botan/internal/os_utils.h>
#endif

namespace Botan {

#if !defined(BOTAN_HAS_CPUID_DETECTION)
uint32_t CPUFeature::as_u32() const {
   throw Invalid_State("CPUFeature invalid bit");
}

std::optional<CPUFeature> CPUFeature::from_string(std::string_view) {
   return {};
}

std::string CPUFeature::to_string() const {
   throw Invalid_State("CPUFeature invalid bit");
}
#endif

//static
std::string CPUID::to_string() {
   std::vector<std::string> flags;

   const uint32_t bitset = state().bitset();

   for(size_t i = 0; i != 32; ++i) {
      const uint32_t b = static_cast<uint32_t>(1) << i;
      if((bitset & b) == b) {
         // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
         flags.push_back(CPUFeature(static_cast<CPUFeature::Bit>(b)).to_string());
      }
   }

   return string_join(flags, ' ');
}

//static
void CPUID::initialize() {
   state() = CPUID_Data();
}

#if defined(BOTAN_HAS_CPUID_DETECTION)

namespace {

uint32_t cleared_cpuid_bits() {
   uint32_t cleared = 0;

   #if defined(BOTAN_HAS_OS_UTILS)
   std::string clear_cpuid_env;
   if(OS::read_env_variable(clear_cpuid_env, "BOTAN_CLEAR_CPUID")) {
      for(const auto& cpuid : split_on(clear_cpuid_env, ',')) {
         if(auto bit = CPUID::bit_from_string(cpuid)) {
            cleared |= bit->as_u32();
         }
      }
   }
   #endif

   return cleared;
}

}  // namespace

#endif

CPUID::CPUID_Data::CPUID_Data() {
   // NOLINTBEGIN(*-prefer-member-initializer)
#if defined(BOTAN_HAS_CPUID_DETECTION)
   m_processor_features = detect_cpu_features(~cleared_cpuid_bits());
#else
   m_processor_features = 0;
#endif
   // NOLINTEND(*-prefer-member-initializer)
}

std::optional<CPUFeature> CPUID::bit_from_string(std::string_view tok) {
   return CPUFeature::from_string(tok);
}

}  // namespace Botan
