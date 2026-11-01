/*
* (C) 2016,2019,2020,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/processor_rng.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/internal/hwrng.h>
#include <botan/internal/loadstor.h>

namespace Botan {

namespace {

uint64_t read_hwrng() {
   if(const auto output = HWRNG::read()) {
      return *output;
   }

   throw PRNG_Unseeded("Processor RNG instruction failed to produce output within expected iterations");
}

}  // namespace

//static
bool Processor_RNG::available() {
   return HWRNG::available();
}

std::string Processor_RNG::name() const {
   return HWRNG::feature().to_string();
}

void Processor_RNG::fill_bytes_with_input(std::span<uint8_t> out, std::span<const uint8_t> in) {
   // No way to provide entropy to processor-specific generator, ignore...
   BOTAN_UNUSED(in);

   while(out.size() >= 8) {
      store_le(read_hwrng(), out.data());
      out = out.subspan(8);
   }

   if(!out.empty()) {
      // at most 7 bytes left
      const auto hwrng_bytes = store_le(read_hwrng());
      copy_mem(out, std::span{hwrng_bytes}.first(out.size()));
   }
}

Processor_RNG::Processor_RNG() {
   if(!Processor_RNG::available()) {
      throw Invalid_State("Current CPU does not support RNG instruction");
   }
}

}  // namespace Botan
