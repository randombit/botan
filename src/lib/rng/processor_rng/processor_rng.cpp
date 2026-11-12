/*
* (C) 2016,2019,2020,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/processor_rng.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/internal/hwrng.h>

namespace Botan {

//static
bool Processor_RNG::available() {
   return HWRNG::is_available();
}

std::string Processor_RNG::name() const {
   return HWRNG::feature().to_string();
}

void Processor_RNG::fill_bytes_with_input(std::span<uint8_t> out, std::span<const uint8_t> in) {
   // No way to provide entropy to processor-specific generator, ignore...
   BOTAN_UNUSED(in);

   if(!HWRNG::fill(out)) {
      throw PRNG_Unseeded("Processor RNG instruction failed to produce output within expected iterations");
   }
}

Processor_RNG::Processor_RNG() {
   if(!Processor_RNG::available()) {
      throw Invalid_State("Current CPU does not support RNG instruction");
   }
}

}  // namespace Botan
