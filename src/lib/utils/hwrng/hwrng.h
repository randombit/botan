/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HWRNG_H_
#define BOTAN_HWRNG_H_

#include <botan/types.h>
#include <botan/internal/cpuid.h>
#include <optional>

namespace Botan::HWRNG {

/**
* Return true if the current CPU supports the hardware RNG instruction
*/
BOTAN_TEST_API bool available();

/**
* Read 64 bits from the hardware RNG
*
* Returns nullopt if the instruction repeatedly failed to produce an output,
* which indicates a hardware fault.
*
* Must only be called if available() returns true
*/
BOTAN_TEST_API std::optional<uint64_t> read();

/*
* The following functions are implemented by the architecture specific submodule
*/

/**
* Return the CPUID feature which indicates the hardware RNG is available
*/
CPUID::Feature feature();

/**
* Make a single attempt to read 64 bits from the hardware RNG
*
* Returns nullopt if the instruction indicated failure
*
* Must only be called if available() returns true
*/
std::optional<uint64_t> read_once();

}  // namespace Botan::HWRNG

#endif
