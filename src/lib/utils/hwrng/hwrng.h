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
#include <span>

namespace Botan::HWRNG {

/**
* Return true if the current CPU supports the hardware RNG instruction
*/
BOTAN_TEST_API bool is_available();

/**
* Read 64 bits from the hardware RNG
*
* Returns nullopt if the instruction repeatedly failed to produce an output,
* which indicates a hardware fault.
*
* Must only be called if is_available() returns true
*/
BOTAN_TEST_API std::optional<uint64_t> read();

/**
* Fill out with output from the hardware RNG
*
* Returns false if the hardware RNG failed, in which case out may be only
* partially written.
*
* Must only be called if is_available() returns true
*/
[[nodiscard]] bool fill(std::span<uint8_t> out);

/**
* Return true if the hardware RNG is available and executes quickly enough
* that it can be used in performance sensitive code
*
* The speed is determined by timing the hardware RNG the first time this
* function (or read_if_fast) is called.
*/
BOTAN_TEST_API bool is_fast();

/**
* Read 64 bits from the hardware RNG if it is fast
*
* Returns nullopt if the hardware RNG is unavailable, slow, or failed.
*
* If the speed of the hardware RNG is not yet known, this call times it and
* returns one of the outputs produced while doing so, even if the hardware RNG
* turns out to be slow.
*/
BOTAN_TEST_API std::optional<uint64_t> read_if_fast();

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
* Must only be called if is_available() returns true
*/
std::optional<uint64_t> read_once();

}  // namespace Botan::HWRNG

#endif
