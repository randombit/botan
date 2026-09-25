/*
 * C++ wrapper around the C API of the Rust crate rust-hqc
 *
 * (C) 2026 Falko Strenzke
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/hqc_ffi.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>

#include <hqc_c_api.h>

namespace Botan::HQC_FFI {

namespace {

void check_rc(int32_t rc, std::string_view operation) {
   switch(rc) {
      case HQC_OK:
         return;
      case HQC_ERR_BUFFER_LENGTH:
         throw Invalid_Argument(fmt("HQC {}: a buffer has the wrong length for the parameter set", operation));
      case HQC_ERR_INVALID_KEY:
         throw Invalid_Argument(fmt("HQC {}: invalid key", operation));
      case HQC_ERR_INVALID_CIPHERTEXT:
         throw Invalid_Argument(fmt("HQC {}: invalid ciphertext", operation));
      default:
         // HQC_ERR_RANDOMNESS, HQC_ERR_INTERNAL, HQC_ERR_BAD_PARAMETER_SET,
         // HQC_ERR_NULL_POINTER and unknown codes: all indicate a bug on the
         // calling side or inside the crate, not bad user input
         throw Internal_Error(fmt("HQC {}: rust-hqc returned error code {}", operation, rc));
   }
}

}  // namespace

Sizes sizes(const HQC_Mode& mode) {
   Sizes s;
   check_rc(::hqc_sizes(mode.parameter_set_byte(), &s.ek, &s.dk, &s.ct, &s.ss), "sizes");
   return s;
}

void keypair(const HQC_Mode& mode, std::span<uint8_t> ek, std::span<uint8_t> dk, std::span<const uint8_t> seed) {
   check_rc(
      ::hqc_keypair(mode.parameter_set_byte(), ek.data(), ek.size(), dk.data(), dk.size(), seed.data(), seed.size()),
      "keypair");
}

void encaps(const HQC_Mode& mode,
            std::span<uint8_t> ct,
            std::span<uint8_t> ss,
            std::span<const uint8_t> ek,
            std::span<const uint8_t> seed) {
   check_rc(::hqc_encaps(mode.parameter_set_byte(),
                         ct.data(),
                         ct.size(),
                         ss.data(),
                         ss.size(),
                         ek.data(),
                         ek.size(),
                         seed.data(),
                         seed.size()),
            "encaps");
}

void decaps(const HQC_Mode& mode, std::span<uint8_t> ss, std::span<const uint8_t> ct, std::span<const uint8_t> dk) {
   check_rc(::hqc_decaps(mode.parameter_set_byte(), ss.data(), ss.size(), ct.data(), ct.size(), dk.data(), dk.size()),
            "decaps");
}

}  // namespace Botan::HQC_FFI
