/*
 * C++ wrapper around the C API of the Rust crate rust-hqc
 *
 * (C) 2026 Falko Strenzke
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/hqc_ffi.h>

#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/xof.h>
#include <botan/internal/fmt.h>

#include <hqc_c_api.h>

/*
 * The C API declares hqc_xof_t as an opaque struct that the callback provider
 * defines. Ours wraps a Botan XOF object.
 */
struct hqc_xof_st {
      std::unique_ptr<Botan::XOF> xof;
};

namespace Botan::HQC_FFI {

namespace {

/*
 * Hash callbacks handed to the crate. They must never let an exception escape
 * into Rust; any failure is reported as a non-zero return value, which the
 * crate turns into HQC_ERR_HASH_CALLBACK.
 */

constexpr int32_t callback_ok = 0;
constexpr int32_t callback_failed = -1;

std::span<const uint8_t> part(const hqc_buffer_t& buf) {
   return {buf.data, buf.len};
}

int32_t hash_parts(std::string_view algo, const hqc_buffer_t* parts, size_t n_parts, uint8_t* out) noexcept {
   try {
      auto hash = HashFunction::create_or_throw(algo);
      for(size_t i = 0; i < n_parts; ++i) {
         hash->update(part(parts[i]));
      }
      hash->final(out);
      return callback_ok;
   } catch(...) {
      return callback_failed;
   }
}

extern "C" int32_t botan_hqc_sha3_256(void* /*ctx*/, const hqc_buffer_t* parts, size_t n_parts, uint8_t* out) {
   return hash_parts("SHA-3(256)", parts, n_parts, out);
}

extern "C" int32_t botan_hqc_sha3_512(void* /*ctx*/, const hqc_buffer_t* parts, size_t n_parts, uint8_t* out) {
   return hash_parts("SHA-3(512)", parts, n_parts, out);
}

extern "C" int32_t botan_hqc_shake256_init(void* /*ctx*/,
                                           const hqc_buffer_t* parts,
                                           size_t n_parts,
                                           hqc_xof_t** out_xof) {
   try {
      auto xof = XOF::create_or_throw("SHAKE-256");
      for(size_t i = 0; i < n_parts; ++i) {
         xof->update(part(parts[i]));
      }
      *out_xof = new hqc_xof_st{std::move(xof)};  // NOLINT(*-owning-memory)
      return callback_ok;
   } catch(...) {
      return callback_failed;
   }
}

extern "C" int32_t botan_hqc_shake256_squeeze(void* /*ctx*/, hqc_xof_t* xof, uint8_t* out, size_t out_len) {
   try {
      xof->xof->output({out, out_len});
      return callback_ok;
   } catch(...) {
      return callback_failed;
   }
}

extern "C" void botan_hqc_shake256_free(void* /*ctx*/, hqc_xof_t* xof) {
   delete xof;  // NOLINT(*-owning-memory)
}

const hqc_callbacks_t* botan_callbacks() {
   static const hqc_callbacks_t callbacks = {
      .version = HQC_CALLBACKS_VERSION,
      .hash =
         {
            .ctx = nullptr,
            .sha3_256 = botan_hqc_sha3_256,
            .sha3_512 = botan_hqc_sha3_512,
            .shake256_init = botan_hqc_shake256_init,
            .shake256_squeeze = botan_hqc_shake256_squeeze,
            .shake256_free = botan_hqc_shake256_free,
         },
   };
   return &callbacks;
}

void check_rc(int32_t rc, std::string_view operation) {
   switch(rc) {
      case HQC_OK:
         return;
      case HQC_ERR_BUFFER_LENGTH:
         throw Invalid_Argument(fmt("HQCr4 {}: a buffer has the wrong length for the parameter set", operation));
      case HQC_ERR_INVALID_KEY:
         throw Invalid_Argument(fmt("HQCr4 {}: invalid key", operation));
      case HQC_ERR_INVALID_CIPHERTEXT:
         throw Invalid_Argument(fmt("HQCr4 {}: invalid ciphertext", operation));
      default:
         // HQC_ERR_RANDOMNESS, HQC_ERR_INTERNAL, HQC_ERR_BAD_PARAMETER_SET,
         // HQC_ERR_NULL_POINTER, HQC_ERR_HASH_CALLBACK, HQC_ERR_BAD_CALLBACKS
         // and unknown codes: all indicate a bug on the calling side or
         // inside the crate, not bad user input
         throw Internal_Error(fmt("HQCr4 {}: rust-hqc returned error code {}", operation, rc));
   }
}

}  // namespace

Sizes sizes(const HQC_Mode& mode) {
   Sizes s;
   check_rc(::hqc_sizes(mode.parameter_set_byte(), &s.ek, &s.dk, &s.ct, &s.ss), "sizes");
   return s;
}

void keypair(const HQC_Mode& mode, std::span<uint8_t> ek, std::span<uint8_t> dk, std::span<const uint8_t> seed) {
   check_rc(::hqc_keypair(mode.parameter_set_byte(),
                          botan_callbacks(),
                          ek.data(),
                          ek.size(),
                          dk.data(),
                          dk.size(),
                          seed.data(),
                          seed.size()),
            "keypair");
}

void encaps(const HQC_Mode& mode,
            std::span<uint8_t> ct,
            std::span<uint8_t> ss,
            std::span<const uint8_t> ek,
            std::span<const uint8_t> seed) {
   check_rc(::hqc_encaps(mode.parameter_set_byte(),
                         botan_callbacks(),
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
   check_rc(::hqc_decaps(mode.parameter_set_byte(),
                         botan_callbacks(),
                         ss.data(),
                         ss.size(),
                         ct.data(),
                         ct.size(),
                         dk.data(),
                         dk.size()),
            "decaps");
}

}  // namespace Botan::HQC_FFI
