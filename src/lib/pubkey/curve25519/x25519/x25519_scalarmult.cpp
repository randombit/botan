/*
* (C) 2014,2018,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/x25519_internal.h>

#include <botan/mem_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/ed25519_internal.h>
#include <botan/internal/x25519_fe.h>
#include <array>

namespace Botan {

namespace {

// RFC 7748 Section 5 decodeScalar25519
std::array<uint8_t, 32> x25519_clamp(std::span<const uint8_t, 32> scalar) {
   std::array<uint8_t, 32> k{};
   copy_mem(k, scalar);
   k[0] &= 248;
   k[31] &= 127;
   k[31] |= 64;
   return k;
}

}  // namespace

void x25519_scalarmult(std::span<uint8_t, 32> out,
                       std::span<const uint8_t, 32> scalar,
                       std::span<const uint8_t, 32> u) {
   CT::poison(scalar);
   CT::poison(u);

   auto k = x25519_clamp(scalar);
   x25519_ladder(out, k, u);
   secure_scrub_memory(k.data(), k.size());

   CT::unpoison(scalar);
   CT::unpoison(u);
   CT::unpoison(out);
}

void x25519_basepoint(std::span<uint8_t, 32> out, std::span<const uint8_t, 32> scalar) {
   /*
   * Compute the public key as [k]B on the Ed25519 curve using the fixed-base
   * tables, then map the result to Curve25519. This gives the same result as
   * running the Montgomery ladder on u = 9 since the base points correspond
   * under the birational map and B has order l, but is several times faster.
   */
   CT::poison(scalar);

   auto k = x25519_clamp(scalar);
   const auto s = Ed25519_Scalar::from_bytes(k);
   ed25519_basepoint_mul_to_x25519(out, s);
   secure_scrub_memory(k.data(), k.size());

   CT::unpoison(scalar);
}

}  // namespace Botan
