/*
* (C) 2014,2018,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/x25519_internal.h>

#include <botan/mem_ops.h>
#include <botan/internal/ct_utils.h>
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
   const std::array<uint8_t, 32> u = {9};
   x25519_scalarmult(out, scalar, u);
}

}  // namespace Botan
