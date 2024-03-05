/*
* X448 Internal
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include <botan/internal/x448_internal.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/curve448_gf.h>

namespace Botan {

namespace {
uint64_t get_bit(const ScalarX448& scalar, size_t bit) {
   return (scalar[bit / 8] >> (bit % 8)) & 1;
}
}  // namespace

secure_vector<uint8_t> encode_point(const Point448& p) {
   return {p.begin(), p.end()};
}

Point448 decode_point(std::span<const uint8_t> p_bytes) {
   BOTAN_ARG_CHECK(p_bytes.size() == X448_LEN, "Invalid size for X448 point");
   return typecast_copy<Point448>(p_bytes);
}

ScalarX448 decode_scalar(std::span<const uint8_t> scalar_bytes) {
   BOTAN_ARG_CHECK(scalar_bytes.size() == X448_LEN, "Invalid size for X448 scalar");
   auto buf = typecast_copy<ScalarX448>(scalar_bytes);

   buf[0] &= 0xfc;
   buf[55] |= 0x80;

   return buf;
}

/// Multiply a scalar with the base group element (5)
Point448 x448_basepoint(const ScalarX448& k) {
   const Point448 u({5});
   return x448(k, u);
}

// Algorithm see RFC 7748, Section 5:
// https://datatracker.ietf.org/doc/html/rfc7748#section-5
Point448 x448(const ScalarX448& k, const Point448& u) {
   const Gf448Elem a24 = 39081;

   Gf448Elem x_1 = Gf448Elem(u.get());
   Gf448Elem x_2 = 1;
   Gf448Elem z_2 = 0;
   Gf448Elem x_3 = Gf448Elem(u.get());
   Gf448Elem z_3 = 1;
   auto swap = CT::Mask<uint64_t>::cleared();

   for(int16_t t = 448 - 1; t >= 0; --t) {
      auto k_t = CT::Mask<uint64_t>::expand(get_bit(k, t));
      swap ^= k_t;

      x_2.ct_cond_swap(swap.as_bool(), x_3);
      z_2.ct_cond_swap(swap.as_bool(), z_3);
      swap = k_t;

      const auto A = x_2 + z_2;
      const auto AA = square(A);
      const auto B = x_2 - z_2;
      const auto BB = square(B);
      const auto E = AA - BB;
      const auto C = x_3 + z_3;
      const auto D = x_3 - z_3;
      const auto DA = D * A;
      const auto CB = C * B;
      x_3 = square(DA + CB);
      z_3 = x_1 * square(DA - CB);
      x_2 = AA * BB;
      z_2 = E * (AA + a24 * E);
   }

   x_2.ct_cond_swap(swap.as_bool(), x_3);
   z_2.ct_cond_swap(swap.as_bool(), z_3);

   const auto res = x_2 / z_2;

   return Point448(res.to_bytes());
}

}  // namespace Botan
