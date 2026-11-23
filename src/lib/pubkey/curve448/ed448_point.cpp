/*
 * Ed448 Point Arithmetic
 * (C) 2024 Jack Lloyd
 *     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */
#include <botan/internal/ed448_point.h>

#include <botan/exceptn.h>
#include <botan/internal/ct_utils.h>
#include <vector>

namespace Botan {

Ed448Point Ed448Point::decode(std::span<const uint8_t, ED448_LEN> enc) {
   // RFC 8032 5.2.3  Decoding
   // 1. First, interpret the string as an integer in little-endian
   //    representation.  Bit 455 of this number is the least significant
   //    bit of the x-coordinate, and denote this value x_0.  The
   //    y-coordinate is recovered simply by clearing this bit.  If the
   //    resulting value is >= p, decoding fails.
   if((enc.back() & 0x7F) != 0) {  // last byte is either 0x00 or 0x80
      throw Decoding_Error("Ed448 point has unacceptable x-distinguisher");
   }
   const bool x_distinguisher = enc.back() != 0;
   const auto y_data = std::span(enc).first<56>();
   if(!Gf448Elem::bytes_are_canonical_representation(y_data)) {
      throw Decoding_Error("Ed448 y-coordinate is not smaller than p");
   }
   const auto y = Gf448Elem(y_data);

   // 2. To recover the x-coordinate, the curve equation implies
   //    x^2 = (y^2 - 1) / (d y^2 - 1) (mod p).  The denominator is always
   //    non-zero mod p.  Let u = y^2 - 1 and v = d y^2 - 1.  To compute
   //    the square root of (u/v), the first step is to compute the
   //    candidate root x = (u/v)^((p+1)/4).  This can be done using the
   //    following trick, to use a single modular powering for both the
   //    inversion of v and the square root:
   //                      (p+1)/4    3            (p-3)/4
   //             x = (u/v)        = u  v (u^5 v^3)         (mod p)
   const auto u = square(Gf448Elem(y)) - Gf448Elem::one();
   const auto v = -mul_a24(square(Gf448Elem(y))) - Gf448Elem::one();
   const auto maybe_x = (u * square(u)) * v * root((square(square(u)) * u) * square(v) * v);

   // 3. If v * x^2 = u, the recovered x-coordinate is x.  Otherwise, no
   //    square root exists, and the decoding fails.
   if(v * square(maybe_x) != u) {
      throw Decoding_Error("Square root does not exist");
   }
   // 4. Finally, use the x_0 bit to select the right square root.  If
   //    x = 0, and x_0 = 1, decoding fails.  Otherwise, if x_0 != x mod
   //    2, set x <-- p - x.  Return the decoded point (x,y).
   if(maybe_x.is_zero() && x_distinguisher) {
      throw Decoding_Error("Square root of zero cannot be odd");
   }
   const bool maybe_x_parity = maybe_x.is_odd();
   std::array<uint64_t, WORDS_448> x_data{};
   CT::Mask<uint64_t>::expand_bool(maybe_x_parity == x_distinguisher)
      .select_n(x_data.data(), maybe_x.words().data(), (-maybe_x).words().data(), WORDS_448);

   return {Gf448Elem(x_data), y};
}

Ed448Point Ed448Point::base_point() {
   constexpr std::array<const uint64_t, WORDS_448> x = {0x2626a82bc70cc05e,
                                                        0x433b80e18b00938e,
                                                        0x12ae1af72ab66511,
                                                        0xea6de324a3d3a464,
                                                        0x9e146570470f1767,
                                                        0x221d15a622bf36da,
                                                        0x4f1970c66bed0ded};
   constexpr std::array<const uint64_t, WORDS_448> y = {0x9808795bf230fa14,
                                                        0xfdbd132c4ed7c8ad,
                                                        0x3ad3ff1ce67c39c4,
                                                        0x87789c1e05a0c2d7,
                                                        0x4bea73736ca39840,
                                                        0x8876203756c9c762,
                                                        0x693f46716eb6bc24};
   return Ed448Point(Gf448Elem(x), Gf448Elem(y));
}

std::array<uint8_t, ED448_LEN> Ed448Point::encode() const {
   std::array<uint8_t, ED448_LEN> res_buf = {0};

   // A single inversion of Z yields both affine coordinates
   const auto z_inv = Gf448Elem::one() / m_z;
   const auto x = m_x * z_inv;
   const auto y = m_y * z_inv;

   // RFC 8032 5.2.2
   //    All values are coded as octet strings, and integers are coded using
   //    little-endian convention. [...]
   //    First, encode the y-coordinate as a little-endian string of 57 octets.
   //    The final octet is always zero.
   y.to_bytes(std::span(res_buf).first<56>());

   //    To form the encoding of the point, copy the least significant bit of
   //    the x-coordinate to the most significant bit of the final octet.
   res_buf.back() = (static_cast<uint8_t>(x.is_odd()) << 7);

   return res_buf;
}

Ed448Point Ed448Point::operator+(const Ed448Point& other) const {
   // RFC 8032 5.2.4. - Point Addition (Add)
   const Gf448Elem A = m_z * other.m_z;
   const Gf448Elem B = square(A);
   const Gf448Elem C = m_x * other.m_x;
   const Gf448Elem D = m_y * other.m_y;
   const Gf448Elem E = -mul_a24(C * D);
   const Gf448Elem F = B - E;
   const Gf448Elem G = B + E;
   const Gf448Elem H = (m_x + m_y) * (other.m_x + other.m_y);
   const Gf448Elem X3 = A * F * (H - C - D);
   const Gf448Elem Y3 = A * G * (D - C);
   const Gf448Elem Z3 = F * G;

   return Ed448Point(X3, Y3, Z3);
}

Ed448Point Ed448Point::double_point() const {
   // RFC 8032 5.2.4. - Point Addition (Double)
   const Gf448Elem B = square(m_x + m_y);
   const Gf448Elem C = square(m_x);
   const Gf448Elem D = square(m_y);
   const Gf448Elem E = C + D;
   const Gf448Elem H = square(m_z);
   const Gf448Elem J = E - (H + H);
   const Gf448Elem X3 = (B - E) * J;
   const Gf448Elem Y3 = E * (C - D);
   const Gf448Elem Z3 = E * J;

   return Ed448Point(X3, Y3, Z3);
}

Ed448Point Ed448Point::scalar_mul(const Scalar448& s) const {
   // 4-bit windowed scalar multiplication.
   std::array<Ed448Point, 16> table = {Ed448Point::identity(),
                                       *this,
                                       Ed448Point::identity(),
                                       Ed448Point::identity(),
                                       Ed448Point::identity(),
                                       Ed448Point::identity(),
                                       Ed448Point::identity(),
                                       Ed448Point::identity(),
                                       Ed448Point::identity(),
                                       Ed448Point::identity(),
                                       Ed448Point::identity(),
                                       Ed448Point::identity(),
                                       Ed448Point::identity(),
                                       Ed448Point::identity(),
                                       Ed448Point::identity(),
                                       Ed448Point::identity()};

   for(size_t i = 2; i < 16; ++i) {
      if(i % 2 == 0) {
         table[i] = table[i / 2].double_point();
      } else {
         table[i] = table[i - 1] + *this;
      }
   }

   // Process 448 bits (446-bit scalar + 2 leading zero bits) in 112 4-bit windows
   auto res = Ed448Point::identity();

   for(int window = 111; window >= 0; --window) {
      // Double 4 times
      res = res.double_point();
      res = res.double_point();
      res = res.double_point();
      res = res.double_point();

      // Extract 4-bit window value. Bits at position >= 446 are zero.
      const uint64_t w = s.get_window(static_cast<size_t>(window) * 4, 4);

      // Constant-time table lookup
      auto selected = Ed448Point::identity();
      for(size_t i = 0; i < 16; ++i) {
         const auto correct_idx = CT::Mask<uint64_t>::is_equal(static_cast<uint64_t>(i), w);
         selected.ct_conditional_assign(correct_idx, table[i]);
      }

      res = res + selected;
   }

   return res;
}

Ed448Point Ed448Point::base_point_mul(const Scalar448& scalar) {
   /*
   Fixed base point multiplication

   Same idea as base point multiply used in pcurves
   */
   constexpr size_t W = 4;
   constexpr size_t WindowElements = (1 << W) - 1;         // 15
   constexpr size_t Windows = (448 + W - 1) / W;           // 112
   constexpr size_t TableSize = Windows * WindowElements;  // 1680

   static const auto table = []() {
      std::vector<Ed448Point> tbl(TableSize, Ed448Point::identity());

      auto accum = Ed448Point::base_point();

      for(size_t i = 0; i < TableSize; i += WindowElements) {
         tbl[i] = accum;

         for(size_t j = 1; j < WindowElements; ++j) {
            if(j % 2 == 1) {
               tbl[i + j] = tbl[i + j / 2].double_point();
            } else {
               tbl[i + j] = tbl[i + j - 1] + tbl[i];
            }
         }

         accum = tbl[i + (WindowElements / 2)].double_point();
      }

      return tbl;
   }();

   auto res = Ed448Point::identity();

   for(size_t i = 0; i != Windows; ++i) {
      const uint8_t w = static_cast<uint8_t>(scalar.get_window(i * W, W));

      // Constant-time table lookup from this window's 15-entry subtable
      auto selected = Ed448Point::identity();
      for(size_t j = 0; j != WindowElements; ++j) {
         const auto assign = CT::Mask<uint64_t>::is_equal(j + 1, w);
         selected.ct_conditional_assign(assign, table[i * WindowElements + j]);
      }

      res = res + selected;
   }

   return res;
}

Ed448Point Ed448Point::double_scalar_mul_vartime(const Scalar448& s1,
                                                 const Ed448Point& p1,
                                                 const Scalar448& s2,
                                                 const Ed448Point& p2) {
   // 2-bit 2-ary Shamir's trick (variable time)
   // Process 2 bits from each scalar per iteration, using a 16-entry table.
   // table[w1 | (w2 << 2)] = w1*p1 + w2*p2, for w1,w2 in 0..3.

   // Precompute small multiples of each point
   const auto p1x2 = p1.double_point();
   const auto p1x3 = p1x2 + p1;
   const auto p2x2 = p2.double_point();
   const auto p2x3 = p2x2 + p2;

   // Build table indexed by (w2 << 2) | w1, excluding identity at index 0
   const std::array<Ed448Point, 15> table = {
      p1,           // 1*p1 + 0*p2
      p1x2,         // 2*p1 + 0*p2
      p1x3,         // 3*p1 + 0*p2
      p2,           // 0*p1 + 1*p2
      p1 + p2,      // 1*p1 + 1*p2
      p1x2 + p2,    // 2*p1 + 1*p2
      p1x3 + p2,    // 3*p1 + 1*p2
      p2x2,         // 0*p1 + 2*p2
      p1 + p2x2,    // 1*p1 + 2*p2
      p1x2 + p2x2,  // 2*p1 + 2*p2
      p1x3 + p2x2,  // 3*p1 + 2*p2
      p2x3,         // 0*p1 + 3*p2
      p1 + p2x3,    // 1*p1 + 3*p2
      p1x2 + p2x3,  // 2*p1 + 3*p2
      p1x3 + p2x3,  // 3*p1 + 3*p2
   };

   auto res = Ed448Point::identity();

   // 446 bits / 2 = 223 windows, covering bit positions 0..445
   for(int window = 222; window >= 0; --window) {
      res = res.double_point();
      res = res.double_point();

      const size_t bit_pos = static_cast<size_t>(window) * 2;
      const size_t idx = s1.get_window(bit_pos, 2) | (s2.get_window(bit_pos, 2) << 2);

      if(idx > 0) {
         res = res + table[idx - 1];
      }
   }

   return res;
}

bool Ed448Point::operator==(const Ed448Point& other) const {
   // Compare in projective coordinates: (X1:Y1:Z1) == (X2:Y2:Z2)
   // iff X1*Z2 == X2*Z1 && Y1*Z2 == Y2*Z1
   // This avoids two field inversions that x() and y() would require.
   const auto lhs_x = m_x * other.m_z;
   const auto rhs_x = other.m_x * m_z;
   const auto lhs_y = m_y * other.m_z;
   const auto rhs_y = other.m_y * m_z;

   const auto mask_x = CT::Mask<uint8_t>::expand_bool(lhs_x == rhs_x);
   const auto mask_y = CT::Mask<uint8_t>::expand_bool(lhs_y == rhs_y);

   return (mask_x & mask_y).as_bool();
}

void Ed448Point::ct_conditional_assign(CT::Mask<uint64_t> mask, const Ed448Point& other) {
   m_x.ct_cond_assign(mask, other.m_x);
   m_y.ct_cond_assign(mask, other.m_y);
   m_z.ct_cond_assign(mask, other.m_z);
}

Ed448Point operator*(const Scalar448& lhs, const Ed448Point& rhs) {
   return rhs.scalar_mul(lhs);
}

}  // namespace Botan
