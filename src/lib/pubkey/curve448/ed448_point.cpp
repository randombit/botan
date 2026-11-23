/*
 * Ed448 Point Arithmetic
 * (C) 2024 Jack Lloyd
 *     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */
#include <botan/internal/ed448_point.h>

#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/mp_core.h>
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

namespace {

/**
* An affine point (x, y) of the base point table, along with d*x*y
*/
struct Ed448AffineEntry {
      std::array<uint64_t, WORDS_448> x;
      std::array<uint64_t, WORDS_448> y;
      std::array<uint64_t, WORDS_448> dxy;
};

/**
* A point in extended coordinates (X:Y:Z:T) with x = X/Z, y = Y/Z, x*y = T/Z
*
* See "Twisted Edwards Curves Revisited" (Hisil, Wong, Carter, Dawson, 2008)
*/
class Ed448ExtendedPoint final {
   public:
      static Ed448ExtendedPoint identity() {
         return Ed448ExtendedPoint(Gf448Elem::zero(), Gf448Elem::one(), Gf448Elem::one(), Gf448Elem::zero());
      }

      Ed448ExtendedPoint(const Gf448Elem& x, const Gf448Elem& y, const Gf448Elem& z, const Gf448Elem& t) :
            m_x(x), m_y(y), m_z(z), m_t(t) {}

      Ed448Point to_projective() const { return Ed448Point(m_x, m_y, m_z); }

      // madd-2008-hwcd with a = 1
      Ed448ExtendedPoint add_affine(const Gf448Elem& x2, const Gf448Elem& y2, const Gf448Elem& dxy2) const {
         const Gf448Elem A = m_x * x2;
         const Gf448Elem B = m_y * y2;
         const Gf448Elem C = m_t * dxy2;
         const Gf448Elem E = (m_x + m_y) * (x2 + y2) - A - B;
         const Gf448Elem F = m_z - C;
         const Gf448Elem G = m_z + C;
         const Gf448Elem H = B - A;
         return Ed448ExtendedPoint(E * F, G * H, F * G, E * H);
      }

      // dbl-2008-hwcd with a = 1
      Ed448ExtendedPoint double_point() const {
         const Gf448Elem A = square(m_x);
         const Gf448Elem B = square(m_y);
         const Gf448Elem Z2 = square(m_z);
         const Gf448Elem C = Z2 + Z2;
         const Gf448Elem E = square(m_x + m_y) - A - B;
         const Gf448Elem G = A + B;
         const Gf448Elem F = G - C;
         const Gf448Elem H = A - B;
         return Ed448ExtendedPoint(E * F, G * H, F * G, E * H);
      }

   private:
      Gf448Elem m_x;
      Gf448Elem m_y;
      Gf448Elem m_z;
      Gf448Elem m_t;
};

std::vector<Ed448AffineEntry> to_affine_entries(const std::vector<Ed448Point>& pts) {
   // Montgomery's trick: one inversion for all of the points
   std::vector<Gf448Elem> z_prod;
   z_prod.reserve(pts.size());
   z_prod.push_back(pts[0].z_proj());
   for(size_t i = 1; i != pts.size(); ++i) {
      z_prod.push_back(z_prod[i - 1] * pts[i].z_proj());
   }

   auto inv = Gf448Elem::one() / z_prod.back();

   std::vector<Ed448AffineEntry> entries(pts.size());
   for(size_t i = pts.size(); i-- > 0;) {
      auto z_inv = inv;
      if(i > 0) {
         z_inv = inv * z_prod[i - 1];
         inv = inv * pts[i].z_proj();
      }

      const auto x = pts[i].x_proj() * z_inv;
      const auto y = pts[i].y_proj() * z_inv;
      // d = -39081
      const auto dxy = -mul_a24(x * y);

      copy_mem(entries[i].x, x.words());
      copy_mem(entries[i].y, y.words());
      copy_mem(entries[i].dxy, dxy.words());
   }

   return entries;
}

}  // namespace

Ed448Point Ed448Point::base_point_mul(const Scalar448& scalar) {
   /*
   Fixed base point multiplication

   Same idea as base point multiply used in pcurves: Booth recoded W-bit
   digits with a table of affine points. To keep the table small, row j holds
   multiples of 2^(W*Passes*j)*B, so each row serves Passes digits (a comb),
   at the cost of W*(Passes-1) doublings.
   */
   constexpr size_t W = 5;
   constexpr size_t RowElements = 1 << (W - 1);  // 16
   // The top digit's sign bit is at or above bit 446 so it is never negative
   constexpr size_t Digits = (446 + W) / W;  // 90
   constexpr size_t Passes = 3;
   constexpr size_t Rows = Digits / Passes;  // 30
   static_assert(Rows * Passes == Digits);

   static const auto table = []() {
      std::vector<Ed448Point> pts;
      pts.reserve(Rows * RowElements);

      auto row_base = Ed448Point::base_point();

      for(size_t r = 0; r != Rows; ++r) {
         const size_t row = pts.size();
         pts.push_back(row_base);

         for(size_t k = 2; k <= RowElements; ++k) {
            if(k % 2 == 0) {
               pts.push_back(pts[row + k / 2 - 1].double_point());
            } else {
               pts.push_back(pts[row + k - 2] + row_base);
            }
         }

         // 2^(W*Passes) * row_base, starting from the last entry 2^(W-1) * row_base
         row_base = pts.back();
         for(size_t i = 0; i != W * Passes - (W - 1); ++i) {
            row_base = row_base.double_point();
         }
      }

      return to_affine_entries(pts);
   }();

   auto accum = Ed448ExtendedPoint::identity();

   for(size_t pass = Passes; pass-- > 0;) {
      if(pass != Passes - 1) {
         for(size_t i = 0; i != W; ++i) {
            accum = accum.double_point();
         }
      }

      for(size_t r = 0; r != Rows; ++r) {
         const size_t d = Passes * r + pass;

         // The W+1 bit window overlaps the previous one by a bit; the first has an implicit zero below
         const size_t raw = (d == 0) ? (scalar.get_window(0, W) << 1) : scalar.get_window(W * d - 1, W + 1);
         const auto [idx, neg] = booth_recode<W>(raw);

         // Constant time lookup of entry idx, with idx = 0 giving the identity
         std::array<uint64_t, WORDS_448> x{};
         std::array<uint64_t, WORDS_448> y{1};
         std::array<uint64_t, WORDS_448> dxy{};
         for(size_t k = 0; k != RowElements; ++k) {
            const auto found = CT::Mask<uint64_t>::is_equal(k + 1, idx);
            const auto& e = table[r * RowElements + k];
            found.select_n(x.data(), e.x.data(), x.data(), WORDS_448);
            found.select_n(y.data(), e.y.data(), y.data(), WORDS_448);
            found.select_n(dxy.data(), e.dxy.data(), dxy.data(), WORDS_448);
         }

         // -(x, y) = (-x, y)
         const auto neg_mask = CT::Mask<uint64_t>::from_choice(neg);
         auto px = Gf448Elem(x);
         auto pdxy = Gf448Elem(dxy);
         px.ct_cond_assign(neg_mask, -px);
         pdxy.ct_cond_assign(neg_mask, -pdxy);

         accum = accum.add_affine(px, Gf448Elem(y), pdxy);
      }
   }

   return accum.to_projective();
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
