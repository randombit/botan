/*
* (C) 2024,2025,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PCURVES_MUL_H_
#define BOTAN_PCURVES_MUL_H_

#include <botan/types.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/pcurves_algos.h>
#include <span>
#include <vector>

namespace Botan {

/*
* Multiplication algorithm window size parameters
*/

static constexpr size_t BasePointWindowBits = 6;
static constexpr size_t VarPointWindowBits = 4;
static constexpr size_t Mul2VartimeWindowBits = 5;
static constexpr size_t Mul2PrecompWindowBits = 3;
static constexpr size_t Mul2WindowBits = 2;

/**
* Return number of blinding bits to use
*
* This can return any value between 0 and the scalar bit length.
*
* The field arithmetic and scalar multiplication algorithms are anyway written and tested
* to be constant time; blinding is just used as a safety net in the case that the compiler
* rewrites constant time code to include variable time behavior. If utmost performance is
* of concern and you are in a position to test that your specific compiler for your
* specific architecture is not inserting variable time behavior where not expected (for
* example by using the existing valgrind-based CT checking) it is safe to modify this
* function to just return 0, or some very small blinding factor of 1-4 bits.
*/
constexpr size_t scalar_blinding_bits(size_t scalar_bits) {
   // For blinding use 1/8 the order length for most curves; for P-521 we round down a bit
   // so the masked scalar fits exactly in 9 or 18 words.

   if(scalar_bits == 521) {
      return 55;
   } else {
      return scalar_bits / 8;
   }
}

/*
* Base point precomputation table
*
* This algorithm works by precomputing a set of points such that
* the online phase of the point multiplication can be effected by
* a sequence of point additions.
*
* The tables, even for W = 1, are large and costly to precompute, so
* this is only used for the base point.
*
* The online phase of the algorithm uess `ceil(SB/W)` additions,
* and no point doublings. The table is of size
* `ceil(SB + W - 1)/W * ((1 << W) - 1)`
* where SB is the bit length of the (blinded) scalar.
*
* Each window of the scalar is associated with a window in the table.
* The table windows are unique to that offset within the scalar.
*
* The simplest version to understand is when W = 1. There the table
* consists of [P, 2*P, 4*P, ..., 2^N*P] where N is the bit length of
* the group order. The online phase consists of conditionally adding
* table[i] depending on if bit i of the scalar is set or not.
*
* When W = 2, the scalar is examined 2 bits at a time, and the table
* for a window index `I` is [(2^I)*P, (2^(I+1))*P, (2^I+2^(I+1))*P].
*
* This extends similarly for larger W
*
* At a certain point, the side channel silent table lookup becomes the
* dominating cost
*
* For all W, each window in the table has an implicit element of
* the identity element which is used if the scalar bits were all zero.
* This is omitted to save space; AffinePoint::ct_select is designed
* to assist in this by returning the identity element if its index
* argument is zero, or otherwise it returns table[idx - 1]
*/
template <typename C, size_t WindowBits>
std::vector<typename C::AffinePoint> basemul_setup(const typename C::AffinePoint& p, size_t max_scalar_bits) {
   static_assert(WindowBits >= 1 && WindowBits <= 8);

   // 2^W elements, less the identity element
   constexpr size_t WindowElements = (1 << WindowBits) - 1;

   const size_t Windows = (max_scalar_bits + WindowBits - 1) / WindowBits;

   const size_t TableSize = Windows * WindowElements;

   std::vector<typename C::ProjectivePoint> table;
   table.reserve(TableSize);

   auto accum = C::ProjectivePoint::from_affine(p);

   for(size_t i = 0; i != TableSize; i += WindowElements) {
      table.push_back(accum);

      for(size_t j = 1; j != WindowElements; ++j) {
         // Conditional ok: loop iteration count is public
         if(j % 2 == 1) {
            table.emplace_back(table[i + j / 2].dbl());
         } else {
            table.emplace_back(table[i + j - 1] + table[i]);
         }
      }

      accum = table[i + (WindowElements / 2)].dbl();
   }

   // Variable time batch conversion is fine since generator is public
   return to_affine_batch<C, true>(table);
}

template <typename C, size_t WindowBits, typename BlindedScalar, typename Blinding>
typename C::ProjectivePoint basemul_exec(std::span<const typename C::AffinePoint> table,
                                         const BlindedScalar& scalar,
                                         const Blinding& blinding) {
   // 2^W elements, less the identity element
   static constexpr size_t WindowElements = (1 << WindowBits) - 1;

   // TODO: C++23 - use std::mdspan to access table?

   auto accum = [&]() {
      const size_t w_0 = scalar.get_window(0);
      const auto tbl_0 = table.first(WindowElements);
      auto pt = C::ProjectivePoint::from_affine(C::AffinePoint::ct_select(tbl_0, w_0));
      CT::poison(pt);
      blinding.randomize_rep(pt, 0);
      return pt;
   }();

   const size_t windows = (scalar.bits() + WindowBits - 1) / WindowBits;

   for(size_t i = 1; i != windows; ++i) {
      const size_t w_i = scalar.get_window(WindowBits * i);
      const auto tbl_i = table.subspan(WindowElements * i, WindowElements);

      /*
      None of these additions can be doublings, because in each iteration, the
      discrete logarithms of the points we're selecting out of the table are
      larger than the largest possible dlog of accum.
      */
      accum += C::AffinePoint::ct_select(tbl_i, w_i);

      // Conditional ok: loop iteration count is public
      if(i < Blinding::Rerandomizations) {
         blinding.randomize_rep(accum, i);
      }
   }

   CT::unpoison(accum);
   return accum;
}

/*
* Base point precomputation table with Booth recoding
*
* Same structure as basemul, but uses Booth recoding to halve the
* table size per window. Instead of storing 2^W - 1 entries per
* window, we store 2^(W-1) entries (multiples 1..2^(W-1) of the
* window base point). The sign is handled by conditional negation
* after the constant-time table lookup.
*
* The scalar is prepared with one extra blinding bit (WindowBits+1),
* and windows overlap by one bit to allow carry propagation from
* the Booth encoding.
*/
template <typename C, size_t WindowBits>
std::vector<typename C::AffinePoint> basemul_booth_setup(const typename C::AffinePoint& p, size_t max_scalar_bits) {
   static_assert(WindowBits >= 1 && WindowBits <= 8);

   // 2^(W-1) elements per window [1*base .. 2^(W-1)*base]
   constexpr size_t WindowElements = 1 << (WindowBits - 1);

   const size_t Windows = (max_scalar_bits + WindowBits - 1) / WindowBits;

   const size_t TableSize = Windows * WindowElements;

   std::vector<typename C::ProjectivePoint> table;
   table.reserve(TableSize);

   auto accum = C::ProjectivePoint::from_affine(p);

   for(size_t i = 0; i != TableSize; i += WindowElements) {
      table.push_back(accum);

      for(size_t j = 1; j != WindowElements; ++j) {
         // Conditional ok: loop iteration count is public
         if(j % 2 == 1) {
            table.emplace_back(table[i + j / 2].dbl());
         } else {
            table.emplace_back(table[i + j - 1] + table[i]);
         }
      }

      // Advance to next window's base: 2^W * current_base
      // The last entry is 2^(W-1) * base, so doubling gives 2^W * base
      accum = table[i + WindowElements - 1].dbl();
   }

   // Variable time batch conversion is fine since generator is public
   return to_affine_batch<C, true>(table);
}

template <typename C, size_t WindowBits, typename BlindedScalar, typename Blinding>
typename C::ProjectivePoint basemul_booth_exec(std::span<const typename C::AffinePoint> table,
                                               const BlindedScalar& scalar,
                                               const Blinding& blinding) {
   static constexpr size_t WindowElements = 1 << (WindowBits - 1);

   const size_t windows = (scalar.bits() + WindowBits) / WindowBits;

   auto accum = [&]() {
      // First window: extract W bits, shift left 1 to insert implicit carry in of zero
      const size_t w_bits = scalar.get_window(0) & ((1 << WindowBits) - 1);
      const size_t raw = w_bits << 1;
      const auto [tidx, tneg] = booth_recode<WindowBits>(raw);
      const auto tbl_0 = table.first(WindowElements);

      auto pt = C::ProjectivePoint::from_affine(C::AffinePoint::ct_select(tbl_0, tidx));
      pt.conditional_assign(tneg, pt.negate());
      CT::poison(pt);
      blinding.randomize_rep(pt, 0);
      return pt;
   }();

   for(size_t i = 1; i != windows; ++i) {
      // Extract W+1 bits overlapping by 1 with the previous window
      const size_t bit_pos = WindowBits * i - 1;
      const size_t raw = scalar.get_window(bit_pos);
      const auto [tidx, tneg] = booth_recode<WindowBits>(raw);

      const auto tbl_i = table.subspan(WindowElements * i, WindowElements);

      accum = C::ProjectivePoint::add_or_sub(accum, C::AffinePoint::ct_select(tbl_i, tidx), tneg);

      // Conditional ok: loop iteration count is public
      if(i < Blinding::Rerandomizations) {
         blinding.randomize_rep(accum, i);
      }
   }

   CT::unpoison(accum);
   return accum;
}

/*
* Variable time base point multiplication using the Booth table
*
* Returns accum + s*P. The scalar is read directly, without blinding or
* constant time table lookups, so this is only usable when s is public
* (eg during signature verification).
*/
template <typename C, size_t WindowBits, typename ScalarBits>
typename C::ProjectivePoint basemul_booth_exec_vartime(std::span<const typename C::AffinePoint> table,
                                                       const ScalarBits& scalar,
                                                       typename C::ProjectivePoint accum) {
   static constexpr size_t WindowElements = 1 << (WindowBits - 1);

   const size_t windows = (scalar.bits() + WindowBits) / WindowBits;
   BOTAN_DEBUG_ASSERT(windows * WindowElements <= table.size());

   for(size_t i = 0; i != windows; ++i) {
      // Extract W+1 bits overlapping by 1 with the previous window; the
      // first window has an implicit carry in of zero
      const size_t raw =
         (i == 0) ? ((scalar.get_window(0) & ((1 << WindowBits) - 1)) << 1) : scalar.get_window(WindowBits * i - 1);

      const auto [tidx, tneg] = booth_recode<WindowBits>(raw);

      // Conditional ok: this function is variable time
      if(tidx > 0) {
         accum = C::ProjectivePoint::add_or_sub(accum, table[WindowElements * i + tidx - 1], tneg);
      }
   }

   return accum;
}

/*
* Point table with a shared Z coordinate
*
* Using table points in mixed additions requires affine coordinates, but
* converting to affine requires a field inversion. Instead the points are
* rescaled so that they all share a single Z coordinate Zt, which needs only
* multiplications.
*
* The map (x,y) -> (Zt^2*x, Zt^3*y) is an isomorphism from the curve
* y^2 = x^3 + a*x + b onto the curve y^2 = x^3 + (a*Zt^4)*x + (b*Zt^6), and
* under this map the Jacobian point (X, Y, Zt) becomes the affine point (X, Y).
* So the table entries can be used directly as affine points, provided that
* all doublings use the coefficient a*Zt^4 (see dbl_n_iso and add_or_sub_iso,
* which covers the doubling fallback inside the addition formula). A result
* (X, Y, Z) on the isomorphic curve maps back to (X, Y, Z*Zt) on the original
* curve.
*
* Zt includes a random factor u, so the table entries and the isomorphic curve
* differ between multiplications even for a fixed input point. This is the
* random curve isomorphism countermeasure of Joye and Tymen (CHES 2001).
*/
template <typename C>
class SharedZPointTable final {
   public:
      using AffinePoint = typename C::AffinePoint;
      using ProjectivePoint = typename C::ProjectivePoint;
      using FieldElement = typename C::FieldElement;

      /**
      * Table of the multiples [P, 2*P, ..., n*P]
      *
      * The multiples are computed as a chain of mixed additions, each of which
      * multiplies Z by a known value H, so the rescaling factors Zt/Z_i are
      * products of H values.
      *
      * @param p the point whose multiples are tabulated
      * @param n the number of multiples
      * @param a the a coefficient of the curve
      * @param u the random isomorphism parameter, which must be nonzero
      */
      SharedZPointTable(const AffinePoint& p, size_t n, const FieldElement& a, const FieldElement& u) :
            SharedZPointTable(build(p, n, a, u)) {}

      /**
      * Table of arbitrary points
      *
      * Here Zt is the product of the Z coordinates, and the rescaling factors
      * Zt/Z_i are computed using prefix and suffix products. Identity elements
      * are excluded from the product and remain the identity.
      *
      * @param pts the points to tabulate
      * @param a the a coefficient of the curve
      * @param one the field element 1
      * @param u the random isomorphism parameter, which must be nonzero
      */
      SharedZPointTable(std::span<const ProjectivePoint> pts,
                        const FieldElement& a,
                        const FieldElement& one,
                        const FieldElement& u) :
            SharedZPointTable(build(pts, a, one, u)) {}

      /**
      * If idx is zero then return the identity element. Otherwise return pts[idx - 1]
      */
      AffinePoint ct_select(size_t idx) const { return AffinePoint::ct_select(m_table, idx); }

      /**
      * Return the shared Z coordinate
      */
      const FieldElement& z() const { return m_z; }

      /**
      * Return the a coefficient of the isomorphic curve, a*z^4
      */
      const FieldElement& a() const { return m_a; }

   private:
      struct Table {
            std::vector<AffinePoint> pts;
            FieldElement z;
            FieldElement a;
      };

      explicit SharedZPointTable(Table t) : m_table(std::move(t.pts)), m_z(t.z), m_a(t.a) {}

      // Return the affine point corresponding to pt after multiplying its Z by f
      static AffinePoint rescale(const ProjectivePoint& pt, const FieldElement& f) {
         const auto f2 = f.square();
         const auto f3 = f2 * f;
         return AffinePoint(pt.x() * f2, pt.y() * f3);
      }

      static Table finish(std::vector<AffinePoint> pts, const FieldElement& zt, const FieldElement& a) {
         const auto zt2 = zt.square();
         return Table{std::move(pts), zt, a * zt2.square()};
      }

      static Table build(const AffinePoint& p, size_t n, const FieldElement& a, const FieldElement& u) {
         BOTAN_ASSERT_NOMSG(n > 2);

         // Chain P, 2*P, 3*P, ... where Z_i = Z_{i-1} * H_i for i >= 2
         std::vector<ProjectivePoint> chain;
         chain.reserve(n);
         // h[i - 2] = H_i
         std::vector<FieldElement> h;
         h.reserve(n - 2);

         chain.push_back(ProjectivePoint::from_affine(p));
         chain.push_back(chain[0].dbl());
         for(size_t i = 2; i != n; ++i) {
            const auto pt_h = ProjectivePoint::add_mixed_h(chain[i - 1], p);
            chain.push_back(pt_h.first);
            h.push_back(pt_h.second);
         }

         // The shared Z is u * Z_{n-1}
         const FieldElement zt = u * chain[n - 1].z();

         // Built in reverse order since the scaling factors are suffix products
         std::vector<AffinePoint> pts;
         pts.reserve(n);

         // The last entry is scaled by u alone
         pts.push_back(rescale(chain[n - 1], u));

         // Entry i is scaled by Zt/Z_i = u * H_{i+1} * ... * H_{n-1}
         FieldElement mu = u * h[n - 3];
         for(size_t i = n - 2; i > 0; --i) {
            // Conditional ok: loop iteration count is public
            if(i != n - 2) {
               mu *= h[i - 1];
            }
            pts.push_back(rescale(chain[i], mu));
         }

         // Entry 0 is P itself with Z = 1, so it is scaled by Zt
         pts.push_back(rescale(chain[0], zt));

         std::reverse(pts.begin(), pts.end());

         return finish(std::move(pts), zt, a);
      }

      static Table build(std::span<const ProjectivePoint> pts,
                         const FieldElement& a,
                         const FieldElement& one,
                         const FieldElement& u) {
         const size_t n = pts.size();
         BOTAN_ASSERT_NOMSG(n > 0);

         // Identity elements have Z = 0; use 1 instead so they do not zero the products
         std::vector<FieldElement> z;
         z.reserve(n);
         for(const auto& pt : pts) {
            auto z_i = pt.z();
            z_i.conditional_assign(pt.is_identity(), one);
            z.push_back(z_i);
         }

         // prefix[i] = z_0 * ... * z_i
         std::vector<FieldElement> prefix;
         prefix.reserve(n);
         prefix.push_back(z[0]);
         for(size_t i = 1; i != n; ++i) {
            prefix.push_back(prefix[i - 1] * z[i]);
         }

         // The shared Z is u * z_0 * ... * z_{n-1}
         const FieldElement zt = u * prefix[n - 1];

         // Entry i is scaled by Zt/Z_i = u * prefix[i-1] * z_{i+1} * ... * z_{n-1};
         // built in reverse order since the second part is a suffix product
         std::vector<AffinePoint> scaled;
         scaled.reserve(n);

         FieldElement suffix = u;
         for(size_t i = n; i > 0; --i) {
            const size_t idx = i - 1;

            auto pt = [&]() {
               // Conditional ok: idx is public
               if(idx == 0) {
                  return rescale(pts[idx], suffix);
               } else {
                  return rescale(pts[idx], prefix[idx - 1] * suffix);
               }
            }();
            pt.conditional_assign(pts[idx].is_identity(), AffinePoint::identity(pt));
            scaled.push_back(pt);

            suffix *= z[idx];
         }

         std::reverse(scaled.begin(), scaled.end());

         return finish(std::move(scaled), zt, a);
      }

      std::vector<AffinePoint> m_table;
      FieldElement m_z;
      FieldElement m_a;
};

/*
* Variable point table mul online phase
*/
template <typename C, size_t WindowBits, typename BlindedScalar, typename Blinding>
typename C::ProjectivePoint varpoint_exec(const SharedZPointTable<C>& table,
                                          const BlindedScalar& scalar,
                                          const Blinding& blinding) {
   const size_t windows = (scalar.bits() + WindowBits - 1) / WindowBits;

   auto accum = [&]() {
      const size_t w_0 = scalar.get_window((windows - 1) * WindowBits);
      auto pt = C::ProjectivePoint::from_affine(table.ct_select(w_0));
      CT::poison(pt);
      blinding.randomize_rep(pt, 0);
      return pt;
   }();

   for(size_t i = 1; i != windows; ++i) {
      accum = accum.dbl_n_iso(table.a(), WindowBits);
      auto w_i = scalar.get_window((windows - i - 1) * WindowBits);

      /*
      This point addition cannot be a doubling (except once)

      Consider the sequence of points that are operated on, and specifically
      their discrete logarithms. We start out at the point at infinity
      (dlog 0) and then add the initial window which is precisely P*w_0

      We then perform WindowBits doublings, so accum's dlog at the point
      of the addition in the first iteration of the loop (when i == 1) is
      at least 2^W * w_0.

      Since we know w_0 > 0, then in every iteration of the loop, accums
      dlog will always be greater than the dlog of the table element we
      just looked up (something between 0 and 2^W-1), and thus the
      addition into accum cannot be a doubling.

      However due to blinding this argument fails, since we perform
      multiplications using a scalar that is larger than the group
      order. In this case it's possible that the dlog of accum becomes
      `order + x` (or, effectively, `x`) and `x` is smaller than 2^W.
      In this case, a doubling may occur. Future iterations of the loop
      cannot be doublings by the same argument above. Since the blinding
      factor is always less than the group order (substantially so),
      it is not possible for the dlog of accum to overflow a second time.
      */

      accum = C::ProjectivePoint::add_mixed_iso(accum, table.ct_select(w_i), table.a());

      // Conditional ok: loop iteration count is public
      if(i < Blinding::Rerandomizations) {
         blinding.randomize_rep(accum, i);
      }
   }

   CT::unpoison(accum);

   // Map back from the isomorphic curve
   return typename C::ProjectivePoint(accum.x(), accum.y(), accum.z() * table.z());
}

/*
* Variable time table of odd multiples of a point
*
* Returns [P, 3*P, 5*P, ..., (2^(W-1) - 1)*P], which covers the digits of a
* width W non-adjacent form.
*/
template <typename C, size_t W>
std::vector<typename C::AffinePoint> odd_multiples_setup_vartime(const typename C::AffinePoint& p) {
   static_assert(W >= 2 && W <= 7);

   constexpr size_t TableSize = 1 << (W - 2);

   std::vector<typename C::ProjectivePoint> table;
   table.reserve(TableSize);

   const auto p2 = C::ProjectivePoint::from_affine(p).dbl();

   table.push_back(C::ProjectivePoint::from_affine(p));
   for(size_t i = 1; i != TableSize; ++i) {
      table.push_back(table[i - 1] + p2);
   }

   // Variable time batch conversion is fine since the point is public
   return to_affine_batch<C, true>(table);
}

/*
* Effect 2-ary multiplication ie x*G + y*H
*
* This is done using a windowed variant of what is usually called
* Shamir's trick.
*
* The W = 1 case is simple; we precompute an extra point GH = G + H,
* and then examine 1 bit in each of x and y. If one or the other bits
* are set then add G or H resp. If both bits are set, add GH.
*
* The example below is a precomputed table for W=2. The flattened table
* begins at (x_i,y_i) = (1,0), i.e. the identity element is omitted.
* The indices in each cell refer to the cell's location in m_table.
*
*  x->           0          1          2         3
*       0  |/ (ident) |0  x     |1  2x      |2  3x     |
*       1  |3    y    |4  x+y   |5  2x+y    |6  3x+y   |
*  y =  2  |7    2y   |8  x+2y  |9  2(x+y)  |10 3x+2y  |
*       3  |11   3y   |12 x+3y  |13 2x+3y   |14 3x+3y  |
*/

template <typename C, size_t WindowBits>
std::vector<typename C::ProjectivePoint> mul2_setup(const typename C::AffinePoint& p,
                                                    const typename C::AffinePoint& q) {
   static_assert(WindowBits >= 1 && WindowBits <= 4);

   // 2^(2*W) elements, less the identity element
   constexpr size_t TableSize = (1 << (2 * WindowBits)) - 1;
   constexpr size_t WindowSize = (1 << WindowBits);

   std::vector<typename C::ProjectivePoint> table;
   table.reserve(TableSize);

   for(size_t i = 0; i != TableSize; ++i) {
      const size_t t_i = (i + 1);
      const size_t p_i = t_i % WindowSize;
      const size_t q_i = (t_i >> WindowBits) % WindowSize;

      // Conditionals ok: all based on t_i/p_i/q_i which in turn are derived from public i

      // Returns x_i * x + y_i * y
      const auto next_tbl_e = [&]() {
         if(p_i % 2 == 0 && q_i % 2 == 0) {
            // Where possible using doubling (eg indices 1, 7, 9 in
            // the table above)
            return table[(t_i / 2) - 1].dbl();
         } else if(p_i > 0 && q_i > 0) {
            // A combination of p and q
            if(p_i == 1) {
               return p + table[(q_i << WindowBits) - 1];
            } else if(q_i == 1) {
               return table[p_i - 1] + q;
            } else {
               return table[p_i - 1] + table[(q_i << WindowBits) - 1];
            }
         } else if(p_i > 0 && q_i == 0) {
            // A multiple of p without a q component
            if(p_i == 1) {
               // Just p
               return C::ProjectivePoint::from_affine(p);
            } else {
               // p * p_{i-1}
               return p + table[p_i - 1 - 1];
            }
         } else if(p_i == 0 && q_i > 0) {
            if(q_i == 1) {
               // Just q
               return C::ProjectivePoint::from_affine(q);
            } else {
               // q * q_{i-1}
               return q + table[((q_i - 1) << WindowBits) - 1];
            }
         } else {
            BOTAN_ASSERT_UNREACHABLE();
         }
      };

      table.emplace_back(next_tbl_e());
   }

   return table;
}

template <typename C, size_t WindowBits, typename BlindedScalar, typename Blinding>
typename C::ProjectivePoint mul2_exec(const SharedZPointTable<C>& table,
                                      const BlindedScalar& x,
                                      const BlindedScalar& y,
                                      const Blinding& blinding) {
   const size_t Windows = (x.bits() + WindowBits - 1) / WindowBits;

   auto accum = [&]() {
      const size_t w_1 = x.get_window((Windows - 1) * WindowBits);
      const size_t w_2 = y.get_window((Windows - 1) * WindowBits);
      const size_t window = w_1 + (w_2 << WindowBits);
      auto pt = C::ProjectivePoint::from_affine(table.ct_select(window));
      CT::poison(pt);
      blinding.randomize_rep(pt, 0);
      return pt;
   }();

   for(size_t i = 1; i != Windows; ++i) {
      accum = accum.dbl_n_iso(table.a(), WindowBits);

      const size_t w_1 = x.get_window((Windows - i - 1) * WindowBits);
      const size_t w_2 = y.get_window((Windows - i - 1) * WindowBits);
      const size_t window = w_1 + (w_2 << WindowBits);
      accum = C::ProjectivePoint::add_mixed_iso(accum, table.ct_select(window), table.a());

      // Conditional ok: loop iteration count is public
      if(i < Blinding::Rerandomizations) {
         blinding.randomize_rep(accum, i);
      }
   }

   CT::unpoison(accum);

   // Map back from the isomorphic curve
   return typename C::ProjectivePoint(accum.x(), accum.y(), accum.z() * table.z());
}

}  // namespace Botan

#endif
