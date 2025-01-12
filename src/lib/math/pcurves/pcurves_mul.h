/*
* (C) 2024,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PCURVES_MUL_H_
#define BOTAN_PCURVES_MUL_H_

#include <botan/types.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/pcurves_algos.h>
#include <vector>

namespace Botan {

class RandomNumberGenerator;

/*
* Multiplication algorithm window size parameters
*/

static constexpr size_t BasePointWindowBits = 5;
static constexpr size_t VarPointWindowBits = 4;
static constexpr size_t Mul2PrecompWindowBits = 3;
static constexpr size_t Mul2WindowBits = 2;

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
         if(j % 2 == 1) {
            table.emplace_back(table[i + j / 2].dbl());
         } else {
            table.emplace_back(table[i + j - 1] + table[i]);
         }
      }

      accum = table[i + (WindowElements / 2)].dbl();
   }

   return to_affine_batch<C>(table);
}

template <typename C, size_t WindowBits, typename BlindedScalar>
typename C::ProjectivePoint basemul_exec(std::span<const typename C::AffinePoint> table,
                                         const BlindedScalar& scalar,
                                         RandomNumberGenerator& rng) {
   // 2^W elements, less the identity element
   static constexpr size_t WindowElements = (1 << WindowBits) - 1;

   // TODO: C++23 - use std::mdspan to access table?

   auto accum = [&]() {
      const size_t w_0 = scalar.get_window(0);
      const auto tbl_0 = table.first(WindowElements);
      auto pt = C::ProjectivePoint::from_affine(C::AffinePoint::ct_select(tbl_0, w_0));
      CT::poison(pt);
      pt.randomize_rep(rng);
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

      if(i <= 3) {
         accum.randomize_rep(rng);
      }
   }

   CT::unpoison(accum);
   return accum;
}

/*
* Variable point table mul setup and online phase
*/
template <typename C, size_t TableSize>
std::vector<typename C::AffinePoint> varpoint_setup(const typename C::AffinePoint& p) {
   static_assert(TableSize > 2);

   std::vector<typename C::ProjectivePoint> table;
   table.reserve(TableSize);
   table.push_back(C::ProjectivePoint::from_affine(p));

   for(size_t i = 1; i != TableSize; ++i) {
      if(i % 2 == 1) {
         table.push_back(table[i / 2].dbl());
      } else {
         table.push_back(table[i - 1] + p);
      }
   }

   return to_affine_batch<C>(table);
}

template <typename C, size_t WindowBits, typename BlindedScalar>
typename C::ProjectivePoint varpoint_exec(std::span<const typename C::AffinePoint> table,
                                          const BlindedScalar& scalar,
                                          RandomNumberGenerator& rng) {
   const size_t windows = (scalar.bits() + WindowBits - 1) / WindowBits;

   auto accum = [&]() {
      const size_t w_0 = scalar.get_window((windows - 1) * WindowBits);
      auto pt = C::ProjectivePoint::from_affine(C::AffinePoint::ct_select(table, w_0));
      CT::poison(pt);
      pt.randomize_rep(rng);
      return pt;
   }();

   for(size_t i = 1; i != windows; ++i) {
      accum = accum.dbl_n(WindowBits);
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

      accum += C::AffinePoint::ct_select(table, w_i);

      if(i <= 3) {
         accum.randomize_rep(rng);
      }
   }

   CT::unpoison(accum);
   return accum;
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
std::vector<typename C::AffinePoint> mul2_setup(const typename C::AffinePoint& p, const typename C::AffinePoint& q) {
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

      // Returns x_i * x + y_i * y
      auto next_tbl_e = [&]() {
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

   return to_affine_batch<C>(table);
}

template <typename C, size_t WindowBits, typename BlindedScalar>
typename C::ProjectivePoint mul2_exec(std::span<const typename C::AffinePoint> table,
                                      const BlindedScalar& x,
                                      const BlindedScalar& y,
                                      RandomNumberGenerator& rng) {
   const size_t Windows = (x.bits() + WindowBits - 1) / WindowBits;

   auto accum = [&]() {
      const size_t w_1 = x.get_window((Windows - 1) * WindowBits);
      const size_t w_2 = y.get_window((Windows - 1) * WindowBits);
      const size_t window = w_1 + (w_2 << WindowBits);
      auto pt = C::ProjectivePoint::from_affine(C::AffinePoint::ct_select(table, window));
      CT::poison(pt);
      pt.randomize_rep(rng);
      return pt;
   }();

   for(size_t i = 1; i != Windows; ++i) {
      accum = accum.dbl_n(WindowBits);

      const size_t w_1 = x.get_window((Windows - i - 1) * WindowBits);
      const size_t w_2 = y.get_window((Windows - i - 1) * WindowBits);
      const size_t window = w_1 + (w_2 << WindowBits);
      accum += C::AffinePoint::ct_select(table, window);

      if(i <= 3) {
         accum.randomize_rep(rng);
      }
   }

   CT::unpoison(accum);
   return accum;
}

}  // namespace Botan

#endif
