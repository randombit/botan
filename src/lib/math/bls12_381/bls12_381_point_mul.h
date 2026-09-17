/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BLS12_381_POINT_MUL_H_
#define BOTAN_BLS12_381_POINT_MUL_H_

#include <botan/bls12_381.h>
#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/mp_core.h>
#include <algorithm>
#include <utility>
#include <vector>

namespace Botan::BLS12_381 {

// z = -0xd201000000010000 (negative; the Miller loop and final exponentiation
// use |z| and account for the sign by conjugation)
constexpr uint64_t BLS_Z_ABS = 0xD201000000010000;

/**
* Window size heuristic for the Pippenger bucket method,
* approximately ln(n) + 2
*/
inline size_t pippenger_window_bits(size_t n) {
   if(n < 32) {
      return 3;
   }
   size_t log2n = 5;
   while(n >= (static_cast<size_t>(2) << log2n)) {
      ++log2n;
   }
   return std::min<size_t>((log2n * 69) / 100 + 2, 16);
}

/**
* Extract the c-bit window starting at bit offset bit (counted from the
* least significant end) of a big-endian encoded scalar
*/
inline size_t scalar_window_at(std::span<const uint8_t, Scalar::BYTES> bytes, size_t bit, size_t c) {
   size_t digit = 0;
   for(size_t k = 0; k != c; ++k) {
      const size_t b = bit + k;
      if(b >= 8 * Scalar::BYTES) {
         break;
      }
      const uint8_t byte = bytes[Scalar::BYTES - 1 - (b / 8)];
      digit |= static_cast<size_t>((byte >> (b % 8)) & 1) << k;
   }
   return digit;
}

/**
* Extract the Booth recoded window of a serialized scalar; constant time
* with respect to the scalar bytes
*/
inline std::pair<size_t, CT::Choice> scalar_booth_window(std::span<const uint8_t, Scalar::BYTES> bytes,
                                                         size_t window,
                                                         size_t window_bits) {
   const size_t raw = (window == 0) ? (scalar_window_at(bytes, 0, window_bits) << 1)
                                    : scalar_window_at(bytes, window * window_bits - 1, window_bits + 1);
   return booth_recode(raw, window_bits);
}

/**
* The scalar multiplication algorithms, shared by G1 and G2; the group
* specific formulas remain member functions of the point types.
*/
template <typename Pt>
class PointMul final {
   public:
      /**
      * Return pts[idx], without leaking idx
      */
      static Pt ct_select(std::span<const Pt> pts, size_t idx) {
         auto result = Pt::identity();

         for(size_t i = 0; i != pts.size(); ++i) {
            const auto cnd = CT::Mask<word>::is_equal(i, idx).as_choice();
            CT::conditional_assign_mem(cnd, result.m_x.data(), pts[i].m_x.data(), result.m_x.size());
            CT::conditional_assign_mem(cnd, result.m_y.data(), pts[i].m_y.data(), result.m_y.size());
            CT::conditional_assign_mem(cnd, result.m_z.data(), pts[i].m_z.data(), result.m_z.size());
         }

         return result;
      }

      static Pt ct_select_signed(std::span<const Pt> pts, size_t idx, CT::Choice negate) {
         auto result = ct_select(pts, idx);
         result.conditional_negate(negate.into_bitmask<uint32_t>() & 1);
         return result;
      }

      /**
      * Constant time fixed window multiplication
      *
      * Possible optimizations: a precomputed table (cf pcurves
      * PrecomputedBaseMulTable) for the common fixed-base case, and a
      * GLV/psi endomorphism split to roughly halve the doubling count
      */
      static Pt mul(const Pt& pt, const Scalar& scalar) {
         constexpr size_t WINDOW_BITS = 4;
         constexpr size_t TABLE_SIZE = (1 << (WINDOW_BITS - 1)) + 1;
         constexpr size_t WINDOWS = (Scalar::BITS + WINDOW_BITS) / WINDOW_BITS;

         std::array<Pt, TABLE_SIZE> tbl;
         for(size_t i = 1; i != TABLE_SIZE; ++i) {
            tbl[i] = tbl[i - 1].add(pt);
         }

         auto sbytes = scalar.serialize();
         CT::poison(sbytes);

         auto accum = Pt::identity();

         for(size_t i = WINDOWS; i > 0; --i) {
            if(i < WINDOWS) {
               for(size_t j = 0; j != WINDOW_BITS; ++j) {
                  accum = accum.dbl();
               }
            }
            const auto [digit, negate] = scalar_booth_window(sbytes, i - 1, WINDOW_BITS);
            accum = accum.add(ct_select_signed(tbl, digit, negate));
         }

         secure_scrub_memory(sbytes);
         CT::unpoison_all(sbytes, accum.m_x, accum.m_y, accum.m_z);

         return accum;
      }

      /**
      * Constant time a*p + b*q
      */
      static Pt mul2(const Pt& p, const Scalar& a, const Pt& q, const Scalar& b) {
         constexpr size_t WINDOW_BITS = 4;
         constexpr size_t TABLE_SIZE = (1 << (WINDOW_BITS - 1)) + 1;
         constexpr size_t WINDOWS = (Scalar::BITS + WINDOW_BITS) / WINDOW_BITS;

         // Interleaved Strauss-Shamir; both scalars share one doubling chain
         std::array<Pt, TABLE_SIZE> ptbl;
         std::array<Pt, TABLE_SIZE> qtbl;
         for(size_t i = 1; i != TABLE_SIZE; ++i) {
            ptbl[i] = ptbl[i - 1].add(p);
            qtbl[i] = qtbl[i - 1].add(q);
         }

         auto abytes = a.serialize();
         auto bbytes = b.serialize();
         CT::poison_all(abytes, bbytes);

         auto accum = Pt::identity();

         for(size_t i = WINDOWS; i > 0; --i) {
            if(i < WINDOWS) {
               for(size_t j = 0; j != WINDOW_BITS; ++j) {
                  accum = accum.dbl();
               }
            }
            const auto [adigit, anegate] = scalar_booth_window(abytes, i - 1, WINDOW_BITS);
            const auto [bdigit, bnegate] = scalar_booth_window(bbytes, i - 1, WINDOW_BITS);
            accum = accum.add(ct_select_signed(ptbl, adigit, anegate));
            accum = accum.add(ct_select_signed(qtbl, bdigit, bnegate));
         }

         secure_scrub_memory(abytes);
         secure_scrub_memory(bbytes);
         CT::unpoison_all(abytes, bbytes, accum.m_x, accum.m_y, accum.m_z);

         return accum;
      }

      /**
      * Variable time single point multiplication
      */
      static Pt mul_vartime(const Pt& pt, const Scalar& scalar) {
         constexpr size_t WINDOW_BITS = 4;
         constexpr size_t TABLE_SIZE = (1 << (WINDOW_BITS - 1)) + 1;
         constexpr size_t WINDOWS = (Scalar::BITS + WINDOW_BITS) / WINDOW_BITS;

         std::array<Pt, TABLE_SIZE> tbl;
         for(size_t i = 1; i != TABLE_SIZE; ++i) {
            tbl[i] = tbl[i - 1].add(pt);
         }

         auto sbytes = scalar.serialize();

         auto accum = Pt::identity();

         for(size_t i = WINDOWS; i > 0; --i) {
            if(i < WINDOWS) {
               for(size_t j = 0; j != WINDOW_BITS; ++j) {
                  accum = accum.dbl();
               }
            }
            const auto [digit, negate] = scalar_booth_window(sbytes, i - 1, WINDOW_BITS);
            if(digit > 0) {
               accum = accum.add(negate.as_bool() ? tbl[digit].negate() : tbl[digit]);
            }
         }

         secure_scrub_memory(sbytes);

         return accum;
      }

      /**
      * Variable time a*p + b*q
      */
      static Pt mul2_vartime(const Pt& p, const Scalar& a, const Pt& q, const Scalar& b) {
         constexpr size_t WINDOW_BITS = 4;
         constexpr size_t TABLE_SIZE = (1 << (WINDOW_BITS - 1)) + 1;
         constexpr size_t WINDOWS = (Scalar::BITS + WINDOW_BITS) / WINDOW_BITS;

         std::array<Pt, TABLE_SIZE> ptbl;
         std::array<Pt, TABLE_SIZE> qtbl;
         for(size_t i = 1; i != TABLE_SIZE; ++i) {
            ptbl[i] = ptbl[i - 1].add(p);
            qtbl[i] = qtbl[i - 1].add(q);
         }

         auto abytes = a.serialize();
         auto bbytes = b.serialize();

         auto accum = Pt::identity();

         for(size_t i = WINDOWS; i > 0; --i) {
            if(i < WINDOWS) {
               for(size_t j = 0; j != WINDOW_BITS; ++j) {
                  accum = accum.dbl();
               }
            }
            const auto [adigit, anegate] = scalar_booth_window(abytes, i - 1, WINDOW_BITS);
            const auto [bdigit, bnegate] = scalar_booth_window(bbytes, i - 1, WINDOW_BITS);
            if(adigit > 0) {
               accum = accum.add(anegate.as_bool() ? ptbl[adigit].negate() : ptbl[adigit]);
            }
            if(bdigit > 0) {
               accum = accum.add(bnegate.as_bool() ? qtbl[bdigit].negate() : qtbl[bdigit]);
            }
         }

         secure_scrub_memory(abytes);
         secure_scrub_memory(bbytes);

         return accum;
      }

      /**
      * Variable time multiscalar multiplication
      */
      template <typename AffinePt>
      static Pt msm_vartime(std::span<const AffinePt> points, std::span<const Scalar> scalars) {
         if(points.size() != scalars.size()) {
            throw Invalid_Argument("BLS12_381 msm_vartime spans must have equal length");
         }

         if(points.empty()) {
            return Pt::identity();
         }

         // Below this size a chain of 2-ary multiplications beats the
         // Pippenger bucket method (measured crossover; not very sensitive)
         constexpr size_t PIPPENGER_MIN_SIZE = 16;

         if(points.size() < PIPPENGER_MIN_SIZE) {
            auto accum = Pt::identity();
            size_t i = 0;
            for(; i + 2 <= points.size(); i += 2) {
               accum = accum.add(
                  mul2_vartime(Pt::from_affine(points[i]), scalars[i], Pt::from_affine(points[i + 1]), scalars[i + 1]));
            }
            if(i < points.size()) {
               accum = accum.add(mul_vartime(Pt::from_affine(points[i]), scalars[i]));
            }
            return accum;
         }

         // The Pippenger bucket method; process the scalars in c-bit windows
         // from the most significant down, adding each point into the bucket
         // its window digit selects, then form the window sum with a running
         // sum over the buckets.
         const size_t c = pippenger_window_bits(points.size());
         const size_t windows = (Scalar::BITS + c) / c;

         std::vector<std::array<uint8_t, Scalar::BYTES>> sbytes;
         sbytes.reserve(scalars.size());
         for(const auto& scalar : scalars) {
            sbytes.push_back(scalar.serialize());
         }

         std::vector<Pt> buckets(static_cast<size_t>(1) << (c - 1));

         auto accum = Pt::identity();

         for(size_t w = 0; w != windows; ++w) {
            if(w > 0) {
               for(size_t j = 0; j != c; ++j) {
                  accum = accum.dbl();
               }
            }

            std::ranges::fill(buckets, Pt::identity());

            const size_t window = windows - 1 - w;
            for(size_t i = 0; i != points.size(); ++i) {
               const auto [digit, negate] = scalar_booth_window(sbytes[i], window, c);
               if(digit > 0) {
                  buckets[digit - 1] = buckets[digit - 1].add_mixed(points[i], negate.as_bool());
               }
            }

            auto running = Pt::identity();
            auto window_sum = Pt::identity();
            for(size_t b = buckets.size(); b > 0; --b) {
               running = running.add(buckets[b - 1]);
               window_sum = window_sum.add(running);
            }

            accum = accum.add(window_sum);
         }

         secure_scrub_memory(sbytes.data(), sbytes.size() * Scalar::BYTES);

         return accum;
      }

      /**
      * Multiplication by |z|, the absolute value of the BLS parameter,
      * used for the subgroup checks and cofactor clearing
      */
      static Pt mul_by_z_abs(const Pt& pt) {
         static_assert((BLS_Z_ABS >> 63) == 1);
         auto accum = pt;

         for(size_t b = 63; b > 0; --b) {
            accum = accum.dbl();
            // The BLS parameter is a public constant so this branch leaks nothing
            if(((BLS_Z_ABS >> (b - 1)) & 1) == 1) {
               accum = accum.add(pt);
            }
         }

         return accum;
      }
};

}  // namespace Botan::BLS12_381

#endif
