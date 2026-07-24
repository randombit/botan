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
#include <algorithm>
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
* Return the i'th 4-bit window of a big-endian encoded scalar, counting
* from the most significant
*/
inline uint8_t scalar_nibble(std::span<const uint8_t, Scalar::BYTES> bytes, size_t i) {
   return (i % 2 == 0) ? (bytes[i / 2] >> 4) : (bytes[i / 2] & 0x0F);
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

      /**
      * Constant time fixed window multiplication
      */
      static Pt mul(const Pt& pt, const Scalar& scalar) {
         constexpr size_t WINDOW_BITS = 4;
         constexpr size_t TABLE_SIZE = 1 << WINDOW_BITS;

         std::array<Pt, TABLE_SIZE> tbl;
         for(size_t i = 1; i != TABLE_SIZE; ++i) {
            tbl[i] = tbl[i - 1].add(pt);
         }

         auto sbytes = scalar.serialize();

         auto accum = Pt::identity();

         for(size_t i = 0; i != 2 * sbytes.size(); ++i) {
            if(i > 0) {
               for(size_t j = 0; j != WINDOW_BITS; ++j) {
                  accum = accum.dbl();
               }
            }
            accum = accum.add(ct_select(tbl, scalar_nibble(sbytes, i)));
         }

         secure_scrub_memory(sbytes);

         return accum;
      }

      /**
      * Constant time a*p + b*q
      */
      static Pt mul2(const Pt& p, const Scalar& a, const Pt& q, const Scalar& b) {
         constexpr size_t WINDOW_BITS = 4;
         constexpr size_t TABLE_SIZE = 1 << WINDOW_BITS;

         // Interleaved Strauss-Shamir; both scalars share one doubling chain
         std::array<Pt, TABLE_SIZE> ptbl;
         std::array<Pt, TABLE_SIZE> qtbl;
         for(size_t i = 1; i != TABLE_SIZE; ++i) {
            ptbl[i] = ptbl[i - 1].add(p);
            qtbl[i] = qtbl[i - 1].add(q);
         }

         auto abytes = a.serialize();
         auto bbytes = b.serialize();

         auto accum = Pt::identity();

         for(size_t i = 0; i != 2 * abytes.size(); ++i) {
            if(i > 0) {
               for(size_t j = 0; j != WINDOW_BITS; ++j) {
                  accum = accum.dbl();
               }
            }
            accum = accum.add(ct_select(ptbl, scalar_nibble(abytes, i)));
            accum = accum.add(ct_select(qtbl, scalar_nibble(bbytes, i)));
         }

         secure_scrub_memory(abytes);
         secure_scrub_memory(bbytes);

         return accum;
      }

      /**
      * Variable time a*p + b*q
      */
      static Pt mul2_vartime(const Pt& p, const Scalar& a, const Pt& q, const Scalar& b) {
         constexpr size_t WINDOW_BITS = 4;
         constexpr size_t TABLE_SIZE = 1 << WINDOW_BITS;

         std::array<Pt, TABLE_SIZE> ptbl;
         std::array<Pt, TABLE_SIZE> qtbl;
         for(size_t i = 1; i != TABLE_SIZE; ++i) {
            ptbl[i] = ptbl[i - 1].add(p);
            qtbl[i] = qtbl[i - 1].add(q);
         }

         auto abytes = a.serialize();
         auto bbytes = b.serialize();

         auto accum = Pt::identity();

         for(size_t i = 0; i != 2 * abytes.size(); ++i) {
            if(i > 0) {
               for(size_t j = 0; j != WINDOW_BITS; ++j) {
                  accum = accum.dbl();
               }
            }
            const uint8_t wa = scalar_nibble(abytes, i);
            const uint8_t wb = scalar_nibble(bbytes, i);
            if(wa > 0) {
               accum = accum.add(ptbl[wa]);
            }
            if(wb > 0) {
               accum = accum.add(qtbl[wb]);
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
               accum = accum.add(mul(Pt::from_affine(points[i]), scalars[i]));
            }
            return accum;
         }

         // The Pippenger bucket method; process the scalars in c-bit windows
         // from the most significant down, adding each point into the bucket
         // its window digit selects, then form the window sum with a running
         // sum over the buckets.
         const size_t c = pippenger_window_bits(points.size());
         const size_t windows = (8 * Scalar::BYTES + c - 1) / c;

         std::vector<std::array<uint8_t, Scalar::BYTES>> sbytes;
         sbytes.reserve(scalars.size());
         for(const auto& scalar : scalars) {
            sbytes.push_back(scalar.serialize());
         }

         std::vector<Pt> buckets((static_cast<size_t>(1) << c) - 1);

         auto accum = Pt::identity();

         for(size_t w = 0; w != windows; ++w) {
            if(w > 0) {
               for(size_t j = 0; j != c; ++j) {
                  accum = accum.dbl();
               }
            }

            std::ranges::fill(buckets, Pt::identity());

            const size_t bit = (windows - 1 - w) * c;
            for(size_t i = 0; i != points.size(); ++i) {
               const size_t digit = scalar_window_at(sbytes[i], bit, c);
               if(digit > 0) {
                  buckets[digit - 1] = buckets[digit - 1].add_mixed(points[i]);
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
         auto accum = Pt::identity();

         for(size_t b = 64; b > 0; --b) {
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
