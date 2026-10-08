/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pcurves_instance.h>

#include <botan/internal/pcurves_solinas.h>
#include <botan/internal/pcurves_wrap.h>

namespace Botan::PCurve {

namespace {

namespace sm2p256v1 {

template <typename Params>
class Sm2p256v1Rep final {
   public:
      static constexpr auto P = Params::P;
      static constexpr size_t N = Params::N;
      typedef typename Params::W W;

      constexpr static std::array<W, N> redc(const std::array<W, 2 * N>& z) {
         const int64_t X00 = get_uint32(z.data(), 0);
         const int64_t X01 = get_uint32(z.data(), 1);
         const int64_t X02 = get_uint32(z.data(), 2);
         const int64_t X03 = get_uint32(z.data(), 3);
         const int64_t X04 = get_uint32(z.data(), 4);
         const int64_t X05 = get_uint32(z.data(), 5);
         const int64_t X06 = get_uint32(z.data(), 6);
         const int64_t X07 = get_uint32(z.data(), 7);
         const int64_t X08 = get_uint32(z.data(), 8);
         const int64_t X09 = get_uint32(z.data(), 9);
         const int64_t X10 = get_uint32(z.data(), 10);
         const int64_t X11 = get_uint32(z.data(), 11);
         const int64_t X12 = get_uint32(z.data(), 12);
         const int64_t X13 = get_uint32(z.data(), 13);
         const int64_t X14 = get_uint32(z.data(), 14);
         const int64_t X15 = get_uint32(z.data(), 15);

         const int64_t S0 = X00 + X08 + X09 + X10 + X11 + X12 + 2 * (X13 + X14 + X15);
         const int64_t S1 = X01 + X09 + X10 + X11 + X12 + X13 + 2 * (X14 + X15);
         const int64_t S2 = X02 - (X08 + X09 + X13 + X14);
         const int64_t S3 = X03 + X08 + X11 + X12 + 2 * X13 + X14 + X15;
         const int64_t S4 = X04 + X09 + X12 + X13 + 2 * X14 + X15;
         const int64_t S5 = X05 + X10 + X13 + X14 + 2 * X15;
         const int64_t S6 = X06 + X11 + X14 + X15;
         const int64_t S7 = X07 + X08 + X09 + X10 + X11 + 2 * (X12 + X13 + X14 + X15) + X15;

         std::array<W, N> r = {};

         SolinasAccum sum(r);

         sum.accum(S0);
         sum.accum(S1);
         sum.accum(S2);
         sum.accum(S3);
         sum.accum(S4);
         sum.accum(S5);
         sum.accum(S6);
         sum.accum(S7);
         const auto S = sum.final_carry(0);

         solinas_correct_redc<N>(r, P, sm2_mul_mod_256(S));

         return r;
      }

      constexpr static std::array<W, N> one() { return std::array<W, N>{1}; }

      constexpr static std::array<W, N> to_rep(const std::array<W, N>& x) { return x; }

      constexpr static std::array<W, N> wide_to_rep(const std::array<W, 2 * N>& x) { return redc(x); }

      constexpr static std::array<W, N> from_rep(const std::array<W, N>& z) { return z; }

   private:
      // Return (i*P) % 2**256
      //
      // Assumes i is small
      constexpr static std::array<W, N> sm2_mul_mod_256(W i) {
         static_assert(WordInfo<W>::bits == 32 || WordInfo<W>::bits == 64);

         // For small i, multiples of P have a simple structure so it's faster to
         // compute the value directly vs a (constant time) table lookup

         auto r = P;
         if constexpr(WordInfo<W>::bits == 32) {
            r[7] -= i;
            r[3] -= i;
            r[2] += i;
            r[0] -= i;
         } else {
            const uint64_t i32 = static_cast<uint64_t>(i) << 32;
            r[3] -= i32;
            r[1] -= i32;
            r[1] += i;
            r[0] -= i;
         }
         return r;
      }
};

/*
* Montgomery arithmetic specialized for SM2
*
* Word-serial Montgomery reduction adds m*p to the accumulator in each step,
* with m chosen so that the low word becomes zero. For SM2, where
* p = 2^256 - 2^224 - 2^96 + 2^64 - 1, -p^-1 mod 2^64 is 1, so m is simply
* the low word itself.
*
* Writing m*p as m*(p+1) - m: the -m is what zeros the low word, which is
* never read again and so is not even written, while m*(p+1) is a multiple of
* 2^64. So what is actually added is m*(p+1)/2^64, one word up, which is
* m*(2^192 - 2^160 - 2^32 + 1) and is formed with shifts and subtractions
* rather than a multiplication.
*/
template <typename Params>
class Sm2p256v1MontgomeryRep final {
   public:
      static constexpr auto P = Params::P;
      static constexpr size_t N = Params::N;
      typedef typename Params::W W;

      static_assert(WordInfo<W>::bits == 64 && N == 4);

      static constexpr auto R1 = montygomery_r(P);
      static constexpr auto R2 = mul_mod(R1, R1, P);
      static constexpr auto R3 = mul_mod(R1, R2, P);

      constexpr static std::array<W, N> one() { return R1; }

      constexpr static BOTAN_FORCE_INLINE std::array<W, N> redc(const std::array<W, 2 * N>& z) {
         std::array<W, 2 * N> t = z;

         // The carry out at the end of the loop needs to end up in t[i + 5]
         // which is exactly q3 on the next iteration of the loop since we
         // shift the window 1 word at a time
         W pending = 0;

         for(size_t i = 0; i != N; ++i) {
            auto [q0, q1, q2, q3] = sm2_m_p1_64(t[i]);

            // q3 is at most 2^64 - 2^32 so no carry out is possible here
            q3 += pending;

            // Adding m*p would zero t[i], which is never read again, so only
            // the part above it is added
            W carry = 0;
            t[i + 1] = word_add(t[i + 1], q0, &carry);
            t[i + 2] = word_add(t[i + 2], q1, &carry);
            t[i + 3] = word_add(t[i + 3], q2, &carry);
            t[i + 4] = word_add(t[i + 4], q3, &carry);
            pending = carry;
         }

         return final_sub(pending, {t[4], t[5], t[6], t[7]});
      }

      constexpr static std::array<W, N> to_rep(const std::array<W, N>& x) {
         std::array<W, 2 * N> z;  // NOLINT(*-member-init)
         comba_mul<N>(z.data(), x.data(), R2.data());
         return redc(z);
      }

      constexpr static std::array<W, N> wide_to_rep(const std::array<W, 2 * N>& x) {
         auto redc_x = redc(x);
         std::array<W, 2 * N> z;  // NOLINT(*-member-init)
         comba_mul<N>(z.data(), redc_x.data(), R3.data());
         return redc(z);
      }

      constexpr static std::array<W, N> from_rep(const std::array<W, N>& z) {
         std::array<W, 2 * N> ze = {};
         copy_mem(std::span{ze}.template first<N>(), z);
         return redc(ze);
      }

   private:
      /**
      * Return the 4 words of m*(p+1)/2^64, which is what remains above the
      * low word after adding m*p to an accumulator whose low word is m
      */
      constexpr static BOTAN_FORCE_INLINE std::array<W, N> sm2_m_p1_64(W m) {
         const W m_lo = m << 32;
         const W m_hi = m >> 32;

         /*
         * m*(p+1)/2^64 = m + m*2^192 - m*2^32 - m*2^160, laid out as
         *
         *   m        -> word 0 gets m
         *   m*2^192  -> word 3 gets m
         *   -m*2^32  -> word 0 loses m << 32, word 1 loses m >> 32 plus the borrow
         *   -m*2^160 -> word 2 loses m << 32, word 3 loses m >> 32 plus the borrow
         *
         * The total is non-negative and below 2^256, so the final borrow is zero
         */
         W borrow = 0;
         const W q0 = word_sub(m, m_lo, &borrow);
         const W q1 = word_sub(static_cast<W>(0), m_hi, &borrow);
         const W q2 = word_sub(static_cast<W>(0), m_lo, &borrow);
         const W q3 = word_sub(m, m_hi, &borrow);

         return {q0, q1, q2, q3};
      }

      /**
      * Given (top || t) < 2*p return it reduced modulo p
      */
      constexpr static BOTAN_FORCE_INLINE std::array<W, N> final_sub(W top, const std::array<W, N>& t) {
         W borrow = 0;
         const W r0 = word_sub(t[0], P[0], &borrow);
         const W r1 = word_sub(t[1], P[1], &borrow);
         const W r2 = word_sub(t[2], P[2], &borrow);
         const W r3 = word_sub(t[3], P[3], &borrow);

         // t is only < p if the subtraction underflowed and top (the 257th bit) is zero
         const W t_lt_p = CT::value_barrier<W>(static_cast<W>(0) - (borrow & (top ^ 1)));

         return {
            Botan::choose(t_lt_p, t[0], r0),
            Botan::choose(t_lt_p, t[1], r1),
            Botan::choose(t_lt_p, t[2], r2),
            Botan::choose(t_lt_p, t[3], r3),
         };
      }
};

// clang-format off

class Params final : public EllipticCurveParameters<
  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
  "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
  "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
  "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"> {
};

// clang-format on

// With 32-bit words the Solinas reduction is faster than Montgomery
using Sm2p256v1Base = std::conditional_t<WordInfo<word>::bits == 64,
                                         EllipticCurve<Params, Sm2p256v1MontgomeryRep>,
                                         EllipticCurve<Params, Sm2p256v1Rep>>;

class Curve final : public Sm2p256v1Base {
   public:
      // Return the square of the inverse of x
      static constexpr FieldElement fe_invert2(const FieldElement& x) {
         // Generated by https://github.com/mmcloughlin/addchain
         auto z = x.square();
         auto t0 = x * z;
         z = t0.square();
         z *= x;
         auto t1 = z;
         t1.square_n(3);
         t1 *= z;
         auto t2 = t1.square();
         z = t2 * x;
         t2.square_n(5);
         t1 *= t2;
         t2 = t1;
         t2.square_n(12);
         t1 *= t2;
         t1.square_n(7);
         z *= t1;
         t2 = z;
         t2.square_n(2);
         t1 = t2;
         t1.square_n(29);
         z *= t1;
         t1.square_n(2);
         t2 *= t1;
         t0 *= t2;
         t1.square_n(32);
         t1 *= t0;
         t1.square_n(64);
         t0 *= t1;
         t0.square_n(94);
         z *= t0;
         z.square_n(2);
         return z;
      }

      static constexpr FieldElement fe_sqrt(const FieldElement& x) {
         auto z = x.square();
         z *= x;
         z = z.square();
         auto t0 = x * z;
         z = t0.square();
         z *= x;
         auto t2 = z.square();
         auto t3 = t2.square();
         auto t1 = t3.square();
         auto t4 = t1;
         t4.square_n(3);
         t3 *= t4;
         t3.square_n(5);
         t1 *= t3;
         t3 = t1;
         t3.square_n(2);
         t2 *= t3;
         t2.square_n(14);
         t1 *= t2;
         t0 *= t1;
         t0.square_n(4);
         t1 = t0;
         t1.square_n(31);
         t0 *= t1;
         t1.square_n(32);
         t1 *= t0;
         t1.square_n(62);
         t0 *= t1;
         z *= t0;
         z.square_n(32);
         z *= x;
         z.square_n(62);
         return z;
      }
};

}  // namespace sm2p256v1

}  // namespace

std::shared_ptr<const PrimeOrderCurve> PCurveInstance::sm2p256v1() {
   return PrimeOrderCurveImpl<sm2p256v1::Curve>::instance();
}

}  // namespace Botan::PCurve
