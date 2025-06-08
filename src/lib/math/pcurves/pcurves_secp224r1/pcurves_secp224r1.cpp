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

namespace secp224r1 {

template <typename Params>
class Secp224r1Rep final {
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

         const int64_t S0 = 0x00000001 + X00 - X07 - X11;
         const int64_t S1 = 0x00000000 + X01 - X08 - X12;
         const int64_t S2 = 0x00000000 + X02 - X09 - X13;
         const int64_t S3 = 0xFFFFFFFF + X03 + X07 + X11 - X10;
         const int64_t S4 = 0xFFFFFFFF + X04 + X08 + X12 - X11;
         const int64_t S5 = 0xFFFFFFFF + X05 + X09 + X13 - X12;
         const int64_t S6 = 0xFFFFFFFF + X06 + X10 - X13;

         std::array<W, N> r = {};

         SolinasAccum sum(r);

         sum.accum(S0);
         sum.accum(S1);
         sum.accum(S2);
         sum.accum(S3);
         sum.accum(S4);
         sum.accum(S5);
         sum.accum(S6);
         const auto S = sum.final_carry(0);

         BOTAN_DEBUG_ASSERT(S <= 2);

         bigint_correct_redc<N>(r, P, p224_mul_mod_224(S));

         return r;
      }

      constexpr static std::array<W, N> one() { return std::array<W, N>{1}; }

      constexpr static std::array<W, N> to_rep(const std::array<W, N>& x) { return x; }

      constexpr static std::array<W, N> wide_to_rep(const std::array<W, 2 * N>& x) { return redc(x); }

      constexpr static std::array<W, N> from_rep(const std::array<W, N>& z) { return z; }

   private:
      // Return (i*P-224) % 2**224
      //
      // Assumes i is small
      constexpr static std::array<W, N> p224_mul_mod_224(W i) {
         static_assert(WordInfo<W>::bits == 32 || WordInfo<W>::bits == 64);

         // For small i, multiples of P-224 have a simple structure so it's faster to
         // compute the value directly vs a (constant time) table lookup

         auto r = P;

         if constexpr(WordInfo<W>::bits == 32) {
            r[3] -= i;
            r[0] += i;
         } else {
            const W i32 = i << 32;
            r[1] -= i32;
            r[0] += i;
         }
         return r;
      }
};

// clang-format off
class Params final : public EllipticCurveParameters<
   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
   "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
   "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
   "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
   "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34"> {
};

// clang-format on

class Curve final : public EllipticCurve<Params, Secp224r1Rep> {
   public:
      // Return the square of the inverse of x
      static constexpr FieldElement fe_invert2(const FieldElement& x) {
         auto z = x.square();
         z *= x;
         z = z.square();
         z *= x;
         auto t0 = z;
         t0.square_n(3);
         t0 *= z;
         auto t1 = t0;
         t1.square_n(6);
         t0 *= t1;
         t0.square_n(3);
         z *= t0;
         t0 = z.square();
         t0 *= x;
         t1 = t0;
         t1.square_n(16);
         t0 *= t1;
         t1 = t0;
         t1.square_n(15);
         z *= t1;
         t1 = z;
         t1.square_n(47);
         z *= t1;
         z = z.square();
         z *= x;
         t1 = z;
         t1.square_n(32);
         t0 *= t1;
         t0.square_n(96);
         z *= t0;
         return z.square();
      }

      static constexpr Scalar scalar_invert(const Scalar& x) {
         // Generated using https://github.com/mmcloughlin/addchain
         auto t6 = x.square();
         auto z = t6.square();
         auto t3 = x * z;
         auto t2 = t3 * t6;
         auto t8 = t2 * z;
         auto t7 = t8 * z;
         auto t5 = t7 * z;
         auto t0 = t5 * t6;
         auto t1 = t0 * t6;
         auto t4 = t1 * z;
         z = t4 * t6;
         t6 *= z;
         auto t10 = t6.square();
         auto t9 = t10 * x;
         t10.square_n(5);
         t9 *= t10;
         t10.square_n(5);
         t9 *= t10;
         t10 = t9;
         t10.square_n(16);
         t10 *= t9;
         auto t11 = t10;
         t11.square_n(32);
         t11 *= t10;
         t11.square_n(32);
         t10 *= t11;
         t10.square_n(16);
         t9 *= t10;
         t9.square_n(7);
         t8 *= t9;
         t8.square_n(4);
         t8 *= t3;
         t8.square_n(8);
         t8 *= t1;
         t8.square_n(10);
         t8 *= t1;
         t8.square_n(7);
         t7 *= t8;
         t7.square_n(11);
         t6 *= t7;
         t6.square_n(9);
         t5 *= t6;
         t5.square_n(5);
         t4 *= t5;
         t4.square_n(3);
         t4 *= t3;
         t4.square_n(5);
         t4 *= t3;
         t4.square_n(5);
         t3 *= t4;
         t3.square_n(8);
         t3 *= t0;
         t3.square_n(4);
         t2 *= t3;
         t2.square_n(8);
         t1 *= t2;
         t1.square_n(9);
         t0 *= t1;
         t0.square_n(8);
         z *= t0;
         z = z.square();
         z *= x;
         return z;
      }
};

}  // namespace secp224r1

}  // namespace

std::shared_ptr<const PrimeOrderCurve> PCurveInstance::secp224r1() {
   return PrimeOrderCurveImpl<secp224r1::Curve>::instance();
}

}  // namespace Botan::PCurve
