/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pcurves_instance.h>

#include <botan/internal/pcurves_wrap.h>

namespace Botan::PCurve {

namespace {

namespace secp521r1 {

template <typename Params>
class P521Rep final {
   public:
      static constexpr auto P = Params::P;
      static constexpr size_t N = Params::N;
      typedef typename Params::W W;

      constexpr static std::array<W, N> one() { return std::array<W, N>{1}; }

      constexpr static std::array<W, N> redc(const std::array<W, 2 * N>& z) {
         constexpr W TOP_MASK = static_cast<W>(0x1FF);

         /*
         * Extract the high part of z (z >> 521)
         */
         std::array<W, N> t;

         for(size_t i = 0; i != N; ++i) {
            t[i] = z[(N - 1) + i] >> 9;
         }

         for(size_t i = 0; i != N - 1; ++i) {
            t[i] |= z[(N - 1) + i + 1] << (WordInfo<W>::bits - 9);
         }

         // Now t += z & (2**521-1)
         W carry = word8_add2(t.data(), z.data(), static_cast<W>(0));

         if constexpr(WordInfo<W>::bits == 32) {
            constexpr size_t HN = N / 2;
            carry = word8_add2(t.data() + HN, z.data() + HN, carry);
         }

         // Now add the (partial) top words; this can't carry out
         // since both inputs are at most 2**9-1
         t[N - 1] += (z[N - 1] & TOP_MASK) + carry;

         // But might be greater than modulus:
         std::array<W, N> r;
         bigint_monty_maybe_sub<N>(r.data(), static_cast<W>(0), t.data(), P.data());

         return r;
      }

      constexpr static std::array<W, N> to_rep(const std::array<W, N>& x) { return x; }

      constexpr static std::array<W, N> wide_to_rep(const std::array<W, 2 * N>& x) { return redc(x); }

      constexpr static std::array<W, N> from_rep(const std::array<W, N>& z) { return z; }
};

// clang-format off
class Params final : public EllipticCurveParameters<
   "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
   "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
   "51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
   "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
   "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
   "11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
   -4> {
};

// clang-format on

class Curve final : public EllipticCurve<Params, P521Rep> {
   public:
      // Return the square of the inverse of x
      static constexpr FieldElement fe_invert2(const FieldElement& x) {
         // Addition chain from https://eprint.iacr.org/2014/852.pdf page 6

         FieldElement r = x.square();
         r *= x;
         r = r.square();
         r *= x;
         FieldElement rl = r;
         r.square_n(3);
         r *= rl;
         r.square_n(1);
         r *= x;
         const auto a7 = r;
         r.square_n(1);
         r *= x;
         rl = r;
         r.square_n(8);
         r *= rl;
         rl = r;
         r.square_n(16);
         r *= rl;
         rl = r;
         r.square_n(32);
         r *= rl;
         rl = r;
         r.square_n(64);
         r *= rl;
         rl = r;
         r.square_n(128);
         r *= rl;
         rl = r;
         r.square_n(256);
         r *= rl;
         r.square_n(7);
         r *= a7;
         r.square_n(2);

         return r;
      }

      static constexpr Scalar scalar_invert(const Scalar& x) {
         // Generated using https://github.com/mmcloughlin/addchain

         auto t2 = x.square();
         auto t13 = t2 * x;
         auto t4 = t13 * x;
         auto z = t13 * t4;
         auto t5 = x * z;
         auto t16 = t13 * t5;
         auto t10 = t16 * t2;
         auto t18 = t10 * t2;
         auto t1 = t18 * t2;
         auto t12 = t1 * t2;
         auto t15 = t12 * t4;
         auto t0 = t15 * t2;
         auto t3 = t0 * t2;
         auto t6 = t2 * t3;
         auto t11 = t5 * t6;
         auto t14 = t11 * t4;
         auto t9 = t14 * t4;
         auto t17 = t2 * t9;
         auto t7 = t17 * t4;
         t4 *= t7;
         auto t8 = t2 * t4;
         t5 = t2 * t8;
         t2 *= t5;
         auto t19 = t2;
         t19.square_n(3);
         t15 *= t19;
         t19 = t15.square();
         auto t20 = t19;
         t20.square_n(8);
         t20 *= t15;
         t20.square_n(10);
         t19 *= t20;
         t20 = t19;
         t20.square_n(8);
         t20 *= t15;
         t20.square_n(28);
         t19 *= t20;
         t20 = t19;
         t20.square_n(63);
         t19 *= t20;
         t20 = t19;
         t20.square_n(8);
         t20 *= t15;
         t20.square_n(127);
         t19 *= t20;
         t19 *= x;
         t19.square_n(7);
         t19 *= t11;
         t19.square_n(5);
         t19 *= t13;
         t19.square_n(8);
         t19 *= t10;
         t19.square_n(8);
         t19 *= t18;
         t19.square_n(11);
         t19 *= t5;
         t19.square_n(4);
         t18 *= t19;
         t18.square_n(8);
         t17 *= t18;
         t17.square_n(6);
         t17 *= t11;
         t17.square_n(5);
         t17 *= t12;
         t17.square_n(5);
         t16 *= t17;
         t16.square_n(10);
         t15 *= t16;
         t15.square_n(4);
         t15 *= t13;
         t15.square_n(15);
         t14 *= t15;
         t14.square_n(9);
         t14 *= t2;
         t14.square_n(2);
         t13 *= t14;
         t13.square_n(9);
         t12 *= t13;
         t12.square_n(7);
         t11 *= t12;
         t11.square_n(4);
         t10 *= t11;
         t10.square_n(12);
         t10 *= t5;
         t10.square_n(6);
         t9 *= t10;
         t9.square_n(7);
         t8 *= t9;
         t8.square_n(8);
         t8 *= t4;
         t8.square_n(8);
         t8 *= t1;
         t8.square_n(8);
         t7 *= t8;
         t7.square_n(5);
         t7 *= t1;
         t7.square_n(9);
         t7 *= t2;
         t7.square_n(6);
         t6 *= t7;
         t6.square_n(7);
         t5 *= t6;
         t5.square_n(7);
         t4 *= t5;
         t4.square_n(5);
         t3 *= t4;
         t3.square_n(4);
         t3 *= z;
         t3.square_n(9);
         t2 *= t3;
         t2.square_n(7);
         t1 *= t2;
         t1.square_n(5);
         t1 *= z;
         t1.square_n(9);
         t0 *= t1;
         t0.square_n(10);
         z *= t0;

         return z;
      }
};

}  // namespace secp521r1

}  // namespace

std::shared_ptr<const PrimeOrderCurve> PCurveInstance::secp521r1() {
   return PrimeOrderCurveImpl<secp521r1::Curve>::instance();
}

}  // namespace Botan::PCurve
