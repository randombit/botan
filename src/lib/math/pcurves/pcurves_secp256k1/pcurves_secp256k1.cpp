/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pcurves_instance.h>

#include <botan/internal/pcurves_wrap.h>

namespace Botan::PCurve {

namespace {

namespace secp256k1 {

template <typename Params>
class Secp256k1Rep final {
   public:
      static constexpr auto P = Params::P;
      static constexpr size_t N = Params::N;
      typedef typename Params::W W;

      static_assert(WordInfo<W>::bits >= 33);

      static constexpr W C = 0x1000003d1;

      constexpr static std::array<W, N> one() { return std::array<W, N>{1}; }

      constexpr static std::array<W, N> redc(const std::array<W, 2 * N>& z) {
         return redc_crandall<W, N, C>(std::span{z});
      }

      constexpr static std::array<W, N> to_rep(const std::array<W, N>& x) { return x; }

      constexpr static std::array<W, N> wide_to_rep(const std::array<W, 2 * N>& x) { return redc(x); }

      constexpr static std::array<W, N> from_rep(const std::array<W, N>& z) { return z; }
};

// clang-format off
class Params final : public EllipticCurveParameters<
   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
   "0",
   "7",
   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
   "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
   "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"> {
};

// clang-format on
#if BOTAN_MP_WORD_BITS == 64
typedef EllipticCurve<Params, Secp256k1Rep> Secp256k1Base;
#else
typedef EllipticCurve<Params> Secp256k1Base;
#endif

class Curve final : public Secp256k1Base {
   public:
      // Return the square of the inverse of x
      static constexpr FieldElement fe_invert2(const FieldElement& x) {
         auto z = x.square();
         z *= x;
         auto t0 = z;
         t0.square_n(2);
         t0 *= z;
         auto t1 = t0.square();
         auto t2 = t1 * x;
         t1 = t2;
         t1.square_n(2);
         t1 *= z;
         auto t3 = t1;
         t3.square_n(4);
         t0 *= t3;
         t3 = t0;
         t3.square_n(11);
         t0 *= t3;
         t3 = t0;
         t3.square_n(5);
         t2 *= t3;
         t3 = t2;
         t3.square_n(27);
         t2 *= t3;
         t3 = t2;
         t3.square_n(54);
         t2 *= t3;
         t3 = t2;
         t3.square_n(108);
         t2 *= t3;
         t2.square_n(7);
         t1 *= t2;
         t1.square_n(23);
         t0 *= t1;
         t0.square_n(5);
         t0 *= x;
         t0.square_n(3);
         z *= t0;
         z.square_n(2);
         return z;
      }

      static constexpr Scalar scalar_invert(const Scalar& x) {
         auto z = x.square();
         auto t2 = x * z;
         auto t6 = t2 * z;
         auto t5 = t6 * z;
         auto t0 = t5 * z;
         auto t3 = t0 * z;
         auto t1 = t3 * z;
         z = t1;
         z.square_n(2);
         z *= t3;
         auto t4 = z.square();
         auto t7 = t4 * x;
         t4 = t7.square();
         t4 *= x;
         auto t9 = t4;
         t9.square_n(3);
         auto t10 = t9;
         t10.square_n(2);
         auto t11 = t10.square();
         auto t8 = t11.square();
         auto t12 = t8;
         t12.square_n(7);
         t11 *= t12;
         t11.square_n(9);
         t8 *= t11;
         t11 = t8;
         t11.square_n(6);
         t10 *= t11;
         t10.square_n(26);
         t8 *= t10;
         t10 = t8;
         t10.square_n(4);
         t9 *= t10;
         t9.square_n(60);
         t8 *= t9;
         t7 *= t8;
         t7.square_n(5);
         t7 *= t3;
         t7.square_n(3);
         t7 *= t6;
         t7.square_n(4);
         t7 *= t6;
         t7.square_n(4);
         t7 *= t5;
         t7.square_n(5);
         t7 *= t1;
         t7.square_n(2);
         t7 *= t2;
         t7.square_n(5);
         t7 *= t5;
         t7.square_n(6);
         t7 *= t1;
         t7.square_n(5);
         t7 *= t3;
         t7.square_n(4);
         t7 *= t1;
         t7.square_n(3);
         t7 *= x;
         t7.square_n(6);
         t6 *= t7;
         t6.square_n(10);
         t6 *= t5;
         t6.square_n(4);
         t5 *= t6;
         t5.square_n(9);
         t4 *= t5;
         t4.square_n(5);
         t4 *= t0;
         t4.square_n(6);
         t3 *= t4;
         t3.square_n(4);
         t3 *= t1;
         t3.square_n(5);
         t2 *= t3;
         t2.square_n(6);
         t2 *= t1;
         t2.square_n(10);
         t1 *= t2;
         t1.square_n(4);
         t0 *= t1;
         t0.square_n(6);
         t0 *= x;
         t0.square_n(8);
         z *= t0;
         return z;
      }
};

}  // namespace secp256k1

}  // namespace

std::shared_ptr<const PrimeOrderCurve> PCurveInstance::secp256k1() {
   return PrimeOrderCurveImpl<secp256k1::Curve>::instance();
}

}  // namespace Botan::PCurve
