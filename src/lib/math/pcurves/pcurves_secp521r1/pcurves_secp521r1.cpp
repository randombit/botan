/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pcurves_instance.h>

#include <botan/internal/pcurves_wrap.h>

namespace Botan::PCurve {

namespace {

// clang-format off
namespace secp521r1 {

template <typename Params>
class P521Rep final {
   public:
      static constexpr auto P = Params::P;
      static constexpr size_t N = Params::N;
      typedef typename Params::W W;

      constexpr static std::array<W, N> one() {
         std::array<W, N> one = {};
         one[0] = 1;
         return one;
      }

      constexpr static std::array<W, N> redc(const std::array<W, 2 * N>& z) {
         constexpr W TOP_MASK = static_cast<W>(0x1FF);

         std::array<W, N> hi = {};
         copy_mem(hi, std::span{z}.template subspan<N - 1, N>());
         shift_right<9>(hi);

         std::array<W, N> lo = {};
         copy_mem(lo, std::span{z}.template first<N>());
         lo[N - 1] &= TOP_MASK;

         // s = hi + lo
         std::array<W, N> s = {};
         // Will never carry out
         W carry = bigint_add<W, N>(s, lo, hi);

         // But might be greater than modulus:
         std::array<W, N> r = {};
         bigint_monty_maybe_sub<N>(r.data(), carry, s.data(), P.data());

         return r;
      }

      constexpr static std::array<W, N> to_rep(const std::array<W, N>& x) { return x; }

      constexpr static std::array<W, N> wide_to_rep(const std::array<W, 2 * N>& x) { return redc(x); }

      constexpr static std::array<W, N> from_rep(const std::array<W, N>& z) { return z; }
};

class Params final : public EllipticCurveParameters<
   "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
   "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
   "51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
   "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
   "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
   "11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
   -4> {
};

class Curve final : public EllipticCurve<Params, P521Rep> {};

}

// clang-format on

}  // namespace

std::shared_ptr<const PrimeOrderCurve> PCurveInstance::secp521r1() {
   return PrimeOrderCurveImpl<secp521r1::Curve>::instance();
}

}  // namespace Botan::PCurve
