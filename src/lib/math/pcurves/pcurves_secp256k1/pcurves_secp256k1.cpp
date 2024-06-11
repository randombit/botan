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
class Curve final : public EllipticCurve<Params, Secp256k1Rep> {};
#else
class Curve final : public EllipticCurve<Params> {};
#endif

}  // namespace secp256k1

}  // namespace

std::shared_ptr<const PrimeOrderCurve> PCurveInstance::secp256k1() {
   return PrimeOrderCurveImpl<secp256k1::Curve>::instance();
}

}  // namespace Botan::PCurve
