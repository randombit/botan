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

namespace secp192r1 {

template <typename Params>
class Secp192r1Rep final {
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

         const int64_t S0 = X00 + X06 + X10;
         const int64_t S1 = X01 + X07 + X11;
         const int64_t S2 = X02 + X06 + X08 + X10;
         const int64_t S3 = X03 + X07 + X09 + X11;
         const int64_t S4 = X04 + X08 + X10;
         const int64_t S5 = X05 + X09 + X11;

         std::array<W, N> r = {};

         SolinasAccum sum(r);

         sum.accum(S0);
         sum.accum(S1);
         sum.accum(S2);
         sum.accum(S3);
         sum.accum(S4);
         sum.accum(S5);
         const auto S = sum.final_carry(0);

         BOTAN_DEBUG_ASSERT(S <= 3);

         bigint_correct_redc<N>(r, P, p192_mul_mod_192(S));

         return r;
      }

      constexpr static std::array<W, N> one() { return std::array<W, N>{1}; }

      constexpr static std::array<W, N> to_rep(const std::array<W, N>& x) { return x; }

      constexpr static std::array<W, N> wide_to_rep(const std::array<W, 2 * N>& x) { return redc(x); }

      constexpr static std::array<W, N> from_rep(const std::array<W, N>& z) { return z; }

   private:
      // Return (i*P-192) % 2**192
      //
      // Assumes i is small
      constexpr static std::array<W, N> p192_mul_mod_192(W i) {
         static_assert(WordInfo<W>::bits == 32 || WordInfo<W>::bits == 64);

         // For small i, multiples of P-192 have a simple structure so it's faster to
         // compute the value directly vs a (constant time) table lookup

         auto r = P;

         if constexpr(WordInfo<W>::bits == 32) {
            r[2] -= i;
            r[0] -= i;
         } else {
            r[1] -= i;
            r[0] -= i;
         }
         return r;
      }
};

// clang-format off
class Params final : public EllipticCurveParameters<
   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
   "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
   "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
   "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
   "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811"> {
};

// clang-format on

class Curve final : public EllipticCurve<Params, Secp192r1Rep> {};

}  // namespace secp192r1

}  // namespace

std::shared_ptr<const PrimeOrderCurve> PCurveInstance::secp192r1() {
   return PrimeOrderCurveImpl<secp192r1::Curve>::instance();
}

}  // namespace Botan::PCurve
