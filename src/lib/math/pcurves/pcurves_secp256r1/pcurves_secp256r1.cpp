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

template <typename Params>
class Secp256r1Rep final {
   public:
      static constexpr auto P = Params::P;
      static constexpr size_t N = Params::N;
      typedef typename Params::W W;

      // Adds 4 * P-256 to prevent underflow
      static constexpr auto P256_4 =
         hex_to_words<uint32_t>("0x3fffffffc00000004000000000000000000000003fffffffffffffffffffffffc");

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

         // See SP 800-186 section G.1.2
         const int64_t S0 = P256_4[0] + X00 + X08 + X09 - (X11 + X12 + X13 + X14);
         const int64_t S1 = P256_4[1] + X01 + X09 + X10 - (X12 + X13 + X14 + X15);
         const int64_t S2 = P256_4[2] + X02 + X10 + X11 - (X13 + X14 + X15);
         const int64_t S3 = P256_4[3] + X03 + 2 * (X11 + X12) + X13 - (X15 + X08 + X09);
         const int64_t S4 = P256_4[4] + X04 + 2 * (X12 + X13) + X14 - (X09 + X10);
         const int64_t S5 = P256_4[5] + X05 + 2 * (X13 + X14) + X15 - (X10 + X11);
         const int64_t S6 = P256_4[6] + X06 + X13 + X14 * 3 + X15 * 2 - (X08 + X09);
         const int64_t S7 = P256_4[7] + X07 + X15 * 3 + X08 - (X10 + X11 + X12 + X13);
         const int64_t S8 = P256_4[8];

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
         const auto S = sum.final_carry(S8);

         BOTAN_DEBUG_ASSERT(S <= 8);

         const auto correction = p256_mul_mod_256(S);
         W borrow = bigint_sub2(r.data(), N, correction.data(), N);

         bigint_cnd_add(borrow, r.data(), N, P.data(), N);

         return r;
      }

      constexpr static std::array<W, N> one() { return std::array<W, N>{1}; }

      constexpr static std::array<W, N> to_rep(const std::array<W, N>& x) { return x; }

      constexpr static std::array<W, N> wide_to_rep(const std::array<W, 2 * N>& x) { return redc(x); }

      constexpr static std::array<W, N> from_rep(const std::array<W, N>& z) { return z; }

   private:
      // Return (i*P-256) % 2**256
      //
      // Assumes i is small
      constexpr static std::array<W, N> p256_mul_mod_256(W i) {
         static_assert(WordInfo<W>::bits == 32 || WordInfo<W>::bits == 64);

         // For small i, multiples of P-256 have a simple structure so it's faster to
         // compute the value directly vs a (constant time) table lookup

         auto r = P;
         if constexpr(WordInfo<W>::bits == 32) {
            r[7] -= i;
            r[6] += i;
            r[3] += i;
            r[0] -= i;
         } else {
            const uint64_t i32 = static_cast<uint64_t>(i) << 32;
            r[3] -= i32;
            r[3] += i;
            r[1] += i32;
            r[0] -= i;
         }
         return r;
      }
};

namespace secp256r1 {

// clang-format off
class Params final : public EllipticCurveParameters<
   "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
   "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
   "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
   "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
   "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
   "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
   -10> {
};

// clang-format on

#if BOTAN_MP_WORD_BITS == 32
// Secp256r1Rep works for 64 bit also, but is at best marginally faster at least
// on compilers/CPUs tested so far
typedef EllipticCurve<Params, Secp256r1Rep> Secp256r1Base;
#else
typedef EllipticCurve<Params> Secp256r1Base;
#endif

class Curve final : public Secp256r1Base {
   public:
      // Return the square of the inverse of x
      static FieldElement fe_invert2(const FieldElement& x) {
         FieldElement r = x.square();
         r *= x;

         const auto p2 = r;
         r.square_n(2);
         r *= p2;
         const auto p4 = r;
         r.square_n(4);
         r *= p4;
         const auto p8 = r;
         r.square_n(8);
         r *= p8;
         const auto p16 = r;
         r.square_n(16);
         r *= p16;
         const auto p32 = r;
         r.square_n(32);
         r *= x;
         r.square_n(128);
         r *= p32;
         r.square_n(32);
         r *= p32;
         r.square_n(16);
         r *= p16;
         r.square_n(8);
         r *= p8;
         r.square_n(4);
         r *= p4;
         r.square_n(2);
         r *= p2;
         r.square_n(2);

         return r;
      }
};

}  // namespace secp256r1

}  // namespace

std::shared_ptr<const PrimeOrderCurve> PCurveInstance::secp256r1() {
   return PrimeOrderCurveImpl<secp256r1::Curve>::instance();
}

}  // namespace Botan::PCurve
