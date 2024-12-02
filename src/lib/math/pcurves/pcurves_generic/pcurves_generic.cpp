/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pcurves_generic.h>

#include <botan/bigint.h>
#include <botan/exceptn.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/pcurves_instance.h>
#include <botan/internal/primality.h>

namespace Botan::PCurve {

namespace {

template <size_t N>
class FLInt final {
   private:
      static constexpr auto P = Rep::P;
      typedef word W;

      static constexpr auto P_MINUS_2 = p_minus<2>(P);

   public:
      static constexpr size_t BITS = count_bits(P);
      static constexpr size_t BYTES = (BITS + 7) / 8;

      static constexpr auto P_MOD_4 = P[0] % 4;

      using Self = FLInt<N>;

      // Default value is zero
      constexpr FLInt() : m_val({}) {}

      FLInt(const Self& other) = default;
      FLInt(Self&& other) = default;
      FLInt& operator=(const Self& other) = default;
      FLInt& operator=(Self&& other) = default;

      static constexpr Self zero() { return Self(std::array<W, N>{0}); }

      static constexpr Self one() { return Self(Rep::one()); }

      static constexpr Self from_word(W x) {
         std::array<W, 1> v{x};
         return Self::from_words(v);
      }

      template <size_t L>
      static constexpr Self from_words(std::array<W, L> w) {
         if constexpr(L == N) {
            return Self(Rep::to_rep(w));
         } else {
            static_assert(L < N);
            std::array<W, N> ew = {};
            copy_mem(std::span{ew}.template first<L>(), w);
            return Self(Rep::to_rep(ew));
         }
      }

      constexpr CT::Choice is_zero() const { return CT::all_zeros(m_val.data(), m_val.size()).as_choice(); }

      constexpr CT::Choice is_nonzero() const { return !is_zero(); }

      constexpr CT::Choice is_one() const { return (*this == Self::one()); }

      constexpr CT::Choice is_even() const {
         auto v = Rep::from_rep(m_val);
         return !CT::Choice::from_int(v[0] & 0x01);
      }

      friend constexpr Self operator+(const Self& a, const Self& b) {
         std::array<W, N> t;
         W carry = bigint_add<W, N>(t, a.value(), b.value());

         std::array<W, N> r;
         bigint_monty_maybe_sub<N>(r.data(), carry, t.data(), P.data());
         return Self(r);
      }

      friend constexpr Self operator-(const Self& a, const Self& b) { return a + b.negate(); }

      /// Return (*this) divided by 2
      Self div2() const {
         // The inverse of 2 modulo P is (P/2)+1; this avoids a constexpr time
         // general inversion, which some compilers can't handle
         constexpr auto INV_2 = p_div_2_plus_1(Rep::P);

         // We could multiply by INV_2 but there is a better way ...

         std::array<W, N> t = value();
         W borrow = shift_right<1>(t);

         // If value was odd, add (P/2)+1
         bigint_cnd_add(borrow, t.data(), N, INV_2.data(), N);

         return Self(t);
      }

      /// Return (*this) multiplied by 2
      Self mul2() const {
         std::array<W, N> t = value();
         W carry = shift_left<1>(t);

         std::array<W, N> r;
         bigint_monty_maybe_sub<N>(r.data(), carry, t.data(), P.data());
         return Self(r);
      }

      /// Return (*this) multiplied by 3
      constexpr Self mul3() const { return mul2() + (*this); }

      /// Return (*this) multiplied by 4
      constexpr Self mul4() const { return mul2().mul2(); }

      /// Return (*this) multiplied by 8
      constexpr Self mul8() const { return mul2().mul2().mul2(); }

      friend constexpr Self operator*(const Self& a, const Self& b) {
         std::array<W, 2 * N> z;
         comba_mul<N>(z.data(), a.data(), b.data());
         return Self(Rep::redc(z));
      }

      constexpr Self& operator*=(const Self& other) {
         std::array<W, 2 * N> z;
         comba_mul<N>(z.data(), data(), other.data());
         m_val = Rep::redc(z);
         return (*this);
      }

      // if cond is true, sets x to nx
      static constexpr void conditional_assign(Self& x, CT::Choice cond, const Self& nx) {
         const W mask = CT::Mask<W>::from_choice(cond).value();

         for(size_t i = 0; i != N; ++i) {
            x.m_val[i] = choose(mask, nx.m_val[i], x.m_val[i]);
         }
      }

      // if cond is true, sets x to nx, y to ny
      static constexpr void conditional_assign(Self& x, Self& y, CT::Choice cond, const Self& nx, const Self& ny) {
         const W mask = CT::Mask<W>::from_choice(cond).value();

         for(size_t i = 0; i != N; ++i) {
            x.m_val[i] = choose(mask, nx.m_val[i], x.m_val[i]);
            y.m_val[i] = choose(mask, ny.m_val[i], y.m_val[i]);
         }
      }

      // if cond is true, sets x to nx, y to ny, z to nz
      static constexpr void conditional_assign(
         Self& x, Self& y, Self& z, CT::Choice cond, const Self& nx, const Self& ny, const Self& nz) {
         const W mask = CT::Mask<W>::from_choice(cond).value();

         for(size_t i = 0; i != N; ++i) {
            x.m_val[i] = choose(mask, nx.m_val[i], x.m_val[i]);
            y.m_val[i] = choose(mask, ny.m_val[i], y.m_val[i]);
            z.m_val[i] = choose(mask, nz.m_val[i], z.m_val[i]);
         }
      }

      constexpr Self square() const {
         std::array<W, 2 * N> z;
         comba_sqr<N>(z.data(), this->data());
         return Self(Rep::redc(z));
      }

      constexpr void square_n(size_t n) {
         std::array<W, 2 * N> z;
         for(size_t i = 0; i != n; ++i) {
            comba_sqr<N>(z.data(), this->data());
            m_val = Rep::redc(z);
         }
      }

      // Negation modulo p
      constexpr Self negate() const {
         auto x_is_zero = CT::all_zeros(this->data(), N);

         std::array<W, N> r;
         bigint_sub3(r.data(), P.data(), N, this->data(), N);
         x_is_zero.if_set_zero_out(r.data(), N);
         return Self(r);
      }

      constexpr Self pow_vartime(const std::array<W, N>& exp) const {
         constexpr size_t WindowBits = (Self::BITS <= 256) ? 4 : 5;
         constexpr size_t WindowElements = (1 << WindowBits) - 1;

         constexpr size_t Windows = (Self::BITS + WindowBits - 1) / WindowBits;

         std::array<Self, WindowElements> tbl;

         tbl[0] = (*this);

         for(size_t i = 1; i != WindowElements; ++i) {
            if(i % 2 == 1) {
               tbl[i] = tbl[i / 2].square();
            } else {
               tbl[i] = tbl[i - 1] * tbl[0];
            }
         }

         auto r = Self::one();

         const size_t w0 = read_window_bits<WindowBits>(std::span{exp}, (Windows - 1) * WindowBits);

         if(w0 > 0) {
            r = tbl[w0 - 1];
         }

         for(size_t i = 1; i != Windows; ++i) {
            r.square_n(WindowBits);

            const size_t w = read_window_bits<WindowBits>(std::span{exp}, (Windows - i - 1) * WindowBits);

            if(w > 0) {
               r *= tbl[w - 1];
            }
         }

         return r;
      }

      /**
      * Returns the modular inverse, or 0 if no modular inverse exists.
      *
      * If the modulus is prime the only value that has no modular inverse is 0.
      *
      * This uses Fermat's little theorem, and so assumes that p is prime
      */
      constexpr Self invert() const { return pow_vartime(Self::P_MINUS_2); }

      /**
      * Return the modular square root if it exists
      */
      constexpr std::pair<Self, CT::Choice> sqrt() const {
         constexpr auto P_PLUS_1_OVER_4 = p_plus_1_over_4(P);
         auto z = pow_vartime(P_PLUS_1_OVER_4);
         const CT::Choice correct = (z.square() == *this);
         Self::conditional_assign(z, !correct, Self::zero());
         return {z, correct};
      }

      constexpr CT::Choice operator==(const Self& other) const {
         return CT::is_equal(this->data(), other.data(), N).as_choice();
      }

      constexpr CT::Choice operator!=(const Self& other) const {
         return CT::is_not_equal(this->data(), other.data(), N).as_choice();
      }

      constexpr std::array<W, Self::N> to_words() const { return Rep::from_rep(m_val); }

      constexpr void serialize_to(std::span<uint8_t, Self::BYTES> bytes) const {
         auto v = Rep::from_rep(m_val);
         std::reverse(v.begin(), v.end());

         if constexpr(Self::BYTES == N * WordInfo<W>::bytes) {
            store_be(bytes, v);
         } else {
            // Remove leading zero bytes
            const auto padded_bytes = store_be(v);
            constexpr size_t extra = N * WordInfo<W>::bytes - Self::BYTES;
            copy_mem(bytes, std::span{padded_bytes}.template subspan<extra, Self::BYTES>());
         }
      }

      template <size_t L>
      std::array<W, L> stash_value() const {
         static_assert(L >= N);
         std::array<W, L> stash = {};
         for(size_t i = 0; i != N; ++i) {
            stash[i] = m_val[i];
         }
         return stash;
      }

      template <size_t L>
      static Self from_stash(const std::array<W, L>& stash) {
         static_assert(L >= N);
         std::array<W, N> val = {};
         for(size_t i = 0; i != N; ++i) {
            val[i] = stash[i];
         }
         return Self(val);
      }

      // Returns nullopt if the input is an encoding greater than or equal P
      static std::optional<Self> deserialize(std::span<const uint8_t> bytes) {
         // We could allow either short inputs or longer zero padded
         // inputs here, however it seems best to avoid non-canonical
         // representations unless required
         if(bytes.size() != Self::BYTES) {
            return {};
         }

         const auto words = bytes_to_words<W, N, BYTES>(bytes.first<Self::BYTES>());

         if(!bigint_ct_is_lt(words.data(), N, P.data(), N).as_bool()) {
            return {};
         }

         return Self::from_words(words);
      }

      // Reduces large input modulo the order
      template <size_t L>
      static constexpr Self from_wide_bytes(std::span<const uint8_t, L> bytes) {
         static_assert(8 * L <= 2 * Self::BITS);
         std::array<uint8_t, 2 * BYTES> padded_bytes = {};
         copy_mem(std::span{padded_bytes}.template last<L>(), bytes);
         return Self(Rep::wide_to_rep(bytes_to_words<W, 2 * N, 2 * BYTES>(std::span{padded_bytes})));
      }

      // Reduces large input modulo the order
      static constexpr std::optional<Self> from_wide_bytes_varlen(std::span<const uint8_t> bytes) {
         if(8 * bytes.size() > 2 * Self::BITS) {
            return {};
         }
         std::array<uint8_t, 2 * BYTES> padded_bytes = {};
         copy_mem(std::span{padded_bytes}.last(bytes.size()), bytes);
         return Self(Rep::wide_to_rep(bytes_to_words<W, 2 * N, 2 * BYTES>(std::span{padded_bytes})));
      }

      static Self random(RandomNumberGenerator& rng) {
         constexpr size_t MAX_ATTEMPTS = 1000;

         std::array<uint8_t, Self::BYTES> buf;

         for(size_t i = 0; i != MAX_ATTEMPTS; ++i) {
            rng.randomize(buf);

            // Zero off high bits that if set would certainly cause us
            // to be out of range
            if constexpr(Self::BITS % 8 != 0) {
               constexpr uint8_t mask = 0xFF >> (8 - (Self::BITS % 8));
               buf[0] &= mask;
            }

            if(auto s = Self::deserialize(buf)) {
               if(s.value().is_nonzero().as_bool()) {
                  return s.value();
               }
            }
         }

         throw Internal_Error("Failed to generate random Scalar within bounded number of attempts");
      }

      static consteval Self constant(int8_t x) {
         std::array<W, 1> v;
         v[0] = (x >= 0) ? x : -x;
         auto s = Self::from_words(v);
         return (x >= 0) ? s : s.negate();
      }

      constexpr void _const_time_poison() const { CT::poison(m_val); }

      constexpr void _const_time_unpoison() const { CT::unpoison(m_val); }

   private:
      constexpr const std::array<W, N>& value() const { return m_val; }

      constexpr const W* data() const { return m_val.data(); }

      explicit constexpr FLInt(std::array<W, N> v) : m_val(v) {}

      std::array<W, N> m_val;
};

}

GenericPrimeOrderCurve::GenericPrimeOrderCurve(
   const BigInt& p, const BigInt& a, const BigInt& b, const BigInt& base_x, const BigInt& base_y, const BigInt& order) :
   m_order_bits(order.bits()),
   m_order_bytes(order.bytes()),
   m_fe_bytes(p.bytes()) {

   const size_t p_bits = p.bits();

   throw Not_Implemented(__func__);
}

size_t GenericPrimeOrderCurve::order_bits() const {
   return m_order_bits;
}

size_t GenericPrimeOrderCurve::scalar_bytes() const {
   return m_order_bytes;
}

size_t GenericPrimeOrderCurve::field_element_bytes() const {
   return m_fe_bytes;
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::mul_by_g(const Scalar& scalar,
                                                                  RandomNumberGenerator& rng) const {
   BOTAN_UNUSED(scalar, rng);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::mul(const AffinePoint& pt,
                                                             const Scalar& scalar,
                                                             RandomNumberGenerator& rng) const {
   BOTAN_UNUSED(pt, scalar, rng);
   throw Not_Implemented(__func__);
}

std::unique_ptr<const PrimeOrderCurve::PrecomputedMul2Table> GenericPrimeOrderCurve::mul2_setup(
   const AffinePoint& x, const AffinePoint& y) const {
   BOTAN_UNUSED(x, y);
   throw Not_Implemented(__func__);
}

std::optional<PrimeOrderCurve::ProjectivePoint> GenericPrimeOrderCurve::mul2_vartime(const PrecomputedMul2Table& tableb,
                                                                                     const Scalar& s1,
                                                                                     const Scalar& s2) const {
   BOTAN_UNUSED(tableb, s1, s2);
   throw Not_Implemented(__func__);
};

std::optional<PrimeOrderCurve::ProjectivePoint> GenericPrimeOrderCurve::mul_px_qy(
   const AffinePoint& p, const Scalar& x, const AffinePoint& q, const Scalar& y, RandomNumberGenerator& rng) const {
   BOTAN_UNUSED(p, x, q, y, rng);
   throw Not_Implemented(__func__);
};

bool GenericPrimeOrderCurve::mul2_vartime_x_mod_order_eq(const PrecomputedMul2Table& tableb,
                                                         const Scalar& v,
                                                         const Scalar& s1,
                                                         const Scalar& s2) const {
   BOTAN_UNUSED(tableb, v, s1, s2);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::base_point_mul_x_mod_order(const Scalar& scalar,
                                                                           RandomNumberGenerator& rng) const {
   BOTAN_UNUSED(scalar, rng);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::AffinePoint GenericPrimeOrderCurve::generator() const {
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::AffinePoint GenericPrimeOrderCurve::point_to_affine(const ProjectivePoint& pt) const {
   BOTAN_UNUSED(pt);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::point_to_projective(const AffinePoint& pt) const {
   BOTAN_UNUSED(pt);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::point_double(const ProjectivePoint& pt) const {
   BOTAN_UNUSED(pt);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::point_add(const ProjectivePoint& a,
                                                                   const ProjectivePoint& b) const {
   BOTAN_UNUSED(a, b);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::point_add_mixed(const ProjectivePoint& a,
                                                                         const AffinePoint& b) const {
   BOTAN_UNUSED(a, b);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::AffinePoint GenericPrimeOrderCurve::point_negate(const AffinePoint& pt) const {
   BOTAN_UNUSED(pt);
   throw Not_Implemented(__func__);
}

bool GenericPrimeOrderCurve::affine_point_is_identity(const AffinePoint& pt) const {
   BOTAN_UNUSED(pt);
   throw Not_Implemented(__func__);
}

void GenericPrimeOrderCurve::serialize_point(std::span<uint8_t> bytes, const AffinePoint& pt) const {
   BOTAN_UNUSED(bytes, pt);
   throw Not_Implemented(__func__);
}

void GenericPrimeOrderCurve::serialize_point_compressed(std::span<uint8_t> bytes, const AffinePoint& pt) const {
   BOTAN_UNUSED(bytes, pt);
   throw Not_Implemented(__func__);
}

void GenericPrimeOrderCurve::serialize_point_x(std::span<uint8_t> bytes, const AffinePoint& pt) const {
   BOTAN_UNUSED(bytes, pt);
   throw Not_Implemented(__func__);
}

void GenericPrimeOrderCurve::serialize_scalar(std::span<uint8_t> bytes, const Scalar& scalar) const {
   BOTAN_UNUSED(bytes, scalar);
   throw Not_Implemented(__func__);
}

std::optional<PrimeOrderCurve::Scalar> GenericPrimeOrderCurve::deserialize_scalar(
   std::span<const uint8_t> bytes) const {
   BOTAN_UNUSED(bytes);
   throw Not_Implemented(__func__);
}

std::optional<PrimeOrderCurve::Scalar> GenericPrimeOrderCurve::scalar_from_wide_bytes(
   std::span<const uint8_t> bytes) const {
   BOTAN_UNUSED(bytes);
   throw Not_Implemented(__func__);
}

std::optional<PrimeOrderCurve::AffinePoint> GenericPrimeOrderCurve::deserialize_point(
   std::span<const uint8_t> bytes) const {
   BOTAN_UNUSED(bytes);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::AffinePoint GenericPrimeOrderCurve::hash_to_curve_nu(std::string_view hash,
                                                                      std::span<const uint8_t> input,
                                                                      std::span<const uint8_t> domain_sep) const {
   BOTAN_UNUSED(hash, input, domain_sep);
   throw Not_Implemented("Hash to curve is not implemented for this curve");
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::hash_to_curve_ro(std::string_view hash,
                                                                          std::span<const uint8_t> input,
                                                                          std::span<const uint8_t> domain_sep) const {
   BOTAN_UNUSED(hash, input, domain_sep);
   throw Not_Implemented("Hash to curve is not implemented for this curve");
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_add(const Scalar& a, const Scalar& b) const {
   BOTAN_UNUSED(a, b);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_sub(const Scalar& a, const Scalar& b) const {
   BOTAN_UNUSED(a, b);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_mul(const Scalar& a, const Scalar& b) const {
   BOTAN_UNUSED(a, b);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_square(const Scalar& s) const {
   BOTAN_UNUSED(s);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_invert(const Scalar& s) const {
   BOTAN_UNUSED(s);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_negate(const Scalar& s) const {
   BOTAN_UNUSED(s);
   throw Not_Implemented(__func__);
}

bool GenericPrimeOrderCurve::scalar_is_zero(const Scalar& s) const {
   BOTAN_UNUSED(s);
   throw Not_Implemented(__func__);
}

bool GenericPrimeOrderCurve::scalar_equal(const Scalar& a, const Scalar& b) const {
   BOTAN_UNUSED(a, b);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_zero() const {
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_one() const {
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_from_u32(uint32_t x) const {
   BOTAN_UNUSED(x);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::random_scalar(RandomNumberGenerator& rng) const {
   BOTAN_UNUSED(rng);
   throw Not_Implemented(__func__);
}

std::shared_ptr<const PrimeOrderCurve> PCurveInstance::from_params(
   const BigInt& p, const BigInt& a, const BigInt& b, const BigInt& base_x, const BigInt& base_y, const BigInt& order) {
   BOTAN_ARG_CHECK(is_bailie_psw_probable_prime(p), "p is not prime");
   BOTAN_ARG_CHECK(is_bailie_psw_probable_prime(order), "order is not prime");
   BOTAN_ARG_CHECK(a >= 0 && a < p, "a is invalid");
   BOTAN_ARG_CHECK(b > 0 && b < p, "b is invalid");
   BOTAN_ARG_CHECK(base_x >= 0 && base_x < p, "base_x is invalid");
   BOTAN_ARG_CHECK(base_y >= 0 && base_y < p, "base_y is invalid");

   const size_t p_bits = p.bits();

   // Same size restriction as EC_Group:
   // Must be either exactly P-512 or else in 128..512 bits multiple of 32
   if(p_bits == 512) {
      if(p != BigInt::power_of_2(521) - 1) {
         return {};
      }
   } else if(p_bits < 128 || p_bits > 512 || p_bits % 32 != 0) {
      return {};
   }

   // We don't want to deal with Shanks-Tonelli in the generic case
   if(p % 4 != 3) {
      return {};
   }

   // The bit length of the field and order being the same simplifies things
   if(p_bits != order.bits()) {
      return {};
   }

   return std::make_shared<GenericPrimeOrderCurve>(p, a, b, base_x, base_y, order);
}

}  // namespace Botan::PCurve
