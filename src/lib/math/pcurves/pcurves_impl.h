/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PCURVES_IMPL_H_
#define BOTAN_PCURVES_IMPL_H_

#include <botan/rng.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/pcurves_util.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/xmd.h>
#include <vector>

namespace Botan {

template <typename Params>
class MontgomeryRep final {
   public:
      using Self = MontgomeryRep<Params>;

      static constexpr auto P = Params::P;
      static constexpr size_t N = Params::N;
      typedef typename Params::W W;

      static_assert(N > 0 && (Params::P[0] & 1) == 1, "Invalid Montgomery modulus");

      static constexpr auto P_dash = monty_inverse(P[0]);

      static constexpr auto R1 = montygomery_r(P);
      static constexpr auto R2 = mul_mod(R1, R1, P);
      static constexpr auto R3 = mul_mod(R1, R2, P);

      constexpr static std::array<W, N> one() { return R1; }

      constexpr static std::array<W, N> redc(const std::array<W, 2 * N>& z) {
         if constexpr(P_dash == 1) {
            return monty_redc_pdash1(z, P);
         } else {
            return monty_redc(z, P, P_dash);
         }
      }

      constexpr static std::array<W, N> to_rep(const std::array<W, N>& x) {
         std::array<W, 2 * N> z;
         comba_mul<N>(z.data(), x.data(), R2.data());
         return Self::redc(z);
      }

      constexpr static std::array<W, N> wide_to_rep(const std::array<W, 2 * N>& x) {
         auto redc_x = Self::redc(x);
         std::array<W, 2 * N> z;
         comba_mul<N>(z.data(), redc_x.data(), R3.data());
         return Self::redc(z);
      }

      constexpr static std::array<W, N> from_rep(const std::array<W, N>& z) {
         std::array<W, 2 * N> ze = {};
         copy_mem(std::span{ze}.template first<N>(), z);
         return Self::redc(ze);
      }
};

template <typename Rep>
class IntMod final {
   private:
      static constexpr auto P = Rep::P;
      static constexpr size_t N = Rep::N;
      typedef typename Rep::W W;

      static constexpr auto P_MINUS_2 = p_minus<2>(P);
      static constexpr auto P_PLUS_1_OVER_4 = p_plus_1_over_4(P);
      static constexpr auto P_MINUS_1_OVER_2 = p_minus_1_over_2(P);

   public:
      static constexpr size_t BITS = count_bits(P);
      static constexpr size_t BYTES = (BITS + 7) / 8;

      static constexpr auto P_MOD_4 = P[0] % 4;

      using Self = IntMod<Rep>;

      // Default value is zero
      constexpr IntMod() : m_val({}) {}

      IntMod(const Self& other) = default;
      IntMod(Self&& other) = default;
      IntMod& operator=(const Self& other) = default;
      IntMod& operator=(Self&& other) = default;

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
         return CT::Choice::from_int(0x01 ^ (v[0] & 0x01));
      }

      friend constexpr Self operator+(const Self& a, const Self& b) {
         std::array<W, N> t;
         W carry = bigint_add<W, N>(t, a.value(), b.value());

         std::array<W, N> r;
         bigint_monty_maybe_sub<N>(r.data(), carry, t.data(), P.data());
         return Self(r);
      }

      friend constexpr Self operator-(const Self& a, const Self& b) { return a + b.negate(); }

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

      // if cond is true, assigns other to *this
      constexpr void conditional_assign(CT::Choice cond, const Self& other) {
         CT::conditional_assign_mem(cond, m_val.data(), other.data(), N);
      }

      constexpr Self square() const {
         std::array<W, 2 * N> z;
         comba_sqr<N>(z.data(), this->data());
         return Self(Rep::redc(z));
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
            for(size_t j = 0; j != WindowBits; ++j) {
               r = r.square();
            }

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
      * Return the modular square root, or zero if no root exists
      *
      * Current impl assumes p == 3 (mod 4)
      */
      constexpr Self sqrt() const
         requires(Self::P_MOD_4 == 3)
      {
         auto z = pow_vartime(Self::P_PLUS_1_OVER_4);
         const CT::Choice correct = (z.square() == *this);
         z.conditional_assign(!correct, Self::zero());
         return z;
      }

      constexpr CT::Choice is_square() const
         requires(Self::P_MOD_4 == 3)
      {
         auto z = pow_vartime(Self::P_MINUS_1_OVER_2);
         const CT::Choice is_one = z.is_one();
         const CT::Choice is_zero = z.is_zero();
         return (is_one || is_zero);
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
      constexpr static std::optional<Self> deserialize(std::span<const uint8_t> bytes) {
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

      // ECDSA style hash->scalar conversion
      //
      // This must accept inputs of any length
      static Self from_bits_with_trunc(std::span<const uint8_t> bytes) {
         const size_t bit_length = bytes.size() * 8;

         if(bit_length <= Self::BITS) {
            // No shifting required, but might still need to reduce by modulus
            std::array<uint8_t, 2 * BYTES> padded_bytes = {};
            copy_mem(std::span{padded_bytes}.last(bytes.size()), bytes);
            return Self(Rep::wide_to_rep(bytes_to_words<W, 2 * N, 2 * BYTES>(std::span{padded_bytes})));
         } else {
            const size_t shift = bit_length - Self::BITS;

            if(shift % 8 == 0) {
               // Easy case just copy different bytes
               const size_t new_length = bytes.size() - (shift / 8);
               return Self::from_bits_with_trunc(bytes.first(new_length));
            } else {
               // fixme
               throw Not_Implemented("Bit shifting for hash to scalar conversion not implemented");
            }
         }
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

      constexpr void ct_poison() const { CT::poison(m_val.data(), m_val.size()); }

      constexpr void ct_unpoison() const { CT::unpoison(m_val.data(), m_val.size()); }

   private:
      constexpr const std::array<W, N>& value() const { return m_val; }

      constexpr const W* data() const { return m_val.data(); }

      explicit constexpr IntMod(std::array<W, N> v) : m_val(v) {}

      std::array<W, N> m_val;
};

template <typename FieldElement, typename Params>
class AffineCurvePoint {
   public:
      // We can't pass a FieldElement directly because FieldElement is
      // not "structural" due to having private members, so instead
      // recreate it here from the words.
      static constexpr FieldElement A = FieldElement::from_words(Params::AW);
      static constexpr FieldElement B = FieldElement::from_words(Params::BW);

      static constexpr size_t BYTES = 1 + 2 * FieldElement::BYTES;
      static constexpr size_t COMPRESSED_BYTES = 1 + FieldElement::BYTES;

      using Self = AffineCurvePoint<FieldElement, Params>;

      constexpr AffineCurvePoint(const FieldElement& x, const FieldElement& y) : m_x(x), m_y(y) {}

      constexpr AffineCurvePoint() : m_x(FieldElement::zero()), m_y(FieldElement::zero()) {}

      static constexpr Self identity() { return Self(FieldElement::zero(), FieldElement::zero()); }

      constexpr CT::Choice is_identity() const { return x().is_zero() && y().is_zero(); }

      AffineCurvePoint(const Self& other) = default;
      AffineCurvePoint(Self&& other) = default;
      AffineCurvePoint& operator=(const Self& other) = default;
      AffineCurvePoint& operator=(Self&& other) = default;

      constexpr Self negate() const { return Self(x(), y().negate()); }

      constexpr void serialize_to(std::span<uint8_t, Self::BYTES> bytes) const {
         BufferStuffer pack(bytes);
         pack.append(0x04);
         x().serialize_to(pack.next<FieldElement::BYTES>());
         y().serialize_to(pack.next<FieldElement::BYTES>());
         BOTAN_DEBUG_ASSERT(pack.full());
      }

      constexpr void serialize_compressed_to(std::span<uint8_t, Self::COMPRESSED_BYTES> bytes) const {
         const uint8_t hdr = CT::Mask<uint8_t>::from_choice(y().is_even()).select(0x02, 0x03);

         BufferStuffer pack(bytes);
         pack.append(hdr);
         x().serialize_to(pack.next<FieldElement::BYTES>());
         BOTAN_DEBUG_ASSERT(pack.full());
      }

      /**
      * If idx is zero then return the identity element. Otherwise return pts[idx - 1]
      *
      * Returns the identity element also if idx is out of range
      */
      static constexpr auto ct_select(std::span<const Self> pts, size_t idx) {
         auto result = Self::identity();

         // Intentionally wrapping; set to maximum size_t if idx == 0
         const size_t idx1 = static_cast<size_t>(idx - 1);
         for(size_t i = 0; i != pts.size(); ++i) {
            const auto found = CT::Mask<size_t>::is_equal(idx1, i).as_choice();
            result.conditional_assign(found, pts[i]);
         }

         return result;
      }

      static constexpr FieldElement x3_ax_b(const FieldElement& x) { return (x.square() + Self::A) * x + Self::B; }

      static constexpr std::optional<Self> deserialize(std::span<const uint8_t> bytes) {
         if(bytes.size() == Self::BYTES) {
            if(bytes[0] != 0x04) {
               return {};
            }
            auto x = FieldElement::deserialize(bytes.subspan(1, FieldElement::BYTES));
            auto y = FieldElement::deserialize(bytes.subspan(1 + FieldElement::BYTES, FieldElement::BYTES));

            if(x && y) {
               const auto lhs = (*y).square();
               const auto rhs = Self::x3_ax_b(*x);
               if((lhs == rhs).as_bool()) {
                  return Self(*x, *y);
               }
            }

            return {};
         } else if(bytes.size() == Self::COMPRESSED_BYTES) {
            if(bytes[0] != 0x02 && bytes[0] != 0x03) {
               return {};
            }
            const CT::Choice y_is_even = CT::Mask<uint8_t>::is_equal(bytes[0], 0x02).as_choice();

            if(auto x = FieldElement::deserialize(bytes.subspan(1, FieldElement::BYTES))) {
               auto y = x3_ax_b(*x).sqrt();
               y.conditional_assign(y_is_even && !y.is_even(), y.negate());
               return Self(*x, y);
            }

            return {};
         } else {
            return {};
         }
      }

      constexpr const FieldElement& x() const { return m_x; }

      constexpr const FieldElement& y() const { return m_y; }

      constexpr void conditional_assign(CT::Choice cond, const Self& pt) {
         m_x.conditional_assign(cond, pt.x());
         m_y.conditional_assign(cond, pt.y());
      }

      constexpr void ct_poison() const {
         x().ct_poison();
         y().ct_poison();
      }

      constexpr void ct_unpoison() const {
         x().ct_unpoison();
         y().ct_unpoison();
      }

   private:
      FieldElement m_x;
      FieldElement m_y;
};

template <typename FieldElement, typename Params>
class ProjectiveCurvePoint {
   public:
      // We can't pass a FieldElement directly because FieldElement is
      // not "structural" due to having private members, so instead
      // recreate it here from the words.
      static constexpr FieldElement A = FieldElement::from_words(Params::AW);

      static constexpr bool A_is_zero = A.is_zero().as_bool();
      static constexpr bool A_is_minus_3 = (A == FieldElement::constant(-3)).as_bool();

      using Self = ProjectiveCurvePoint<FieldElement, Params>;
      using AffinePoint = AffineCurvePoint<FieldElement, Params>;

      static constexpr Self from_affine(const AffinePoint& pt) {
         if(pt.is_identity().as_bool()) {
            return Self::identity();
         } else {
            return ProjectiveCurvePoint(pt.x(), pt.y());
         }
      }

      static constexpr Self identity() { return Self(FieldElement::zero(), FieldElement::one(), FieldElement::zero()); }

      constexpr ProjectiveCurvePoint() :
            m_x(FieldElement::zero()), m_y(FieldElement::one()), m_z(FieldElement::zero()) {}

      constexpr ProjectiveCurvePoint(const FieldElement& x, const FieldElement& y) :
            m_x(x), m_y(y), m_z(FieldElement::one()) {}

      constexpr ProjectiveCurvePoint(const FieldElement& x, const FieldElement& y, const FieldElement& z) :
            m_x(x), m_y(y), m_z(z) {}

      ProjectiveCurvePoint(const Self& other) = default;
      ProjectiveCurvePoint(Self&& other) = default;
      ProjectiveCurvePoint& operator=(const Self& other) = default;
      ProjectiveCurvePoint& operator=(Self&& other) = default;

      friend constexpr Self operator+(const Self& a, const Self& b) { return Self::add(a, b); }

      friend constexpr Self operator+(const Self& a, const AffinePoint& b) { return Self::add_mixed(a, b); }

      friend constexpr Self operator+(const AffinePoint& a, const Self& b) { return Self::add_mixed(b, a); }

      constexpr Self& operator+=(const Self& other) {
         (*this) = (*this) + other;
         return (*this);
      }

      constexpr Self& operator+=(const AffinePoint& other) {
         (*this) = (*this) + other;
         return (*this);
      }

      friend constexpr Self operator-(const Self& a, const Self& b) { return a + b.negate(); }

      constexpr CT::Choice is_identity() const { return z().is_zero(); }

      constexpr void conditional_assign(CT::Choice cond, const Self& pt) {
         m_x.conditional_assign(cond, pt.x());
         m_y.conditional_assign(cond, pt.y());
         m_z.conditional_assign(cond, pt.z());
      }

      constexpr static Self add_mixed(const Self& a, const AffinePoint& b) {
         const auto a_is_identity = a.is_identity();
         const auto b_is_identity = b.is_identity();
         if((a_is_identity && b_is_identity).as_bool()) {
            return Self::identity();
         }

         /*
         https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2

         12M + 4S + 6add + 1*2
         */

         const auto Z1Z1 = a.z().square();
         const auto U2 = b.x() * Z1Z1;
         const auto S2 = b.y() * a.z() * Z1Z1;
         const auto H = U2 - a.x();
         const auto r = S2 - a.y();

         // If r is zero then we are in the doubling case
         if(r.is_zero().as_bool()) {
            return a.dbl();
         }

         const auto HH = H.square();
         const auto HHH = H * HH;
         const auto V = a.x() * HH;
         const auto t2 = r.square();
         const auto t3 = V + V;
         const auto t4 = t2 - HHH;
         auto X3 = t4 - t3;
         const auto t5 = V - X3;
         const auto t6 = a.y() * HHH;
         const auto t7 = r * t5;
         auto Y3 = t7 - t6;
         auto Z3 = a.z() * H;

         // TODO these could be combined
         // if a is identity then return b
         X3.conditional_assign(a_is_identity, b.x());
         Y3.conditional_assign(a_is_identity, b.y());
         Z3.conditional_assign(a_is_identity, FieldElement::one());

         // if b is identity then return a
         X3.conditional_assign(b_is_identity, a.x());
         Y3.conditional_assign(b_is_identity, a.y());
         Z3.conditional_assign(b_is_identity, a.z());

         return Self(X3, Y3, Z3);
      }

      constexpr static Self add(const Self& a, const Self& b) {
         const auto a_is_identity = a.is_identity();
         const auto b_is_identity = b.is_identity();
         if((a_is_identity && b_is_identity).as_bool()) {
            return Self::identity();
         }

         /*
         https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2
         */

         const auto Z1Z1 = a.z().square();
         const auto Z2Z2 = b.z().square();
         const auto U1 = a.x() * Z2Z2;
         const auto U2 = b.x() * Z1Z1;
         const auto S1 = a.y() * b.z() * Z2Z2;
         const auto S2 = b.y() * a.z() * Z1Z1;
         const auto H = U2 - U1;
         const auto r = S2 - S1;

         if(r.is_zero().as_bool()) {
            return a.dbl();
         }

         const auto HH = H.square();
         const auto HHH = H * HH;
         const auto V = U1 * HH;
         const auto t2 = r.square();
         const auto t3 = V + V;
         const auto t4 = t2 - HHH;
         auto X3 = t4 - t3;
         const auto t5 = V - X3;
         const auto t6 = S1 * HHH;
         const auto t7 = r * t5;
         auto Y3 = t7 - t6;
         const auto t8 = b.z() * H;
         auto Z3 = a.z() * t8;

         // TODO these could be combined
         // if a is identity then return b
         X3.conditional_assign(a_is_identity, b.x());
         Y3.conditional_assign(a_is_identity, b.y());
         Z3.conditional_assign(a_is_identity, b.z());

         // if b is identity then return a
         X3.conditional_assign(b_is_identity, a.x());
         Y3.conditional_assign(b_is_identity, a.y());
         Z3.conditional_assign(b_is_identity, a.z());

         return Self(X3, Y3, Z3);
      }

      constexpr Self dbl_n(size_t n) const {
         // TODO it is possible to optimize this by carrying over values from
         // the previous iteration into the next

         Self pt = (*this);
         for(size_t i = 0; i != n; ++i) {
            pt = pt.dbl();
         }
         return pt;
      }

      constexpr Self dbl() const {
         //https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-1998-cmo-2

         FieldElement m = FieldElement::zero();

         if constexpr(Self::A_is_minus_3) {
            /*
            if a == -3 then
            3*x^2 + a*z^4 == 3*x^2 - 3*z^4 == 3*(x^2-z^4) == 3*(x-z^2)*(x+z^2)

            Cost: 2M + 2A + 1*3
            */
            const auto z2 = z().square();
            m = (x() - z2).mul3() * (x() + z2);
         } else if constexpr(Self::A_is_zero) {
            // If a == 0 then 3*x^2 + a*z^4 == 3*x^2
            // Cost: 1S + 1*3
            m = x().square().mul3();
         } else {
            // Cost: 1M + 3S + 1A + 1*3
            const auto z2 = z().square();
            m = x().square().mul3() + A * z2.square();
         }

         const auto y2 = y().square();
         const auto s = x().mul4() * y2;
         const auto nx = m.square() - s.mul2();
         const auto ny = m * (s - nx) - y2.square().mul8();
         const auto nz = y().mul2() * z();

         return Self(nx, ny, nz);
      }

      constexpr Self negate() const { return Self(x(), y().negate(), z()); }

      constexpr AffinePoint to_affine() const {
         // Not strictly required right? - default should work as long
         // as (0,0) is identity and invert returns 0 on 0
         if(this->is_identity().as_bool()) {
            return AffinePoint::identity();
         }

         const auto z_inv = m_z.invert();
         const auto z2_inv = z_inv.square();
         const auto z3_inv = z_inv * z2_inv;

         const auto x = m_x * z2_inv;
         const auto y = m_y * z3_inv;
         return AffinePoint(x, y);
      }

      static std::vector<AffinePoint> to_affine_batch(std::span<const Self> projective) {
         const size_t N = projective.size();
         std::vector<AffinePoint> affine(N, AffinePoint::identity());

         bool any_identity = false;
         for(size_t i = 0; i != N; ++i) {
            if(projective[i].is_identity().as_bool()) {
               any_identity = true;
               // If any of the elements are the identity we fall back to
               // performing the conversion without a batch
               break;
            }
         }

         if(N <= 2 || any_identity) {
            for(size_t i = 0; i != N; ++i) {
               affine[i] = projective[i].to_affine();
            }
         } else {
            std::vector<FieldElement> c(N);

            /*
            Batch projective->affine using Montgomery's trick

            See Algorithm 2.26 in "Guide to Elliptic Curve Cryptography"
            (Hankerson, Menezes, Vanstone)
            */

            c[0] = projective[0].z();
            for(size_t i = 1; i != N; ++i) {
               c[i] = c[i - 1] * projective[i].z();
            }

            auto s_inv = c[N - 1].invert();

            for(size_t i = N - 1; i > 0; --i) {
               const auto& p = projective[i];

               const auto z_inv = s_inv * c[i - 1];
               const auto z2_inv = z_inv.square();
               const auto z3_inv = z_inv * z2_inv;

               s_inv = s_inv * p.z();

               affine[i] = AffinePoint(p.x() * z2_inv, p.y() * z3_inv);
            }

            const auto z2_inv = s_inv.square();
            const auto z3_inv = s_inv * z2_inv;
            affine[0] = AffinePoint(projective[0].x() * z2_inv, projective[0].y() * z3_inv);
         }

         return affine;
      }

      void randomize_rep(RandomNumberGenerator& rng) {
         auto r = FieldElement::random(rng);

         auto r2 = r.square();
         auto r3 = r2 * r;

         m_x *= r2;
         m_y *= r3;
         m_z *= r;
      }

      constexpr const FieldElement& x() const { return m_x; }

      constexpr const FieldElement& y() const { return m_y; }

      constexpr const FieldElement& z() const { return m_z; }

      constexpr void ct_poison() const {
         x().ct_poison();
         y().ct_poison();
         z().ct_poison();
      }

      constexpr void ct_unpoison() const {
         x().ct_unpoison();
         y().ct_unpoison();
         z().ct_unpoison();
      }

   private:
      FieldElement m_x;
      FieldElement m_y;
      FieldElement m_z;
};

template <StringLiteral PS,
          StringLiteral AS,
          StringLiteral BS,
          StringLiteral NS,
          StringLiteral GXS,
          StringLiteral GYS,
          int8_t ZI = 0>
class EllipticCurveParameters {
   public:
      typedef word W;

      static constexpr auto PW = hex_to_words<W>(PS.value);
      static constexpr auto NW = hex_to_words<W>(NS.value);
      static constexpr auto AW = hex_to_words<W>(AS.value);
      static constexpr auto BW = hex_to_words<W>(BS.value);
      static constexpr auto GXW = hex_to_words<W>(GXS.value);
      static constexpr auto GYW = hex_to_words<W>(GYS.value);

      static constexpr int8_t Z = ZI;
};

template <WordType WI, size_t NI, std::array<WI, NI> PI>
struct IntParams {
   public:
      typedef WI W;
      static constexpr size_t N = NI;
      static constexpr auto P = PI;
};

template <typename Params, template <typename FieldParamsT> typename FieldRep = MontgomeryRep>
class EllipticCurve {
   public:
      typedef typename Params::W W;

      static constexpr auto PW = Params::PW;
      static constexpr auto NW = Params::NW;
      static constexpr auto AW = Params::AW;

      // Simplifying assumption
      static_assert(PW.size() == NW.size());

      class ScalarParams final : public IntParams<W, NW.size(), NW> {};

      using Scalar = IntMod<MontgomeryRep<ScalarParams>>;

      class FieldParams final : public IntParams<W, PW.size(), PW> {};

      using FieldElement = IntMod<FieldRep<FieldParams>>;

      using AffinePoint = AffineCurvePoint<FieldElement, Params>;
      using ProjectivePoint = ProjectiveCurvePoint<FieldElement, Params>;

      static constexpr size_t OrderBits = Scalar::BITS;
      static constexpr size_t PrimeFieldBits = FieldElement::BITS;

      static constexpr FieldElement A = FieldElement::from_words(Params::AW);
      static constexpr FieldElement B = FieldElement::from_words(Params::BW);

      static constexpr AffinePoint G =
         AffinePoint(FieldElement::from_words(Params::GXW), FieldElement::from_words(Params::GYW));

      static constexpr FieldElement SSWU_Z = FieldElement::constant(Params::Z);

      static constexpr bool ValidForSswuHash =
         (Params::Z != 0 && A.is_nonzero().as_bool() && B.is_nonzero().as_bool() && FieldElement::P_MOD_4 == 3);

      // (-B / A), will be zero if A == 0 or B == 0 or Z == 0
      static const FieldElement& SSWU_C1()
         requires ValidForSswuHash
      {
         // We derive it from C2 to avoid a second inversion
         static const auto C1 = (SSWU_C2() * SSWU_Z).negate();
         return C1;
      }

      // (B / (Z * A)), will be zero if A == 0 or B == 0 or Z == 0
      static const FieldElement& SSWU_C2()
         requires ValidForSswuHash
      {
         // This could use a variable time inversion
         static const auto C2 = (B * (SSWU_Z * A).invert());
         return C2;
      }
};

/**
* Blinded Scalar
*
* This randomizes the scalar representation by computing s + n*k
* where n is the group order and k is a random value
*/
template <typename C, size_t WindowBits>
class BlindedScalarBits final {
   private:
      typedef typename C::W W;

      static constexpr bool BlindingEnabled = true;

      // For blinding use 1/4 the order, rounded up to the next word
      static constexpr size_t BlindingBits =
         ((C::OrderBits / 4 + WordInfo<W>::bits - 1) / WordInfo<W>::bits) * WordInfo<W>::bits;

      static_assert(BlindingBits % WordInfo<W>::bits == 0);
      static_assert(BlindingBits < C::Scalar::BITS);

   public:
      static constexpr size_t Bits = C::Scalar::BITS + (BlindingEnabled ? BlindingBits : 0);
      static constexpr size_t Bytes = (Bits + 7) / 8;

      BlindedScalarBits(const typename C::Scalar& scalar, RandomNumberGenerator& rng) {
         if constexpr(BlindingEnabled) {
            constexpr size_t mask_words = BlindingBits / WordInfo<W>::bits;
            constexpr size_t mask_bytes = mask_words * WordInfo<W>::bytes;

            constexpr size_t n_words = C::NW.size();

            uint8_t maskb[mask_bytes] = {0};
            rng.randomize(maskb, mask_bytes);

            W mask[n_words] = {0};
            load_le(mask, maskb, mask_words);
            mask[mask_words - 1] |= WordInfo<W>::top_bit;

            W mask_n[2 * n_words] = {0};

            const auto sw = scalar.to_words();

            // Compute masked scalar s + k*n
            comba_mul<n_words>(mask_n, mask, C::NW.data());
            bigint_add2_nc(mask_n, 2 * n_words, sw.data(), sw.size());

            std::reverse(mask_n, mask_n + 2 * n_words);
            m_bytes = store_be<std::vector<uint8_t>>(mask_n);
         } else {
            static_assert(Bytes == C::Scalar::BYTES);
            m_bytes.resize(Bytes);
            scalar.serialize_to(std::span{m_bytes}.template first<Bytes>());
         }

         CT::poison(m_bytes.data(), m_bytes.size());
      }

      size_t get_window(size_t offset) const {
         // Extract a WindowBits sized window out of s, depending on offset.
         return read_window_bits<WindowBits>(std::span{m_bytes}, offset);
      }

      ~BlindedScalarBits() {
         secure_scrub_memory(m_bytes.data(), m_bytes.size());
         CT::unpoison(m_bytes.data(), m_bytes.size());
      }

   private:
      // TODO this could be a fixed size array
      std::vector<uint8_t> m_bytes;
};

template <typename C, size_t WindowBits>
class UnblindedScalarBits final {
   public:
      static constexpr size_t Bits = C::Scalar::BITS;

      UnblindedScalarBits(const typename C::Scalar& scalar) { scalar.serialize_to(std::span{m_bytes}); }

      size_t get_window(size_t offset) const {
         // Extract a WindowBits sized window out of s, depending on offset.
         return read_window_bits<WindowBits>(std::span{m_bytes}, offset);
      }

   private:
      std::array<uint8_t, C::Scalar::BYTES> m_bytes;
};

/**
* Base point precomputation table
*
* This algorithm works by precomputing a set of points such that
* the online phase of the point multiplication can be effected by
* a sequence of point additions.
*
* The tables, even for W = 1, are large and costly to precompute, so
* this is only used for the base point.
*
* The online phase of the algorithm uess `ceil(SB/W)` additions,
* and no point doublings. The table is of size
* `ceil(SB + W - 1)/W * ((1 << W) - 1)`
* where SB is the bit length of the (blinded) scalar.
*
* Each window of the scalar is associated with a window in the table.
* The table windows are unique to that offset within the scalar.
*
* The simplest version to understand is when W = 1. There the table
* consists of [P, 2*P, 4*P, ..., 2^N*P] where N is the bit length of
* the group order. The online phase consists of conditionally adding
* table[i] depending on if bit i of the scalar is set or not.
*
* When W = 2, the scalar is examined 2 bits at a time, and the table
* for a window index `I` is [(2^I)*P, (2^(I+1))*P, (2^I+2^(I+1))*P].
*
* This extends similarly for larger W
*
* At a certain point, the side channel silent table lookup becomes the
* dominating cost
*
* For all W, each window in the table has an implicit element of
* the identity element which is used if the scalar bits were all zero.
* This is omitted to save space; AffinePoint::ct_select is designed
* to assist in this by returning the identity element if its index
* argument is zero, or otherwise it returns table[idx - 1]
*/
template <typename C, size_t W>
class PrecomputedBaseMulTable final {
   public:
      typedef typename C::Scalar Scalar;
      typedef typename C::AffinePoint AffinePoint;
      typedef typename C::ProjectivePoint ProjectivePoint;

      static constexpr size_t WindowBits = W;
      static_assert(WindowBits >= 1 && WindowBits <= 8);

      using BlindedScalar = BlindedScalarBits<C, WindowBits>;

      static constexpr size_t Windows = (BlindedScalar::Bits + WindowBits - 1) / WindowBits;

      static_assert(Windows > 1);

      // 2^W elements, less the identity element
      static constexpr size_t WindowElements = (1 << WindowBits) - 1;

      static constexpr size_t TableSize = Windows * WindowElements;

      PrecomputedBaseMulTable(const AffinePoint& p) : m_table{} {
         std::vector<ProjectivePoint> table;
         table.reserve(TableSize);

         auto accum = ProjectivePoint::from_affine(p);

         for(size_t i = 0; i != TableSize; i += WindowElements) {
            table.push_back(accum);

            for(size_t j = 1; j != WindowElements; ++j) {
               if(j % 2 == 1) {
                  table.emplace_back(table[i + j / 2].dbl());
               } else {
                  table.emplace_back(table[i + j - 1] + table[i]);
               }
            }

            accum = table[i + (WindowElements / 2)].dbl();
         }

         m_table = ProjectivePoint::to_affine_batch(table);
      }

      ProjectivePoint mul(const Scalar& s, RandomNumberGenerator& rng) const {
         const BlindedScalar bits(s, rng);

         // TODO: C++23 - use std::mdspan to access m_table
         auto table = std::span{m_table};

         auto accum = [&]() {
            const size_t w_0 = bits.get_window(0);
            const auto tbl_0 = table.first(WindowElements);
            auto pt = ProjectivePoint::from_affine(AffinePoint::ct_select(tbl_0, w_0));
            pt.ct_poison();
            pt.randomize_rep(rng);
            return pt;
         }();

         for(size_t i = 1; i != Windows; ++i) {
            const size_t w_i = bits.get_window(WindowBits * i);
            const auto tbl_i = table.subspan(WindowElements * i, WindowElements);

            /*
            None of these additions can be doublings, because in each iteration, the
            discrete logarithms of the points we're selecting out of the table are
            larger than the largest possible dlog of accum.
            */
            accum += AffinePoint::ct_select(tbl_i, w_i);

            if(i <= 3) {
               accum.randomize_rep(rng);
            }
         }

         accum.ct_unpoison();
         return accum;
      }

   private:
      std::vector<AffinePoint> m_table;
};

/**
* Precomputed point multiplication table
*
* This is a standard fixed window multiplication using W-bit wide window.
*/
template <typename C, size_t W>
class WindowedMulTable final {
   public:
      typedef typename C::Scalar Scalar;
      typedef typename C::AffinePoint AffinePoint;
      typedef typename C::ProjectivePoint ProjectivePoint;

      static constexpr size_t WindowBits = W;
      static_assert(WindowBits >= 1 && WindowBits <= 8);

      using BlindedScalar = BlindedScalarBits<C, WindowBits>;

      static constexpr size_t Windows = (BlindedScalar::Bits + WindowBits - 1) / WindowBits;

      static_assert(Windows > 1);

      // 2^W elements, less the identity element
      static constexpr size_t TableSize = (1 << WindowBits) - 1;

      WindowedMulTable(const AffinePoint& p) : m_table{} {
         std::vector<ProjectivePoint> table;
         table.reserve(TableSize);

         table.push_back(ProjectivePoint::from_affine(p));
         for(size_t i = 1; i != TableSize; ++i) {
            if(i % 2 == 1) {
               table.push_back(table[i / 2].dbl());
            } else {
               table.push_back(table[i - 1] + table[0]);
            }
         }

         m_table = ProjectivePoint::to_affine_batch(table);
      }

      ProjectivePoint mul(const Scalar& s, RandomNumberGenerator& rng) const {
         const BlindedScalar bits(s, rng);

         auto accum = [&]() {
            const size_t w_0 = bits.get_window((Windows - 1) * WindowBits);
            // Guaranteed because we set the high bit of the randomizer
            BOTAN_DEBUG_ASSERT(w_0 != 0);
            auto pt = ProjectivePoint::from_affine(AffinePoint::ct_select(m_table, w_0));
            pt.ct_poison();
            pt.randomize_rep(rng);
            return pt;
         }();

         for(size_t i = 1; i != Windows; ++i) {
            accum = accum.dbl_n(WindowBits);
            const size_t w_i = bits.get_window((Windows - i - 1) * WindowBits);

            /*
            This point addition cannot be a doubling (except once)

            Consider the sequence of points that are operated on, and specifically
            their discrete logarithms. We start out at the point at infinity
            (dlog 0) and then add the initial window which is precisely P*w_0

            We then perform WindowBits doublings, so accum's dlog at the point
            of the addition in the first iteration of the loop (when i == 1) is
            at least 2^W * w_0.

            Since we know w_0 > 0, then in every iteration of the loop, accums
            dlog will always be greater than the dlog of the table element we
            just looked up (something between 0 and 2^W-1), and thus the
            addition into accum cannot be a doubling.

            However due to blinding this argument fails, since we perform
            multiplications using a scalar that is larger than the group
            order. In this case it's possible that the dlog of accum becomes
            `order + x` (or, effectively, `x`) and `x` is smaller than 2^W.
            In this case, a doubling may occur. Future iterations of the loop
            cannot be doublings by the same argument above. Since the blinding
            factor is always less than the group order (substantially so),
            it is not possible for the dlog of accum to overflow a second time.
            */
            accum += AffinePoint::ct_select(m_table, w_i);

            if(i <= 3) {
               accum.randomize_rep(rng);
            }
         }

         accum.ct_unpoison();
         return accum;
      }

   private:
      std::vector<AffinePoint> m_table;
};

/**
* Effect 2-ary multiplication ie x*G + y*H
*
* This is done using a windowed variant of what is usually called
* Shamir's trick.
*
* The W = 1 case is simple; we precompute an extra point GH = G + H,
* and then examine 1 bit in each of x and y. If one or the other bits
* are set then add G or H resp. If both bits are set, add GH.
*
* The example below is a precomputed table for W=2. The flattened table
* begins at (x_i,y_i) = (1,0), i.e. the identity element is omitted.
* The indices in each cell refer to the cell's location in m_table.
*
*  x->           0          1          2         3
*       0  |/ (ident) |0  x     |1  2x      |2  3x     |
*       1  |3    y    |4  x+y   |5  2x+y    |6  3x+y   |
*  y =  2  |7    2y   |8  x+2y  |9  2(x+y)  |10 3x+2y  |
*       3  |11   3y   |12 x+3y  |13 2x+3y   |14 3x+3y  |
*/
template <typename C, size_t W>
class WindowedMul2Table final {
   public:
      // We look at W bits of each scalar per iteration
      static_assert(W >= 1 && W <= 4);

      typedef typename C::Scalar Scalar;
      typedef typename C::AffinePoint AffinePoint;
      typedef typename C::ProjectivePoint ProjectivePoint;

      static constexpr size_t WindowBits = W;

      static constexpr size_t Windows = (Scalar::BITS + WindowBits - 1) / WindowBits;

      static constexpr size_t WindowSize = (1 << WindowBits);

      // 2^(2*W) elements, less the identity element
      static constexpr size_t TableSize = (1 << (2 * WindowBits)) - 1;

      WindowedMul2Table(const AffinePoint& x, const AffinePoint& y) {
         std::vector<ProjectivePoint> table;
         table.reserve(TableSize);

         for(size_t i = 0; i != TableSize; ++i) {
            const size_t t_i = (i + 1);
            const size_t x_i = t_i % WindowSize;
            const size_t y_i = (t_i >> WindowBits) % WindowSize;

            // Returns x_i * x + y_i * y
            auto next_tbl_e = [&]() {
               if(x_i % 2 == 0 && y_i % 2 == 0) {
                  // Where possible using doubling (eg indices 1, 7, 9 in
                  // the table above)
                  return table[(t_i / 2) - 1].dbl();
               } else if(x_i > 0 && y_i > 0) {
                  // A combination of x and y
                  return table[x_i - 1] + table[(y_i << WindowBits) - 1];
               } else if(x_i > 0 && y_i == 0) {
                  // A multiple of x without a y component
                  if(x_i == 1) {
                     // Just x
                     return ProjectivePoint::from_affine(x);
                  } else {
                     // x * x_{i-1}
                     return x + table[x_i - 1 - 1];
                  }
               } else if(x_i == 0 && y_i > 0) {
                  if(y_i == 1) {
                     // Just y
                     return ProjectivePoint::from_affine(y);
                  } else {
                     // y * y_{i-1}
                     return y + table[((y_i - 1) << WindowBits) - 1];
                  }
               } else {
                  BOTAN_ASSERT_UNREACHABLE();
               }
            };

            table.emplace_back(next_tbl_e());
         }

         m_table = ProjectivePoint::to_affine_batch(table);
      }

      /**
      * Variable time 2-ary multiplication
      *
      * A common use of 2-ary multiplication is when verifying the commitments
      * of an elliptic curve signature. Since in this case the inputs are all
      * public, there is no problem with variable time computation.
      *
      * It may be useful to offer a constant time (+blinded) variant of this in
      * the future for handling secret inputs, for example when computing
      * Pedersen commitments
      *
      * TODO for variable time computation we could make use of a wNAF
      * representation instead
      */
      ProjectivePoint mul2_vartime(const Scalar& s1, const Scalar& s2) const {
         const UnblindedScalarBits<C, W> bits1(s1);
         const UnblindedScalarBits<C, W> bits2(s2);

         auto accum = ProjectivePoint::identity();

         for(size_t i = 0; i != Windows; ++i) {
            if(i > 0) {
               accum = accum.dbl_n(WindowBits);
            }

            const size_t w_1 = bits1.get_window((Windows - i - 1) * WindowBits);
            const size_t w_2 = bits2.get_window((Windows - i - 1) * WindowBits);

            const size_t window = w_1 + (w_2 << WindowBits);

            if(window > 0) {
               accum += m_table[window - 1];
            }
         }

         return accum;
      }

   private:
      std::vector<AffinePoint> m_table;
};

template <typename C>
inline auto map_to_curve_sswu(const typename C::FieldElement& u) -> typename C::AffinePoint {
   u.ct_poison();
   const auto z_u2 = C::SSWU_Z * u.square();  // z * u^2
   const auto z2_u4 = z_u2.square();
   const auto tv1 = (z2_u4 + z_u2).invert();
   auto x1 = C::SSWU_C1() * (C::FieldElement::one() + tv1);
   x1.conditional_assign(tv1.is_zero(), C::SSWU_C2());
   const auto gx1 = C::AffinePoint::x3_ax_b(x1);

   const auto x2 = C::SSWU_Z * u.square() * x1;
   const auto gx2 = C::AffinePoint::x3_ax_b(x2);

   const auto gx1_is_square = gx1.is_square();

   auto x = x2;
   auto y = gx2.sqrt();

   x.conditional_assign(gx1_is_square, x1);
   y.conditional_assign(gx1_is_square, gx1.sqrt());

   const auto flip_y = y.is_even() != u.is_even();
   y.conditional_assign(flip_y, y.negate());

   auto pt = typename C::AffinePoint(x, y);

   pt.ct_unpoison();
   return pt;
}

template <typename C>
inline auto hash_to_curve_sswu(std::string_view hash,
                               bool random_oracle,
                               std::span<const uint8_t> pw,
                               std::span<const uint8_t> dst) -> typename C::ProjectivePoint {
   static_assert(C::ValidForSswuHash);

   const size_t SecurityLevel = (C::OrderBits + 1) / 2;
   const size_t L = (C::PrimeFieldBits + SecurityLevel + 7) / 8;

   const size_t Cnt = (random_oracle ? 2 : 1);

   std::vector<uint8_t> xmd(L * Cnt);
   expand_message_xmd(hash, xmd, pw, dst);

   if(Cnt == 1) {
      const auto u = C::FieldElement::from_wide_bytes(std::span<const uint8_t, L>(xmd));
      return C::ProjectivePoint::from_affine(map_to_curve_sswu<C>(u));
   } else {
      const auto u0 = C::FieldElement::from_wide_bytes(std::span<const uint8_t, L>(xmd.data(), L));
      const auto u1 = C::FieldElement::from_wide_bytes(std::span<const uint8_t, L>(xmd.data() + L, L));

      auto accum = C::ProjectivePoint::from_affine(map_to_curve_sswu<C>(u0));
      accum += map_to_curve_sswu<C>(u1);
      return accum;
   }
}

}  // namespace Botan

#endif
