/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PCURVES_IMPL_H_
#define BOTAN_PCURVES_IMPL_H_

#include <botan/rng.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/pcurves_util.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/xmd.h>
#include <vector>

namespace Botan {

template <WordType W, size_t N, std::array<W, N> P>
class MontgomeryInteger {
   private:
      static_assert(N > 0 && (P[0] & 1) == 1, "Invalid Montgomery modulus");
      // One can dream
      //static_assert(is_prime(P), "Montgomery Modulus must be a prime");

      static const constinit W P_dash = monty_inverse(P[0]);

      static const constexpr auto R1 = montygomery_r(P);
      static const constexpr auto R2 = mul_mod(R1, R1, P);
      static const constexpr auto R3 = mul_mod(R1, R2, P);

      static const constexpr auto P_MINUS_2 = p_minus<2>(P);
      static const constexpr auto P_PLUS_1_OVER_4 = p_plus_1_over_4(P);
      static const constexpr auto P_MINUS_1_OVER_2 = p_minus_1_over_2(P);

   public:
      static const constexpr size_t BITS = count_bits(P);
      static const constexpr size_t BYTES = (BITS + 7) / 8;

      static const constexpr W P_MOD_4 = P[0] % 4;

      typedef MontgomeryInteger<W, N, P> Self;

      // Default value is zero
      constexpr MontgomeryInteger() : m_val({}) {}

      MontgomeryInteger(const Self& other) = default;
      MontgomeryInteger(Self&& other) = default;
      MontgomeryInteger& operator=(const Self& other) = default;
      MontgomeryInteger& operator=(Self&& other) = default;

      // ??
      //~MontgomeryInteger() { secure_scrub_memory(m_val); }

      static constexpr Self zero() { return Self(std::array<W, N>{0}); }

      static constexpr Self one() { return Self(Self::R1); }

      static constexpr Self from_word(W x) {
         std::array<W, 1> v;
         v[0] = x;
         return Self(v) * R2;
      }

      constexpr bool is_zero() const { return CT::all_zeros(m_val.data(), m_val.size()).as_bool(); }

      constexpr bool is_nonzero() const { return !is_zero(); }

      constexpr bool is_one() const { return (*this == Self::one()); }

      constexpr bool is_even() const {
         auto v = bigint_monty_redc(m_val, P, P_dash);
         return (v[0] & 0x01) == 0;
      }

      friend constexpr Self operator+(const Self& a, const Self& b) {
         std::array<W, N> t;
         W carry = bigint_add3_nc(t.data(), a.data(), N, b.data(), N);

         std::array<W, N> r;
         bigint_monty_maybe_sub<N>(r.data(), carry, t.data(), P.data());
         return Self(r);
      }

      constexpr Self& operator+=(const Self& other) {
         std::array<W, N> t;
         W carry = bigint_add3_nc(t.data(), this->data(), N, other.data(), N);
         bigint_monty_maybe_sub<N>(m_val.data(), carry, t.data(), P.data());
         return (*this);
      }

      friend constexpr Self operator-(const Self& a, const Self& b) { return a + b.negate(); }

      friend constexpr Self operator*(uint8_t a, const Self& b) { return b * a; }

      friend constexpr Self operator*(const Self& a, uint8_t b) {
         // We assume b is a small constant and allow variable time
         // computation

         Self z = Self::zero();
         Self x = a;

         while(b > 0) {
            if(b & 1) {
               z = z + x;
            }
            x = x.dbl();
            b >>= 1;
         }

         return z;
      }

      friend constexpr Self operator*(const Self& a, const Self& b) {
         std::array<W, 2 * N> z;
         comba_mul<N>(z.data(), a.data(), b.data());
         return Self(bigint_monty_redc(z, P, P_dash));
      }

      constexpr Self& operator-=(const Self& other) {
         (*this) = (*this) - other;
         return (*this);
      }

      constexpr Self& operator*=(const Self& other) {
         (*this) = (*this) * other;
         return (*this);
      }

      constexpr void conditional_add(bool cond, const Self& other) { conditional_assign(cond, *this + other); }

      constexpr void conditional_mul(bool cond, const Self& other) { conditional_assign(cond, *this * other); }

      constexpr void conditional_sub(bool cond, const Self& other) { conditional_add(cond, other.negate()); }

      // if cond is true, assigns other to *this
      constexpr void conditional_assign(bool cond, const Self& other) {
         CT::conditional_assign_mem(static_cast<W>(cond), m_val.data(), other.data(), N);
      }

      // TODO be faster
      constexpr Self dbl() const { return (*this) + (*this); }

      constexpr Self square() const {
         std::array<W, 2 * N> z;
         comba_sqr<N>(z.data(), this->data());
         return bigint_monty_redc(z, P, P_dash);
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
         auto x = (*this);
         auto y = Self::one();

         for(size_t i = 0; i != Self::BITS; ++i) {
            if(get_bit(i, exp)) {
               y = y * x;
            }
            x = x.square();
         }

         return y;
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
      constexpr Self sqrt() const {
         static_assert(Self::P_MOD_4 == 3);
         auto z = pow_vartime(Self::P_PLUS_1_OVER_4);
         const bool correct = (z * z) == *this;
         z.conditional_assign(!correct, Self::zero());
         return z;
      }

      constexpr bool is_square() const {
         static_assert(Self::P_MOD_4 == 3);
         auto z = pow_vartime(Self::P_MINUS_1_OVER_2);
         const bool is_one = z.is_one();
         const bool is_zero = z.is_zero();
         return (is_one || is_zero);
      }

      constexpr bool operator==(const Self& other) const {
         return CT::is_equal(this->data(), other.data(), N).as_bool();
      }

      constexpr bool operator!=(const Self& other) const {
         return CT::is_not_equal(this->data(), other.data(), N).as_bool();
      }

      constexpr std::array<uint8_t, Self::BYTES> serialize() const {
         auto v = bigint_monty_redc(m_val, P, P_dash);
         std::reverse(v.begin(), v.end());
         auto bytes = store_be(v);

         if constexpr(Self::BYTES == N * WordInfo<W>::bytes) {
            return bytes;
         } else {
            // Remove leading zero bytes
            const size_t extra = N * WordInfo<W>::bytes - Self::BYTES;
            std::array<uint8_t, Self::BYTES> out;
            copy_mem(out.data(), &bytes[extra], Self::BYTES);
            return out;
         }
      }

      // Returns nullopt if the input is an encoding greater than or equal P
      constexpr static std::optional<Self> deserialize(std::span<const uint8_t> bytes) {
         // We could allow either short inputs or longer zero padded
         // inputs here, however it seems best to avoid non-canonical
         // representations unless required
         if(bytes.size() != Self::BYTES) {
            return {};
         }

         const auto words = bytes_to_words<W, N, BYTES>(&bytes[0]);

         if(!bigint_ct_is_lt(words.data(), N, P.data(), N).as_bool()) {
            return {};
         }

         return Self(words) * Self::R2;
      }

      // Reduces large input modulo the order
      template <size_t L>
      static constexpr Self from_wide_bytes(std::span<const uint8_t, L> bytes) {
         static_assert(8 * L <= 2 * Self::BITS);

         std::array<uint8_t, 2 * BYTES> padded_bytes = {};
         copy_mem(padded_bytes.data() + 2 * BYTES - L, bytes.data(), L);

         if constexpr(Self::BITS == 521) {
            // This could be improved!
            const auto radix = Self::from_word(256);

            auto accum = Self::zero();

            for(size_t i = 0; i != L; ++i) {
               accum *= radix;
               accum += Self::from_word(bytes[i]);
            }
            return accum;
         } else {
            static_assert(8 * Self::BYTES == Self::BITS);

            const std::array<W, N> hi = bytes_to_words<W, N, BYTES>(&padded_bytes[0]);
            const std::array<W, N> lo = bytes_to_words<W, N, BYTES>(&padded_bytes[BYTES]);
            return Self(hi) * R3 + Self(lo) * R2;
         }
      }

      static constexpr Self random(RandomNumberGenerator& rng) {
         std::array<uint8_t, Self::BYTES> buf;
         for(;;) {
            rng.randomize(buf.data(), buf.size());
            if(auto v = Self::deserialize(buf)) {
               return v;
            }
         }
      }

      template <size_t L>
      static consteval Self constant(StringLiteral<L> S) {
         return Self::constant(S.value);
      }

      template <size_t L>
      static consteval Self constant(const char (&s)[L]) {
         const auto v = hex_to_words<W>(s);
         return Self(v) * R2;
      }

      static consteval Self constant(int8_t x) {
         std::array<W, 1> v;
         v[0] = (x >= 0) ? x : -x;
         auto s = Self(v) * R2;
         return (x >= 0) ? s : s.negate();
      }

   private:
      constexpr const std::array<W, N>& value() const { return m_val; }

      constexpr const W* data() const { return m_val.data(); }

      template <size_t S>
      constexpr MontgomeryInteger(std::array<W, S> w) : m_val({}) {
         static_assert(S <= N);
         for(size_t i = 0; i != S; ++i) {
            m_val[i] = w[i];
         }
      }

      std::array<W, N> m_val;
};

template <typename FieldElement>
class AffineCurvePoint {
   public:
      static const constinit size_t BYTES = 1 + 2 * FieldElement::BYTES;
      static const constinit size_t COMPRESSED_BYTES = 1 + FieldElement::BYTES;

      typedef AffineCurvePoint<FieldElement> Self;

      constexpr AffineCurvePoint(const FieldElement& x, const FieldElement& y) : m_x(x), m_y(y) {}

      constexpr AffineCurvePoint() : m_x(FieldElement::zero()), m_y(FieldElement::zero()) {}

      static constexpr Self identity() { return Self(FieldElement::zero(), FieldElement::zero()); }

      constexpr bool is_identity() const { return m_x.is_zero() && m_y.is_zero(); }

      AffineCurvePoint(const Self& other) = default;
      AffineCurvePoint(Self&& other) = default;
      AffineCurvePoint& operator=(const Self& other) = default;
      AffineCurvePoint& operator=(Self&& other) = default;

      constexpr Self negate() const { return Self(m_x, m_y.negate()); }

      std::vector<uint8_t> serialize_to_vec() const {
         const auto b = this->serialize();
         return std::vector(b.begin(), b.end());
      }

      constexpr std::array<uint8_t, Self::BYTES> serialize() const {
         std::array<uint8_t, Self::BYTES> r = {};
         BufferStuffer pack(r);
         pack.append(0x04);
         pack.append(m_x.serialize());
         pack.append(m_y.serialize());
         return r;
      }

      constexpr std::array<uint8_t, Self::COMPRESSED_BYTES> serialize_compressed() const {
         std::array<uint8_t, Self::COMPRESSED_BYTES> r = {};
         const bool y_is_even = y().is_even();
         BufferStuffer pack(r);
         pack.append(y_is_even ? 0x02 : 0x03);
         pack.append(x().serialize());
         return r;
      }

      //static constexpr std::optional<Self> deserialize(std::span<const uint8_t> bytes) {}

      constexpr const FieldElement& x() const { return m_x; }

      constexpr const FieldElement& y() const { return m_y; }

   private:
      FieldElement m_x;
      FieldElement m_y;
};

template <typename FieldElement, StringLiteral AS>
class ProjectiveCurvePoint {
   public:
      // We can't pass a FieldElement directly because FieldElement is
      // not "structural" due to having private members, so instead
      // recreate it here from the string.
      static const constexpr FieldElement A = FieldElement::constant(AS);

      static const constinit bool A_is_minus_3 = (A == FieldElement::constant(-3));
      static const constinit bool A_is_zero = (A == FieldElement::zero());

      typedef ProjectiveCurvePoint<FieldElement, AS> Self;
      typedef AffineCurvePoint<FieldElement> AffinePoint;

      static constexpr Self from_affine(const AffinePoint& pt) { return ProjectiveCurvePoint(pt.x(), pt.y()); }

      static constexpr Self identity() {
         return Self(FieldElement::zero(), FieldElement::zero(), FieldElement::zero());
      }

      constexpr ProjectiveCurvePoint() :
            m_x(FieldElement::zero()), m_y(FieldElement::zero()), m_z(FieldElement::zero()) {}

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

      constexpr bool is_identity() const { return z().is_zero(); }

      template <typename Pt>
      constexpr void conditional_add(bool cond, const Pt& pt) {
         conditional_assign(cond, *this + pt);
      }

      void conditional_assign(bool cond, const Self& pt) {
         m_x.conditional_assign(cond, pt.x());
         m_y.conditional_assign(cond, pt.y());
         m_z.conditional_assign(cond, pt.z());
      }

      constexpr static Self add_mixed(const Self& a, const AffinePoint& b) {
         // TODO avoid these early returns by masking instead
         if(a.is_identity()) {
            return Self::from_affine(b);
         }

         if(b.is_identity()) {
            return a;
         }

         /*
         https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2

         TODO rename these vars

         TODO reduce vars

         TODO use a complete addition formula??? (YES)
         https://eprint.iacr.org/2015/1060.pdf
         */

         const auto Z1Z1 = a.z().square();
         const auto U2 = b.x() * Z1Z1;
         const auto S2 = b.y() * a.z() * Z1Z1;
         const auto H = U2 - a.x();
         const auto r = S2 - a.y();

         if(H.is_zero()) {
            if(r.is_zero()) {
               return a.dbl();
            } else {
               return Self::identity();
            }
         }

         const auto HH = H.square();
         const auto HHH = H * HH;
         const auto V = a.x() * HH;
         const auto t2 = r.square();
         const auto t3 = V + V;
         const auto t4 = t2 - HHH;
         const auto X3 = t4 - t3;
         const auto t5 = V - X3;
         const auto t6 = a.y() * HHH;
         const auto t7 = r * t5;
         const auto Y3 = t7 - t6;
         const auto Z3 = a.z() * H;

         return Self(X3, Y3, Z3);
      }

      constexpr static Self add(const Self& a, const Self& b) {
         // TODO avoid these early returns by masking instead
         if(a.is_identity()) {
            return b;
         }

         if(b.is_identity()) {
            return a;
         }

         /*
         https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2

         TODO rename these vars

         TODO reduce vars

         TODO use a complete addition formula??? (YES)
         https://eprint.iacr.org/2015/1060.pdf
         */

         const auto Z1Z1 = a.z().square();
         const auto Z2Z2 = b.z().square();
         const auto U1 = a.x() * Z2Z2;
         const auto U2 = b.x() * Z1Z1;
         const auto S1 = a.y() * b.z() * Z2Z2;
         const auto S2 = b.y() * a.z() * Z1Z1;
         const auto H = U2 - U1;
         const auto r = S2 - S1;

         if(H.is_zero()) {
            if(r.is_zero()) {
               return a.dbl();
            } else {
               return Self::identity();
            }
         }

         const auto HH = H.square();
         const auto HHH = H * HH;
         const auto V = U1 * HH;
         const auto t2 = r.square();
         const auto t3 = V + V;
         const auto t4 = t2 - HHH;
         const auto X3 = t4 - t3;
         const auto t5 = V - X3;
         const auto t6 = S1 * HHH;
         const auto t7 = r * t5;
         const auto Y3 = t7 - t6;
         const auto t8 = b.z() * H;
         const auto Z3 = a.z() * t8;

         return Self(X3, Y3, Z3);
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
            m = 3 * (x() - z2) * (x() + z2);
         } else if constexpr(Self::A_is_zero) {
            // If a == 0 then 3*x^2 + a*z^4 == 3*x^2
            // Cost: 1S + 1*3
            m = 3 * x().square();
         } else {
            // Cost: 1M + 3S + 1A + 1*3
            const auto z2 = z().square();
            m = 3 * x().square() + A * z2.square();
         }

         const auto y2 = y().square();
         const auto s = 4 * x() * y2;
         const auto nx = m.square() - 2 * s;
         const auto ny = m * (s - nx) - 8 * y2.square();
         const auto nz = 2 * y() * z();

         return Self(nx, ny, nz);
      }

      constexpr Self negate() const { return Self(m_x, m_y.negate(), m_z); }

      constexpr AffinePoint to_affine() const {
         // Not strictly required right? - default should work as long
         // as (0,0) is identity and invert returns 0 on 0
         if(this->is_identity()) {
            return AffinePoint::identity();
         }

         // Maybe also worth skipping ...
         if(m_z.is_one()) {
            return AffinePoint(m_x, m_y);
         }

         const auto z_inv = m_z.invert();
         const auto z2_inv = z_inv.square();
         const auto z3_inv = z_inv * z2_inv;

         const auto x = m_x * z2_inv;
         const auto y = m_y * z3_inv;
         return AffinePoint(x, y);
      }

      template <size_t N>
      static constexpr auto to_affine_batch(const std::array<Self, N>& projective) -> std::array<AffinePoint, N> {
         std::array<AffinePoint, N> affine;

         bool any_identity = false;
         for(size_t i = 0; i != N; ++i) {
            if(projective[i].is_identity()) {
               any_identity = true;
            }
         }

         if(N <= 2 || any_identity) {
            for(size_t i = 0; i != N; ++i) {
               affine[i] = projective[i].to_affine();
            }
         } else {
            std::array<FieldElement, N> c;

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

      constexpr const FieldElement& x() const { return m_x; }

      constexpr const FieldElement& y() const { return m_y; }

      constexpr const FieldElement& z() const { return m_z; }

   private:
      FieldElement m_x;
      FieldElement m_y;
      FieldElement m_z;
};

template <typename AffinePoint, typename ProjectivePoint, typename Scalar>
class PrecomputedMulTable {
   public:
      //static const constinit WINDOW_BITS = 1; // TODO allow config?

      //static_assert(WINDOW_BITS >= 1 && WINDOW_BITS <= 8);

      static const constinit size_t TABLE_SIZE = Scalar::BITS;

      constexpr PrecomputedMulTable(const AffinePoint& p) : m_table{} {
         std::array<ProjectivePoint, TABLE_SIZE> table;

         table[0] = ProjectivePoint::from_affine(p);
         for(size_t i = 1; i != TABLE_SIZE; ++i) {
            table[i] = table[i - 1].dbl();
         }

         m_table = ProjectivePoint::to_affine_batch(table);
      }

      constexpr ProjectivePoint operator()(const Scalar& s) const {
         const auto bits = s.serialize();

         auto accum = ProjectivePoint::identity();

         for(size_t i = 0; i != Scalar::BITS; ++i) {
            const size_t b = 8 * Scalar::BYTES - i - 1;
            const bool b_set = (bits[b / 8] >> (7 - b % 8)) & 1;
            accum.conditional_add(b_set, m_table[i]);
         }

         return accum;
      }

   private:
      std::array<AffinePoint, TABLE_SIZE> m_table;
};

template <StringLiteral PS,
          StringLiteral AS,
          StringLiteral BS,
          StringLiteral NS,
          StringLiteral GXS,
          StringLiteral GYS,
          int8_t Z = 0,
          template <WordType W, size_t N, std::array<W, N> P> typename FieldType = MontgomeryInteger>
class EllipticCurve {
   public:
      typedef word W;

      static const constexpr auto PW = hex_to_words<W>(PS.value);
      static const constexpr auto NW = hex_to_words<W>(NS.value);

      // Simplifying assumption
      static_assert(PW.size() == NW.size());

      typedef MontgomeryInteger<W, NW.size(), NW> Scalar;
      typedef FieldType<W, PW.size(), PW> FieldElement;

      static const constinit size_t OrderBits = Scalar::BITS;
      static const constinit size_t PrimeFieldBits = FieldElement::BITS;

      static const constexpr FieldElement A = FieldElement::constant(AS);
      static const constexpr FieldElement B = FieldElement::constant(BS);
      static const constexpr FieldElement Gx = FieldElement::constant(GXS);
      static const constexpr FieldElement Gy = FieldElement::constant(GYS);

      static const constexpr FieldElement SSWU_Z = FieldElement::constant(Z);

      static const constinit bool ValidForSswuHash =
         (SSWU_Z.is_nonzero() && A.is_nonzero() && B.is_nonzero() && FieldElement::P_MOD_4 == 3);

      typedef AffineCurvePoint<FieldElement> AffinePoint;
      typedef ProjectiveCurvePoint<FieldElement, AS> ProjectivePoint;

      static const constexpr AffinePoint G = AffinePoint(Gx, Gy);

      typedef PrecomputedMulTable<AffinePoint, ProjectivePoint, Scalar> MulTable;

      static const MulTable& MulByGTable() {
         static const auto MulG = MulTable(G);
         return MulG;
      }

      static const ProjectivePoint MulByG(const Scalar& scalar) { return MulByGTable()(scalar); }

      // (-B / A), will be zero if A == 0 or B == 0 or Z == 0
      static const FieldElement& SSWU_C1() {
         // We derive it from C2 to avoid a second inversion
         static const auto C1 = (SSWU_C2() * SSWU_Z).negate();
         return C1;
      }

      // (B / (Z * A)), will be zero if A == 0 or B == 0 or Z == 0
      static const FieldElement& SSWU_C2() {
         // This could use a variable time inversion
         static const auto C2 = (B * (SSWU_Z * A).invert());
         return C2;
      }
};

template <typename C>
inline auto map_to_curve_sswu(const typename C::FieldElement& u) -> typename C::AffinePoint {
   const auto z_u2 = C::SSWU_Z * u.square();  // z * u^2
   const auto z2_u4 = z_u2.square();
   const auto tv1 = (z2_u4 + z_u2).invert();
   auto x1 = C::SSWU_C1() * (C::FieldElement::one() + tv1);
   x1.conditional_assign(tv1.is_zero(), C::SSWU_C2());
   const auto gx1 = (x1.square() + C::A) * x1 + C::B;

   const auto x2 = C::SSWU_Z * u.square() * x1;
   const auto gx2 = (x2.square() + C::A) * x2 + C::B;

   const auto gx1_is_square = gx1.is_square();

   auto x = x2;
   auto y = gx2.sqrt();

   x.conditional_assign(gx1_is_square, x1);
   y.conditional_assign(gx1_is_square, gx1.sqrt());

   const bool flip_y = y.is_even() != u.is_even();
   y.conditional_assign(flip_y, y.negate());

   return typename C::AffinePoint(x, y);
}

template <typename C>
inline std::vector<uint8_t> hash_to_curve_sswu(std::string_view hash,
                                               bool random_oracle,
                                               std::span<const uint8_t> pw,
                                               std::span<const uint8_t> dst) {
   static_assert(C::ValidForSswuHash);

   const size_t SecurityLevel = (C::OrderBits + 1) / 2;
   const size_t L = (C::PrimeFieldBits + SecurityLevel + 7) / 8;

   const size_t Cnt = (random_oracle ? 2 : 1);

   std::vector<uint8_t> xmd(L * Cnt);
   expand_message_xmd(hash, xmd, pw, dst);

   auto pt = C::ProjectivePoint::identity();

   for(size_t i = 0; i != Cnt; ++i) {
      const auto u = C::FieldElement::from_wide_bytes(std::span<const uint8_t, L>(xmd.data() + i * L, L));
      pt += map_to_curve_sswu<C>(u);
   }

   return pt.to_affine().serialize_to_vec();
}

}  // namespace Botan

#endif
