/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pcurves_generic.h>

#include <botan/bigint.h>
#include <botan/exceptn.h>
#include <botan/rng.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/pcurves_instance.h>
#include <botan/internal/primality.h>
#include <algorithm>

namespace Botan::PCurve {

namespace {

template <size_t N>
constexpr std::optional<std::array<word, N>> bytes_to_words(std::span<const uint8_t> bytes) {
   if(bytes.size() > WordInfo<word>::bytes * N) {
      return std::nullopt;
   }

   std::array<word, N> r = {};

   const size_t full_words = bytes.size() / WordInfo<word>::bytes;
   const size_t extra_bytes = bytes.size() % WordInfo<word>::bytes;

   for(size_t i = 0; i != full_words; ++i) {
      r[i] = load_be<word>(bytes.data(), full_words - 1 - i);
   }

   if(extra_bytes > 0) {
      const size_t shift = extra_bytes * 8;
      bigint_shl1(r.data(), r.size(), r.size(), shift);

      for(size_t i = 0; i != extra_bytes; ++i) {
         const word b0 = bytes[WordInfo<word>::bytes * full_words + i];
         r[0] |= (b0 << (8 * (extra_bytes - 1 - i)));
      }
   }

   return r;
}

template <typename T>
T impl_pow_vartime(const T& elem, const T& one, size_t bits, std::span<const word> exp) {
   constexpr size_t WindowBits = 4;
   constexpr size_t WindowElements = (1 << WindowBits) - 1;

   const size_t Windows = (bits + WindowBits - 1) / WindowBits;

   std::vector<T> tbl;
   tbl.reserve(WindowElements);

   tbl.push_back(elem);

   for(size_t i = 1; i != WindowElements; ++i) {
      if(i % 2 == 1) {
         tbl.push_back(tbl[i / 2].square());
      } else {
         tbl.push_back(tbl[i - 1] * tbl[0]);
      }
   }

   auto r = one;

   const size_t w0 = read_window_bits<WindowBits>(exp, (Windows - 1) * WindowBits);

   if(w0 > 0) {
      r = tbl[w0 - 1];
   }

   for(size_t i = 1; i != Windows; ++i) {
      for(size_t j = 0; j != WindowBits; ++j) {
         r = r.square();
      }
      const size_t w = read_window_bits<WindowBits>(exp, (Windows - i - 1) * WindowBits);

      if(w > 0) {
         r *= tbl[w - 1];
      }
   }

   return r;
}

}  // namespace

class GenericCurveParams final {
   public:
      typedef PrimeOrderCurve::StorageUnit StorageUnit;
      static constexpr size_t N = PrimeOrderCurve::StorageWords;

      GenericCurveParams(const BigInt& p,
                         const BigInt& a,
                         const BigInt& b,
                         const BigInt& base_x,
                         const BigInt& base_y,
                         const BigInt& order) :
            m_words(p.sig_words()),
            m_order_bits(order.bits()),
            m_order_bytes(order.bytes()),
            m_field_bits(p.bits()),
            m_field_bytes(p.bytes()),
            m_monty_order(order),
            m_monty_field(p),
            m_field(bn_to_fixed(p)),
            m_field_minus_2(bn_to_fixed_rev(p - 2)),
            m_field_monty_r1(bn_to_fixed(m_monty_field.R1())),
            m_field_monty_r2(bn_to_fixed(m_monty_field.R2())),
            m_field_p_plus_1_over_4(bn_to_fixed_rev((p + 1) / 4)),
            m_field_p_over_2_plus_1(bn_to_fixed((p / 2) + 1)),
            m_field_p_dash(m_monty_field.p_dash()),

            m_order(bn_to_fixed(order)),
            m_order_minus_2(bn_to_fixed_rev(order - 2)),
            m_order_monty_r1(bn_to_fixed(m_monty_order.R1())),
            m_order_monty_r2(bn_to_fixed(m_monty_order.R2())),
            m_order_monty_r3(bn_to_fixed(m_monty_order.R3())),
            m_order_p_dash(m_monty_order.p_dash()),

            m_a_is_minus_3(a + 3 == p),
            m_a_is_zero(a.is_zero()),
            m_order_is_lt_field(order < p) {
         secure_vector<word> ws;
         m_monty_curve_a = bn_to_fixed(m_monty_field.mul(a, m_monty_field.R2(), ws));
         m_monty_curve_b = bn_to_fixed(m_monty_field.mul(b, m_monty_field.R2(), ws));

         m_base_x = bn_to_fixed(m_monty_field.mul(base_x, m_monty_field.R2(), ws));
         m_base_y = bn_to_fixed(m_monty_field.mul(base_y, m_monty_field.R2(), ws));
      }

      size_t words() const { return m_words; }

      size_t order_bits() const { return m_order_bits; }

      size_t order_bytes() const { return m_order_bytes; }

      size_t field_bits() const { return m_field_bits; }

      size_t field_bytes() const { return m_field_bytes; }

      const Montgomery_Params& monty_order() const { return m_monty_order; }

      const Montgomery_Params& monty_field() const { return m_monty_field; }

      const StorageUnit& field() const { return m_field; }

      const StorageUnit& field_minus_2() const { return m_field_minus_2; }

      const StorageUnit& field_monty_r1() const { return m_field_monty_r1; }

      const StorageUnit& field_monty_r2() const { return m_field_monty_r2; }

      const StorageUnit& field_p_plus_1_over_4() const { return m_field_p_plus_1_over_4; }

      const StorageUnit& field_p_over_2_plus_1() const { return m_field_p_over_2_plus_1; }

      word field_p_dash() const { return m_field_p_dash; }

      const StorageUnit& order() const { return m_order; }

      const StorageUnit& order_minus_2() const { return m_order_minus_2; }

      const StorageUnit& order_monty_r1() const { return m_order_monty_r1; }

      const StorageUnit& order_monty_r2() const { return m_order_monty_r2; }

      const StorageUnit& order_monty_r3() const { return m_order_monty_r3; }

      word order_p_dash() const { return m_order_p_dash; }

      const StorageUnit& monty_curve_a() const { return m_monty_curve_a; }

      const StorageUnit& monty_curve_b() const { return m_monty_curve_b; }

      const StorageUnit& base_x() const { return m_base_x; }

      const StorageUnit& base_y() const { return m_base_y; }

      bool a_is_minus_3() const { return m_a_is_minus_3; }

      bool a_is_zero() const { return m_a_is_zero; }

      bool order_is_less_than_field() const { return m_order_is_lt_field; }

      void mul(std::array<word, 2 * N>& z, const std::array<word, N>& x, const std::array<word, N>& y) const {
         clear_mem(z);

         if(m_words == 4) {
            bigint_comba_mul4(z.data(), x.data(), y.data());
         } else if(m_words == 6) {
            bigint_comba_mul6(z.data(), x.data(), y.data());
         } else if(m_words == 8) {
            bigint_comba_mul8(z.data(), x.data(), y.data());
         } else if(m_words == 9) {
            bigint_comba_mul9(z.data(), x.data(), y.data());
         } else {
            bigint_mul(z.data(), z.size(), x.data(), m_words, m_words, y.data(), m_words, m_words, nullptr, 0);
         }
      }

      void sqr(std::array<word, 2 * N>& z, const std::array<word, N>& x) const {
         clear_mem(z);

         if(m_words == 4) {
            bigint_comba_sqr4(z.data(), x.data());
         } else if(m_words == 6) {
            bigint_comba_sqr6(z.data(), x.data());
         } else if(m_words == 8) {
            bigint_comba_sqr8(z.data(), x.data());
         } else if(m_words == 9) {
            bigint_comba_sqr9(z.data(), x.data());
         } else {
            bigint_sqr(z.data(), z.size(), x.data(), m_words, m_words, nullptr, 0);
         }
      }

   private:
      static std::array<word, PrimeOrderCurve::StorageWords> bn_to_fixed(const BigInt& n) {
         const size_t n_words = n.sig_words();
         BOTAN_ASSERT_NOMSG(n_words <= PrimeOrderCurve::StorageWords);

         std::array<word, PrimeOrderCurve::StorageWords> r = {};
         copy_mem(std::span{r}.first(n_words), n._as_span().first(n_words));
         return r;
      }

      static std::array<word, PrimeOrderCurve::StorageWords> bn_to_fixed_rev(const BigInt& n) {
         auto v = bn_to_fixed(n);
         std::reverse(v.begin(), v.end());
         return v;
      }

   private:
      size_t m_words;
      size_t m_order_bits;
      size_t m_order_bytes;
      size_t m_field_bits;
      size_t m_field_bytes;

      Montgomery_Params m_monty_order;
      Montgomery_Params m_monty_field;

      StorageUnit m_field;
      StorageUnit m_field_minus_2;
      StorageUnit m_field_monty_r1;
      StorageUnit m_field_monty_r2;
      StorageUnit m_field_p_plus_1_over_4;
      StorageUnit m_field_p_over_2_plus_1;
      word m_field_p_dash;

      StorageUnit m_order;
      StorageUnit m_order_minus_2;
      StorageUnit m_order_monty_r1;
      StorageUnit m_order_monty_r2;
      StorageUnit m_order_monty_r3;
      word m_order_p_dash;

      StorageUnit m_monty_curve_a;
      StorageUnit m_monty_curve_b;

      StorageUnit m_base_x;
      StorageUnit m_base_y;

      bool m_a_is_minus_3;
      bool m_a_is_zero;
      bool m_order_is_lt_field;
};

class GenericScalar final {
   public:
      typedef word W;
      typedef PrimeOrderCurve::StorageUnit StorageUnit;
      static constexpr size_t N = PrimeOrderCurve::StorageWords;

      static std::optional<GenericScalar> from_wide_bytes(const GenericPrimeOrderCurve* curve,
                                                          std::span<const uint8_t> bytes) {
         const size_t mlen = curve->_params().order_bytes();

         if(bytes.size() > 2 * mlen) {
            return {};
         }

         std::array<uint8_t, 2 * sizeof(word) * N> padded_bytes = {};
         copy_mem(std::span{padded_bytes}.last(bytes.size()), bytes);

         auto words = bytes_to_words<2 * N>(std::span{padded_bytes});
         if(words) {
            auto in_rep = wide_to_rep(curve, words.value());
            return GenericScalar(curve, in_rep);
         } else {
            return {};
         }
      }

      static std::optional<GenericScalar> deserialize(const GenericPrimeOrderCurve* curve,
                                                      std::span<const uint8_t> bytes) {
         const size_t len = curve->_params().order_bytes();

         if(bytes.size() != len) {
            return {};
         }

         const auto words = bytes_to_words<N>(bytes);

         if(words) {
            if(!bigint_ct_is_lt(words->data(), N, curve->_params().order().data(), N).as_bool()) {
               return {};
            }

            // Safe because we checked above that words is an integer < P
            return GenericScalar(curve, to_rep(curve, *words));
         } else {
            return {};
         }
      }

      static GenericScalar zero(const GenericPrimeOrderCurve* curve) {
         StorageUnit zeros = {};
         return GenericScalar(curve, zeros);
      }

      static GenericScalar one(const GenericPrimeOrderCurve* curve) {
         return GenericScalar(curve, curve->_params().order_monty_r1());
      }

      static GenericScalar random(const GenericPrimeOrderCurve* curve, RandomNumberGenerator& rng) {
         constexpr size_t MAX_ATTEMPTS = 1000;

         const size_t bits = curve->_params().order_bits();

         std::vector<uint8_t> buf(curve->_params().order_bytes());

         for(size_t i = 0; i != MAX_ATTEMPTS; ++i) {
            rng.randomize(buf);

            // Zero off high bits that if set would certainly cause us
            // to be out of range
            if(bits % 8 != 0) {
               const uint8_t mask = 0xFF >> (8 - (bits % 8));
               buf[0] &= mask;
            }

            if(auto s = GenericScalar::deserialize(curve, buf)) {
               if(s.value().is_nonzero().as_bool()) {
                  return s.value();
               }
            }
         }

         throw Internal_Error("Failed to generate random Scalar within bounded number of attempts");
      }

      friend GenericScalar operator+(const GenericScalar& a, const GenericScalar& b) {
         auto curve = check_curve(a, b);
         const size_t words = curve->_params().words();

         StorageUnit t = {};
         W carry = bigint_add3_nc(t.data(), a.data(), words, b.data(), words);

         StorageUnit r = {};
         bigint_monty_maybe_sub(words, r.data(), carry, t.data(), curve->_params().order().data());
         return GenericScalar(curve, r);
      }

      friend GenericScalar operator-(const GenericScalar& a, const GenericScalar& b) { return a + b.negate(); }

      friend GenericScalar operator*(const GenericScalar& a, const GenericScalar& b) {
         auto curve = check_curve(a, b);

         std::array<W, 2 * N> z;
         curve->_params().mul(z, a.value(), b.value());
         return GenericScalar(curve, redc(curve, z));
      }

      GenericScalar& operator*=(const GenericScalar& other) {
         auto curve = check_curve(*this, other);

         std::array<W, 2 * N> z;
         curve->_params().mul(z, value(), other.value());
         m_val = redc(curve, z);
         return (*this);
      }

      GenericScalar square() const {
         auto curve = this->m_curve;

         std::array<W, 2 * N> z;
         curve->_params().sqr(z, value());
         return GenericScalar(curve, redc(curve, z));
      }

      GenericScalar pow_vartime(const StorageUnit& exp) const {
         auto one = GenericScalar::one(curve());
         auto bits = curve()->_params().order_bits();
         auto words = curve()->_params().words();
         return impl_pow_vartime(*this, one, bits, std::span{exp}.last(words));
      }

      GenericScalar negate() const {
         auto x_is_zero = CT::all_zeros(this->data(), N);

         StorageUnit r;
         bigint_sub3(r.data(), m_curve->_params().order().data(), N, this->data(), N);
         x_is_zero.if_set_zero_out(r.data(), N);
         return GenericScalar(m_curve, r);
      }

      GenericScalar invert() const { return pow_vartime(m_curve->_params().order_minus_2()); }

      // TODO remove this
      std::vector<uint8_t> serialize() const {
         std::vector<uint8_t> bytes(m_curve->_params().order_bytes());
         this->serialize_to(bytes);
         return bytes;
      }

      void serialize_to(std::span<uint8_t> bytes) const {
         auto v = from_rep(m_curve, m_val);
         std::reverse(v.begin(), v.end());

         const size_t flen = m_curve->_params().order_bytes();
         BOTAN_ARG_CHECK(bytes.size() == flen, "Expected output span provided");

         // Remove leading zero bytes
         const auto padded_bytes = store_be(v);
         const size_t extra = N * WordInfo<W>::bytes - flen;
         copy_mem(bytes, std::span{padded_bytes}.subspan(extra, flen));
      }

      CT::Choice is_zero() const { return CT::all_zeros(m_val.data(), m_curve->_params().words()).as_choice(); }

      CT::Choice is_nonzero() const { return !is_zero(); }

      CT::Choice operator==(const GenericScalar& other) const {
         if(this->m_curve != other.m_curve) {
            return CT::Choice::no();
         }

         return CT::is_equal(m_val.data(), other.m_val.data(), m_curve->_params().words()).as_choice();
      }

      /**
      * Convert the integer to standard representation and return the sequence of words
      */
      StorageUnit to_words() const { return from_rep(m_curve, m_val); }

      const StorageUnit& stash_value() const { return m_val; }

      const GenericPrimeOrderCurve* curve() const { return m_curve; }

      GenericScalar(const GenericPrimeOrderCurve* curve, StorageUnit val) : m_curve(curve), m_val(val) {}

   private:
      const StorageUnit& value() const { return m_val; }

      const W* data() const { return m_val.data(); }

      static const GenericPrimeOrderCurve* check_curve(const GenericScalar& a, const GenericScalar& b) {
         BOTAN_STATE_CHECK(a.m_curve == b.m_curve);
         return a.m_curve;
      }

      static StorageUnit redc(const GenericPrimeOrderCurve* curve, std::array<W, 2 * N> z) {
         const auto& mod = curve->_params().order();
         const size_t words = curve->_params().words();
         StorageUnit r = {};
         StorageUnit ws = {};
         bigint_monty_redc(r.data(), z.data(), mod.data(), words, curve->_params().order_p_dash(), ws.data(), ws.size());
         return r;
      }

      static StorageUnit from_rep(const GenericPrimeOrderCurve* curve, StorageUnit z) {
         std::array<W, 2 * N> ze = {};
         copy_mem(std::span{ze}.template first<N>(), z);
         return redc(curve, ze);
      }

      static StorageUnit to_rep(const GenericPrimeOrderCurve* curve, StorageUnit x) {
         std::array<W, 2 * N> z;
         curve->_params().mul(z, x, curve->_params().order_monty_r2());
         return redc(curve, z);
      }

      static StorageUnit wide_to_rep(const GenericPrimeOrderCurve* curve, std::array<W, 2 * N> x) {
         auto redc_x = redc(curve, x);
         std::array<W, 2 * N> z;
         curve->_params().mul(z, redc_x, curve->_params().order_monty_r3());
         return redc(curve, z);
      }

      const GenericPrimeOrderCurve* m_curve;
      StorageUnit m_val;
};

class GenericField final {
   public:
      typedef word W;
      typedef PrimeOrderCurve::StorageUnit StorageUnit;
      static constexpr size_t N = PrimeOrderCurve::StorageWords;

      static std::optional<GenericField> deserialize(const GenericPrimeOrderCurve* curve,
                                                     std::span<const uint8_t> bytes) {
         const size_t len = curve->_params().field_bytes();

         if(bytes.size() != len) {
            return {};
         }

         const auto words = bytes_to_words<N>(bytes);

         if(words) {
            if(!bigint_ct_is_lt(words->data(), N, curve->_params().field().data(), N).as_bool()) {
               return {};
            }

            // Safe because we checked above that words is an integer < P
            return GenericField::from_words(curve, *words);
         } else {
            return {};
         }
      }

      static GenericField from_words(const GenericPrimeOrderCurve* curve, const std::array<word, N>& words) {
         return GenericField(curve, to_rep(curve, words));
      }

      static GenericField zero(const GenericPrimeOrderCurve* curve) {
         StorageUnit zeros = {};
         return GenericField(curve, zeros);
      }

      static GenericField one(const GenericPrimeOrderCurve* curve) {
         return GenericField(curve, curve->_params().field_monty_r1());
      }

      static GenericField curve_a(const GenericPrimeOrderCurve* curve) {
         return GenericField(curve, curve->_params().monty_curve_a());
      }

      static GenericField curve_b(const GenericPrimeOrderCurve* curve) {
         return GenericField(curve, curve->_params().monty_curve_b());
      }

      static GenericField random(const GenericPrimeOrderCurve* curve, RandomNumberGenerator& rng) {
         constexpr size_t MAX_ATTEMPTS = 1000;

         const size_t bits = curve->_params().field_bits();

         std::vector<uint8_t> buf(curve->_params().field_bytes());

         for(size_t i = 0; i != MAX_ATTEMPTS; ++i) {
            rng.randomize(buf);

            // Zero off high bits that if set would certainly cause us
            // to be out of range
            if(bits % 8 != 0) {
               const uint8_t mask = 0xFF >> (8 - (bits % 8));
               buf[0] &= mask;
            }

            if(auto s = GenericField::deserialize(curve, buf)) {
               if(s.value().is_nonzero().as_bool()) {
                  return s.value();
               }
            }
         }

         throw Internal_Error("Failed to generate random Scalar within bounded number of attempts");
      }

      /**
      * Return the value of this divided by 2
      */
      GenericField div2() const {
         StorageUnit t = value();
         W borrow = shift_right<1>(t);

         // If value was odd, add (P/2)+1
         bigint_cnd_add(borrow, t.data(), N, m_curve->_params().field_p_over_2_plus_1().data(), N);

         return GenericField(m_curve, t);
      }

      /// Return (*this) multiplied by 2
      GenericField mul2() const {
         StorageUnit t = value();
         W carry = shift_left<1>(t);

         StorageUnit r;
         bigint_monty_maybe_sub<N>(r.data(), carry, t.data(), m_curve->_params().field().data());
         return GenericField(m_curve, r);
      }

      /// Return (*this) multiplied by 3
      GenericField mul3() const { return mul2() + (*this); }

      /// Return (*this) multiplied by 4
      GenericField mul4() const { return mul2().mul2(); }

      /// Return (*this) multiplied by 8
      GenericField mul8() const { return mul2().mul2().mul2(); }

      friend GenericField operator+(const GenericField& a, const GenericField& b) {
         auto curve = check_curve(a, b);
         const size_t words = curve->_params().words();

         StorageUnit t = {};
         W carry = bigint_add3_nc(t.data(), a.data(), words, b.data(), words);

         StorageUnit r = {};
         bigint_monty_maybe_sub(words, r.data(), carry, t.data(), curve->_params().field().data());
         return GenericField(curve, r);
      }

      friend GenericField operator-(const GenericField& a, const GenericField& b) { return a + b.negate(); }

      friend GenericField operator*(const GenericField& a, const GenericField& b) {
         auto curve = check_curve(a, b);

         std::array<W, 2 * N> z;
         curve->_params().mul(z, a.value(), b.value());
         return GenericField(curve, redc(curve, z));
      }

      GenericField& operator*=(const GenericField& other) {
         auto curve = check_curve(*this, other);

         std::array<W, 2 * N> z;
         curve->_params().mul(z, value(), other.value());
         m_val = redc(curve, z);
         return (*this);
      }

      GenericField square() const {
         std::array<W, 2 * N> z;
         m_curve->_params().sqr(z, value());
         return GenericField(m_curve, redc(m_curve, z));
      }

      GenericField pow_vartime(const StorageUnit& exp) const {
         auto one = GenericField::one(curve());
         auto bits = curve()->_params().field_bits();
         auto words = curve()->_params().words();
         return impl_pow_vartime(*this, one, bits, std::span{exp}.last(words));
      }

      GenericField negate() const {
         auto x_is_zero = CT::all_zeros(this->data(), N);

         StorageUnit r;
         bigint_sub3(r.data(), m_curve->_params().field().data(), N, this->data(), N);
         x_is_zero.if_set_zero_out(r.data(), N);
         return GenericField(m_curve, r);
      }

      GenericField invert() const { return pow_vartime(m_curve->_params().field_minus_2()); }

      void serialize_to(std::span<uint8_t> bytes) const {
         auto v = from_rep(m_curve, m_val);
         std::reverse(v.begin(), v.end());

         const size_t flen = m_curve->_params().field_bytes();
         BOTAN_ARG_CHECK(bytes.size() == flen, "Expected output span provided");

         // Remove leading zero bytes
         const auto padded_bytes = store_be(v);
         const size_t extra = N * WordInfo<W>::bytes - flen;
         copy_mem(bytes, std::span{padded_bytes}.subspan(extra, flen));
      }

      CT::Choice is_zero() const { return CT::all_zeros(m_val.data(), m_curve->_params().words()).as_choice(); }

      CT::Choice is_nonzero() const { return !is_zero(); }

      CT::Choice operator==(const GenericField& other) const {
         if(this->m_curve != other.m_curve) {
            return CT::Choice::no();
         }

         return CT::is_equal(m_val.data(), other.m_val.data(), m_curve->_params().words()).as_choice();
      }

      const StorageUnit& stash_value() const { return m_val; }

      const GenericPrimeOrderCurve* curve() const { return m_curve; }

      CT::Choice is_even() const {
         auto v = from_rep(m_curve, m_val);
         return !CT::Choice::from_int(v[0] & 0x01);
      }

      /**
      * Convert the integer to standard representation and return the sequence of words
      */
      StorageUnit to_words() const { return from_rep(m_curve, m_val); }

      void _const_time_poison() const { CT::poison(m_val); }

      void _const_time_unpoison() const { CT::unpoison(m_val); }

      static void conditional_assign(GenericField& x, CT::Choice cond, const GenericField& nx) {
         const W mask = CT::Mask<W>::from_choice(cond).value();

         for(size_t i = 0; i != N; ++i) {
            x.m_val[i] = choose(mask, nx.m_val[i], x.m_val[i]);
         }
      }

      /**
      * Conditional assignment
      *
      * If `cond` is true, sets `x` to `nx` and `y` to `ny`
      */
      static void conditional_assign(
         GenericField& x, GenericField& y, CT::Choice cond, const GenericField& nx, const GenericField& ny) {
         const W mask = CT::Mask<W>::from_choice(cond).value();

         for(size_t i = 0; i != N; ++i) {
            x.m_val[i] = choose(mask, nx.m_val[i], x.m_val[i]);
            y.m_val[i] = choose(mask, ny.m_val[i], y.m_val[i]);
         }
      }

      /**
      * Conditional assignment
      *
      * If `cond` is true, sets `x` to `nx`, `y` to `ny`, and `z` to `nz`
      */
      static void conditional_assign(GenericField& x,
                                     GenericField& y,
                                     GenericField& z,
                                     CT::Choice cond,
                                     const GenericField& nx,
                                     const GenericField& ny,
                                     const GenericField& nz) {
         const W mask = CT::Mask<W>::from_choice(cond).value();

         for(size_t i = 0; i != N; ++i) {
            x.m_val[i] = choose(mask, nx.m_val[i], x.m_val[i]);
            y.m_val[i] = choose(mask, ny.m_val[i], y.m_val[i]);
            z.m_val[i] = choose(mask, nz.m_val[i], z.m_val[i]);
         }
      }

      std::pair<GenericField, CT::Choice> sqrt() const {
         BOTAN_STATE_CHECK(m_curve->_params().field()[0] % 4 == 3);

         auto z = pow_vartime(m_curve->_params().field_p_plus_1_over_4());
         const CT::Choice correct = (z.square() == *this);
         // Zero out the return value if it would otherwise be incorrect
         conditional_assign(z, !correct, zero(m_curve));
         return {z, correct};
      }

      GenericField(const GenericPrimeOrderCurve* curve, StorageUnit val) : m_curve(curve), m_val(val) {}

   private:
      const StorageUnit& value() const { return m_val; }

      const W* data() const { return m_val.data(); }

      static const GenericPrimeOrderCurve* check_curve(const GenericField& a, const GenericField& b) {
         BOTAN_STATE_CHECK(a.m_curve == b.m_curve);
         return a.m_curve;
      }

      static StorageUnit redc(const GenericPrimeOrderCurve* curve, std::array<W, 2 * N> z) {
         const auto& mod = curve->_params().field();
         const size_t words = curve->_params().words();
         StorageUnit r = {};
         StorageUnit ws = {};
         bigint_monty_redc(r.data(), z.data(), mod.data(), words, curve->_params().field_p_dash(), ws.data(), ws.size());
         return r;
      }

      static StorageUnit from_rep(const GenericPrimeOrderCurve* curve, StorageUnit z) {
         std::array<W, 2 * N> ze = {};
         copy_mem(std::span{ze}.template first<N>(), z);
         return redc(curve, ze);
      }

      static StorageUnit to_rep(const GenericPrimeOrderCurve* curve, StorageUnit x) {
         std::array<W, 2 * N> z;
         curve->_params().mul(z, x, curve->_params().field_monty_r2());
         return redc(curve, z);
      }

      const GenericPrimeOrderCurve* m_curve;
      StorageUnit m_val;
};

/**
* Affine Curve Point
*
* This contains a pair of integers (x,y) which satisfy the curve equation
*/
class GenericAffinePoint final {
   public:
      GenericAffinePoint(const GenericField& x, const GenericField& y) : m_x(x), m_y(y) {}

      GenericAffinePoint(const GenericPrimeOrderCurve* curve) :
            m_x(GenericField::zero(curve)), m_y(GenericField::zero(curve)) {}

      static GenericAffinePoint identity(const GenericPrimeOrderCurve* curve) {
         return GenericAffinePoint(GenericField::zero(curve), GenericField::zero(curve));
      }

      CT::Choice is_identity() const { return x().is_zero() && y().is_zero(); }

      GenericAffinePoint negate() const { return GenericAffinePoint(x(), y().negate()); }

      /**
      * Serialize the point in uncompressed format
      */
      void serialize_to(std::span<uint8_t> bytes) const {
         const size_t fe_bytes = curve()->_params().field_bytes();
         BOTAN_ARG_CHECK(bytes.size() == 1 + 2 * fe_bytes, "Buffer size incorrect");
         BOTAN_STATE_CHECK(this->is_identity().as_bool() == false);
         BufferStuffer pack(bytes);
         pack.append(0x04);
         x().serialize_to(pack.next(fe_bytes));
         y().serialize_to(pack.next(fe_bytes));
         BOTAN_DEBUG_ASSERT(pack.full());
      }

      /**
      * Serialize the point in compressed format
      */
      void serialize_compressed_to(std::span<uint8_t> bytes) const {
         const size_t fe_bytes = curve()->_params().field_bytes();
         BOTAN_ARG_CHECK(bytes.size() == 1 + fe_bytes, "Buffer size incorrect");
         BOTAN_STATE_CHECK(this->is_identity().as_bool() == false);
         const uint8_t hdr = CT::Mask<uint8_t>::from_choice(y().is_even()).select(0x02, 0x03);

         BufferStuffer pack(bytes);
         pack.append(hdr);
         x().serialize_to(pack.next(fe_bytes));
         BOTAN_DEBUG_ASSERT(pack.full());
      }

      /**
      * Serialize the affine x coordinate only
      */
      void serialize_x_to(std::span<uint8_t> bytes) const {
         BOTAN_STATE_CHECK(this->is_identity().as_bool() == false);
         x().serialize_to(bytes);
      }

      /**
      * If idx is zero then return the identity element. Otherwise return pts[idx - 1]
      *
      * Returns the identity element also if idx is out of range
      */
      static auto ct_select(std::span<const GenericAffinePoint> pts, size_t idx) {
         BOTAN_ARG_CHECK(!pts.empty(), "Cannot select from an empty set");
         auto result = GenericAffinePoint::identity(pts[0].curve());

         // Intentionally wrapping; set to maximum size_t if idx == 0
         const size_t idx1 = static_cast<size_t>(idx - 1);
         for(size_t i = 0; i != pts.size(); ++i) {
            const auto found = CT::Mask<size_t>::is_equal(idx1, i).as_choice();
            result.conditional_assign(found, pts[i]);
         }

         return result;
      }

      /**
      * Return (x^3 + A*x + B) mod p
      */
      static GenericField x3_ax_b(const GenericField& x) {
         return (x.square() + GenericField::curve_a(x.curve())) * x + GenericField::curve_b(x.curve());
      }

      /**
      * Point deserialization
      *
      * This accepts compressed or uncompressed formats.
      *
      * It also currently accepts the deprecated hybrid format.
      * TODO(Botan4): remove support for decoding hybrid points
      */
      static std::optional<GenericAffinePoint> deserialize(const GenericPrimeOrderCurve* curve,
                                                           std::span<const uint8_t> bytes) {
         const size_t fe_bytes = curve->_params().field_bytes();

         if(bytes.size() == 1 + 2 * fe_bytes) {
            if(bytes[0] == 0x04) {
               auto x = GenericField::deserialize(curve, bytes.subspan(1, fe_bytes));
               auto y = GenericField::deserialize(curve, bytes.subspan(1 + fe_bytes, fe_bytes));

               if(x && y) {
                  const auto lhs = (*y).square();
                  const auto rhs = GenericAffinePoint::x3_ax_b(*x);
                  if((lhs == rhs).as_bool()) {
                     return GenericAffinePoint(*x, *y);
                  }
               }
            } else if(bytes[0] == 0x06 || bytes[0] == 0x07) {
               // Deprecated "hybrid" encoding
               const CT::Choice y_is_even = CT::Mask<uint8_t>::is_equal(bytes[0], 0x06).as_choice();
               auto x = GenericField::deserialize(curve, bytes.subspan(1, fe_bytes));
               auto y = GenericField::deserialize(curve, bytes.subspan(1 + fe_bytes, fe_bytes));

               if(x && y && (y_is_even == y->is_even()).as_bool()) {
                  const auto lhs = (*y).square();
                  const auto rhs = GenericAffinePoint::x3_ax_b(*x);
                  if((lhs == rhs).as_bool()) {
                     return GenericAffinePoint(*x, *y);
                  }
               }
            }
         } else if(bytes.size() == 1 + fe_bytes) {
            if(bytes[0] == 0x02 || bytes[0] == 0x03) {
               const CT::Choice y_is_even = CT::Mask<uint8_t>::is_equal(bytes[0], 0x02).as_choice();

               if(auto x = GenericField::deserialize(curve, bytes.subspan(1, fe_bytes))) {
                  auto [y, is_square] = x3_ax_b(*x).sqrt();

                  if(is_square.as_bool()) {
                     const auto flip_y = y_is_even != y.is_even();
                     GenericField::conditional_assign(y, flip_y, y.negate());
                     return GenericAffinePoint(*x, y);
                  }
               }
            }
         } else if(bytes.size() == 1 && bytes[0] == 0x00) {
            // See SEC1 section 2.3.4
            return GenericAffinePoint::identity(curve);
         }

         return {};
      }

      /**
      * Return the affine x coordinate
      */
      const GenericField& x() const { return m_x; }

      /**
      * Return the affine y coordinate
      */
      const GenericField& y() const { return m_y; }

      /**
      * Conditional assignment of an affine point
      */
      void conditional_assign(CT::Choice cond, const GenericAffinePoint& pt) {
         GenericField::conditional_assign(m_x, m_y, cond, pt.x(), pt.y());
      }

      const GenericPrimeOrderCurve* curve() const { return m_x.curve(); }

      void _const_time_poison() const { CT::poison_all(m_x, m_y); }

      void _const_time_unpoison() const { CT::unpoison_all(m_x, m_y); }

   private:
      GenericField m_x;
      GenericField m_y;
};

class GenericProjectivePoint final {
   public:
      typedef GenericProjectivePoint Self;

      /**
      * Convert a point from affine to projective form
      */
      static Self from_affine(const GenericAffinePoint& pt) {
         if(pt.is_identity().as_bool()) {
            return Self::identity(pt.curve());
         } else {
            return GenericProjectivePoint(pt.x(), pt.y());
         }
      }

      /**
      * Return the identity element
      */
      static Self identity(const GenericPrimeOrderCurve* curve) {
         return Self(GenericField::zero(curve), GenericField::one(curve), GenericField::zero(curve));
      }

      /**
      * Default constructor: the identity element
      */
      GenericProjectivePoint(const GenericPrimeOrderCurve* curve) :
            m_x(GenericField::zero(curve)), m_y(GenericField::one(curve)), m_z(GenericField::zero(curve)) {}

      /**
      * Affine constructor: take x/y coordinates
      */
      GenericProjectivePoint(const GenericField& x, const GenericField& y) :
            m_x(x), m_y(y), m_z(GenericField::one(m_x.curve())) {}

      /**
      * Projective constructor: take x/y/z coordinates
      */
      GenericProjectivePoint(const GenericField& x, const GenericField& y, const GenericField& z) :
            m_x(x), m_y(y), m_z(z) {}

      friend Self operator+(const Self& a, const Self& b) { return Self::add(a, b); }

      friend Self operator+(const Self& a, const GenericAffinePoint& b) { return Self::add_mixed(a, b); }

      friend Self operator+(const GenericAffinePoint& a, const Self& b) { return Self::add_mixed(b, a); }

      Self& operator+=(const Self& other) {
         (*this) = (*this) + other;
         return (*this);
      }

      Self& operator+=(const GenericAffinePoint& other) {
         (*this) = (*this) + other;
         return (*this);
      }

      CT::Choice is_identity() const { return z().is_zero(); }

      /**
      * Mixed (projective + affine) point addition
      */
      static Self add_mixed(const Self& a, const GenericAffinePoint& b) {
         const auto a_is_identity = a.is_identity();
         const auto b_is_identity = b.is_identity();
         if((a_is_identity && b_is_identity).as_bool()) {
            return Self::identity(a.curve());
         }

         /*
         https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2

         Cost: 8M + 3S + 6add + 1*2
         */

         const auto Z1Z1 = a.z().square();
         const auto U2 = b.x() * Z1Z1;
         const auto S2 = b.y() * a.z() * Z1Z1;
         const auto H = U2 - a.x();
         const auto r = S2 - a.y();

         // If r == H == 0 then we are in the doubling case
         // For a == -b we compute the correct result because
         // H will be zero, leading to Z3 being zero also
         if((r.is_zero() && H.is_zero()).as_bool()) {
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

         // if a is identity then return b
         GenericField::conditional_assign(X3, Y3, Z3, a_is_identity, b.x(), b.y(), GenericField::one(a.curve()));

         // if b is identity then return a
         GenericField::conditional_assign(X3, Y3, Z3, b_is_identity, a.x(), a.y(), a.z());

         return Self(X3, Y3, Z3);
      }

      /**
      * Projective point addition
      */
      static Self add(const Self& a, const Self& b) {
         const auto a_is_identity = a.is_identity();
         const auto b_is_identity = b.is_identity();

         if((a_is_identity && b_is_identity).as_bool()) {
            return Self::identity(a.curve());
         }

         /*
         https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2

         Cost: 12M + 4S + 6add + 1*2
         */

         const auto Z1Z1 = a.z().square();
         const auto Z2Z2 = b.z().square();
         const auto U1 = a.x() * Z2Z2;
         const auto U2 = b.x() * Z1Z1;
         const auto S1 = a.y() * b.z() * Z2Z2;
         const auto S2 = b.y() * a.z() * Z1Z1;
         const auto H = U2 - U1;
         const auto r = S2 - S1;

         // If a == -b then H == 0 && r != 0, in which case
         // at the end we'll set z = a.z * b.z * H = 0, resulting
         // in the correct output (point at infinity)
         if((r.is_zero() && H.is_zero()).as_bool()) {
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

         // if a is identity then return b
         GenericField::conditional_assign(X3, Y3, Z3, a_is_identity, b.x(), b.y(), b.z());

         // if b is identity then return a
         GenericField::conditional_assign(X3, Y3, Z3, b_is_identity, a.x(), a.y(), a.z());

         return Self(X3, Y3, Z3);
      }

      /**
      * Iterated point doubling
      */
      Self dbl_n(size_t n) const {
         /*
         Repeated doubling using an adaptation of Algorithm 3.23 in
         "Guide To Elliptic Curve Cryptography" (Hankerson, Menezes, Vanstone)

         Curiously the book gives the algorithm only for A == -3, but
         the largest gains come from applying it to the generic A case,
         where it saves 2 squarings per iteration.

         For A == 0
           Pay 1*2 + 1half to save n*(1*4 + 1*8)

         For A == -3:
           Pay 2S + 1*2 + 1half to save n*(1A + 1*4 + 1*8) + 1M

         For generic A:
           Pay 2S + 1*2 + 1half to save n*(2S + 1*4 + 1*8)
         */

         if(curve()->_params().a_is_zero()) {
            auto nx = x();
            auto ny = y().mul2();
            auto nz = z();

            while(n > 0) {
               const auto ny2 = ny.square();
               const auto ny4 = ny2.square();
               const auto t1 = nx.square().mul3();
               const auto t2 = nx * ny2;
               nx = t1.square() - t2.mul2();
               nz *= ny;
               ny = t1 * (t2 - nx).mul2() - ny4;
               n--;
            }
            return Self(nx, ny.div2(), nz);
         } else {
            auto nx = x();
            auto ny = y().mul2();
            auto nz = z();
            auto w = nz.square().square() * GenericField::curve_a(curve());

            while(n > 0) {
               const auto ny2 = ny.square();
               const auto ny4 = ny2.square();
               GenericField t1 = nx.square().mul3() + w;
               const auto t2 = nx * ny2;
               nx = t1.square() - t2.mul2();
               nz *= ny;
               ny = t1 * (t2 - nx).mul2() - ny4;
               n--;
               if(n > 0) {
                  w *= ny4;
               }
            }
            return Self(nx, ny.div2(), nz);
         }
      }

      /**
      * Point doubling
      */
      Self dbl() const {
         /*
         Using https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-1998-cmo-2

         Cost (generic A): 4M + 6S + 4A + 2*2 + 1*3 + 1*4 + 1*8
         Cost (A == -3):   4M + 4S + 5A + 2*2 + 1*3 + 1*4 + 1*8
         Cost (A == 0):    3M + 4S + 3A + 2*2 + 1*3 + 1*4 + 1*8
         */

         GenericField m = [&]() {
            if(curve()->_params().a_is_minus_3()) {
               /*
               if a == -3 then
               3*x^2 + a*z^4 == 3*x^2 - 3*z^4 == 3*(x^2-z^4) == 3*(x-z^2)*(x+z^2)

               Cost: 1M + 1S + 2A + 1*3
               */
               const auto z2 = z().square();
               return (x() - z2).mul3() * (x() + z2);
            } else if(curve()->_params().a_is_zero()) {
               // If a == 0 then 3*x^2 + a*z^4 == 3*x^2
               // Cost: 1S + 1*3
               return x().square().mul3();
            } else {
               // Cost: 1M + 3S + 1A + 1*3
               const auto z2 = z().square();
               return x().square().mul3() + GenericField::curve_a(curve()) * z2.square();
            }
         }();

         // Remaining cost: 3M + 3S + 3A + 2*2 + 1*4 + 1*8
         const auto y2 = y().square();
         const auto s = x().mul4() * y2;
         const auto nx = m.square() - s.mul2();
         const auto ny = m * (s - nx) - y2.square().mul8();
         const auto nz = y().mul2() * z();

         return Self(nx, ny, nz);
      }

      /**
      * Point negation
      */
      Self negate() const { return Self(x(), y().negate(), z()); }

      /**
      * Randomize the point representation
      *
      * Projective coordinates are redundant; if (x,y,z) is a projective
      * point then so is (x*r^2,y*r^3,z*r) for any non-zero r.
      */
      void randomize_rep(RandomNumberGenerator& rng) {
         // In certain contexts we may be called with a Null_RNG; in that case the
         // caller is accepting that randomization will not occur

         if(rng.is_seeded()) {
            auto r = GenericField::random(curve(), rng);

            auto r2 = r.square();
            auto r3 = r2 * r;

            m_x *= r2;
            m_y *= r3;
            m_z *= r;
         }
      }

      GenericAffinePoint to_affine() const {
         if(is_identity().as_bool()) {
            return GenericAffinePoint::identity(curve());
         }

         const auto z_inv = z().invert();
         const auto z2_inv = z_inv.square();
         const auto z3_inv = z_inv * z2_inv;
         return GenericAffinePoint(x() * z2_inv, y() * z3_inv);
      }

      static std::vector<GenericAffinePoint> to_affine_batch(std::span<GenericProjectivePoint> projective) {
         const size_t N = projective.size();

         CT::Choice any_identity = CT::Choice::no();

         for(const auto& pt : projective) {
            any_identity = any_identity || pt.is_identity();
         }

         if(N <= 2 || any_identity.as_bool()) {
            // If there are identity elements, using the batch inversion gets
            // tricky. It can be done, but this should be a rare situation so
            // just punt to the serial conversion if it occurs
            std::vector<GenericAffinePoint> affine;
            for(size_t i = 0; i != N; ++i) {
               affine.push_back(projective[i].to_affine());
            }
            return affine;
         } else {
            std::vector<GenericField> c;

            /*
            Batch projective->affine using Montgomery's trick

            See Algorithm 2.26 in "Guide to Elliptic Curve Cryptography"
            (Hankerson, Menezes, Vanstone)
            */

            c.push_back(projective[0].z());
            for(size_t i = 1; i != N; ++i) {
               c.push_back(c[i - 1] * projective[i].z());
            }

            auto s_inv = c[N - 1].invert();

            std::vector<GenericAffinePoint> affine;
            for(size_t i = N - 1; i > 0; --i) {
               const auto& p = projective[i];

               const auto z_inv = s_inv * c[i - 1];
               const auto z2_inv = z_inv.square();
               const auto z3_inv = z_inv * z2_inv;

               s_inv = s_inv * p.z();

               affine.push_back(GenericAffinePoint(p.x() * z2_inv, p.y() * z3_inv));
            }

            const auto z2_inv = s_inv.square();
            const auto z3_inv = s_inv * z2_inv;
            affine.push_back(GenericAffinePoint(projective[0].x() * z2_inv, projective[0].y() * z3_inv));
            std::reverse(affine.begin(), affine.end());
            return affine;
         }
      }

      /**
      * Return the projective x coordinate
      */
      const GenericField& x() const { return m_x; }

      /**
      * Return the projective y coordinate
      */
      const GenericField& y() const { return m_y; }

      /**
      * Return the projective z coordinate
      */
      const GenericField& z() const { return m_z; }

      const GenericPrimeOrderCurve* curve() const { return m_x.curve(); }

      void _const_time_poison() const { CT::poison_all(m_x, m_y, m_z); }

      void _const_time_unpoison() const { CT::unpoison_all(m_x, m_y, m_z); }

   private:
      GenericField m_x;
      GenericField m_y;
      GenericField m_z;
};

class GenericBlindedScalarBits final {
   public:
      GenericBlindedScalarBits(const GenericScalar& scalar, RandomNumberGenerator& rng, size_t wb) {
         // Just a simplifying assumption for get_window, can extend to 1..7 as required
         BOTAN_ASSERT_NOMSG(wb == 4 || wb == 5);

         const auto& params = scalar.curve()->_params();

         const size_t order_bits = params.order_bits();
         const size_t order_bytes = params.order_bytes();
         const size_t blinder_bits = blinding_bits(order_bits);

         const size_t mask_words = blinder_bits / WordInfo<word>::bits;
         const size_t mask_bytes = mask_words * WordInfo<word>::bytes;

         const size_t words = params.words();

         secure_vector<uint8_t> maskb(mask_bytes);
         if(rng.is_seeded()) {
            rng.randomize(maskb);
         } else {
            std::vector<uint8_t> sbytes(order_bytes);
            scalar.serialize_to(sbytes);
            for(size_t i = 0; i != sbytes.size(); ++i) {
               maskb[i % mask_bytes] ^= sbytes[i];
            }
         }

         std::array<word, PrimeOrderCurve::StorageWords> mask = {};
         load_le(mask.data(), maskb.data(), mask_words);
         mask[mask_words - 1] |= WordInfo<word>::top_bit;
         mask[0] |= 1;

         std::array<word, 2 * PrimeOrderCurve::StorageWords> mask_n = {};

         const auto sw = scalar.to_words();

         // Compute masked scalar s + k*n
         params.mul(mask_n, mask, params.order());
         bigint_add2_nc(mask_n.data(), 2 * words, sw.data(), words);

         std::reverse(mask_n.begin(), mask_n.end());
         m_bytes = store_be<std::vector<uint8_t>>(mask_n);
         m_window_bits = wb;
         m_windows = (order_bits + blinder_bits + wb - 1) / wb;
      }

      size_t windows() const { return m_windows; }

      size_t get_window(size_t offset) const {
         if(m_window_bits == 4) {
            return read_window_bits<4>(std::span{m_bytes}, offset);
         } else if(m_window_bits == 5) {
            return read_window_bits<5>(std::span{m_bytes}, offset);
         } else {
            BOTAN_ASSERT_UNREACHABLE();
         }
      }

      static size_t blinding_bits(size_t order_bits) {
         if(order_bits > 512) {
            return blinding_bits(512);
         }

         const size_t wb = sizeof(word) * 8;
         return ((order_bits / 4 + wb - 1) / wb) * wb;
      }

   private:
      std::vector<uint8_t> m_bytes;
      size_t m_windows;
      size_t m_window_bits;
};

class GenericWindowedMul final {
   public:
      GenericWindowedMul(const GenericAffinePoint& pt, size_t window_bits) : m_window_bits(window_bits) {
         BOTAN_ARG_CHECK(window_bits == 4 || window_bits == 5, "Invalid window_bits");

         const size_t table_size = (1 << window_bits) - 1;

         std::vector<GenericProjectivePoint> table;
         table.push_back(GenericProjectivePoint::from_affine(pt));

         for(size_t i = 1; i != table_size; ++i) {
            if(i % 2 == 1) {
               table.push_back(table[i / 2].dbl());
            } else {
               table.push_back(table[i - 1] + pt);
            }
         }

         m_table = GenericProjectivePoint::to_affine_batch(table);
      }

      GenericProjectivePoint mul(const GenericScalar& s, RandomNumberGenerator& rng) {
         GenericBlindedScalarBits bits(s, rng, m_window_bits);

         const size_t windows = bits.windows();

         auto accum = [&]() {
            const size_t w_0 = bits.get_window((windows - 1) * m_window_bits);
            // Guaranteed because we set the high bit of the randomizer
            BOTAN_DEBUG_ASSERT(w_0 != 0);
            auto pt = GenericProjectivePoint::from_affine(GenericAffinePoint::ct_select(m_table, w_0));
            CT::poison(pt);
            pt.randomize_rep(rng);
            return pt;
         }();

         for(size_t i = 1; i != windows; ++i) {
            accum = accum.dbl_n(m_window_bits);
            auto w_i = bits.get_window((windows - i - 1) * m_window_bits);
            accum += GenericAffinePoint::ct_select(m_table, w_i);

            if(i <= 3) {
               accum.randomize_rep(rng);
            }
         }

         CT::unpoison(accum);
         return accum;
      }

   private:
      std::vector<GenericAffinePoint> m_table;
      size_t m_window_bits;
};

class GenericBaseMulTable final {
   public:
      static constexpr size_t WindowBits = 4;

      static constexpr size_t WindowElements = (1 << WindowBits) - 1;

      GenericBaseMulTable(const GenericAffinePoint& pt) {
         const size_t order_bits = pt.curve()->order_bits();
         const size_t blinded_scalar_bits = order_bits + GenericBlindedScalarBits::blinding_bits(order_bits);

         const size_t windows = (blinded_scalar_bits + WindowBits - 1) / WindowBits;
         const size_t table_size = windows * WindowElements;

         std::vector<GenericProjectivePoint> table;
         table.reserve(table_size);

         auto accum = GenericProjectivePoint::from_affine(pt);

         for(size_t i = 0; i != table_size; i += WindowElements) {
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

         m_table = GenericProjectivePoint::to_affine_batch(table);
      }

      GenericProjectivePoint mul(const GenericScalar& s, RandomNumberGenerator& rng) {
         GenericBlindedScalarBits bits(s, rng, WindowBits);

         // TODO: C++23 - use std::mdspan to access m_table
         auto table = std::span{m_table};

         auto accum = [&]() {
            const size_t w_0 = bits.get_window(0);
            const auto tbl_0 = table.first(WindowElements);
            auto pt = GenericProjectivePoint::from_affine(GenericAffinePoint::ct_select(tbl_0, w_0));
            CT::poison(pt);
            pt.randomize_rep(rng);
            return pt;
         }();

         for(size_t i = 1; i != bits.windows(); ++i) {
            const size_t w_i = bits.get_window(WindowBits * i);
            const auto tbl_i = table.subspan(WindowElements * i, WindowElements);
            accum += GenericAffinePoint::ct_select(tbl_i, w_i);

            if(i <= 3) {
               accum.randomize_rep(rng);
            }
         }

         CT::unpoison(accum);
         return accum;
      }

   private:
      std::vector<GenericAffinePoint> m_table;
};

class GenericWindowedMul2 final : public PrimeOrderCurve::PrecomputedMul2Table {
   public:
      static constexpr size_t WindowBits = 3;

      static constexpr size_t WindowSize = (1 << WindowBits);

      // 2^(2*W) elements, less the identity element
      static constexpr size_t TableSize = (1 << (2 * WindowBits)) - 1;

      GenericWindowedMul2(const GenericWindowedMul2& other) = delete;
      GenericWindowedMul2(GenericWindowedMul2&& other) = delete;
      GenericWindowedMul2& operator=(const GenericWindowedMul2& other) = delete;
      GenericWindowedMul2& operator=(GenericWindowedMul2&& other) = delete;

      ~GenericWindowedMul2() override = default;

      GenericWindowedMul2(const GenericAffinePoint& x, const GenericAffinePoint& y) {
         std::vector<GenericProjectivePoint> table;

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
                  if(x_i == 1) {
                     return x + table[(y_i << WindowBits) - 1];
                  } else if(y_i == 1) {
                     return table[x_i - 1] + y;
                  } else {
                     return table[x_i - 1] + table[(y_i << WindowBits) - 1];
                  }
               } else if(x_i > 0 && y_i == 0) {
                  // A multiple of x without a y component
                  if(x_i == 1) {
                     // Just x
                     return GenericProjectivePoint::from_affine(x);
                  } else {
                     // x * x_{i-1}
                     return x + table[x_i - 1 - 1];
                  }
               } else if(x_i == 0 && y_i > 0) {
                  if(y_i == 1) {
                     // Just y
                     return GenericProjectivePoint::from_affine(y);
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

         m_table = GenericProjectivePoint::to_affine_batch(table);
      }

      GenericProjectivePoint mul2_vartime(const GenericScalar& x, const GenericScalar& y) const {
         const auto x_bits = x.serialize();
         const auto y_bits = y.serialize();

         const auto& curve = m_table[0].curve();
         auto accum = GenericProjectivePoint(curve);

         const size_t order_bits = curve->order_bits();

         const size_t windows = (order_bits + WindowBits - 1) / WindowBits;

         for(size_t i = 0; i != windows; ++i) {
            auto x_i = read_window_bits<WindowBits>(std::span{x_bits}, (windows - i - 1) * WindowBits);
            auto y_i = read_window_bits<WindowBits>(std::span{y_bits}, (windows - i - 1) * WindowBits);

            if(i > 0) {
               accum = accum.dbl_n(WindowBits);
            }

            const size_t idx = (y_i << WindowBits) + x_i;

            if(idx > 0) {
               accum += m_table[idx - 1];
            }
         }

         return accum;
      }

   private:
      std::vector<GenericAffinePoint> m_table;
};

GenericPrimeOrderCurve::GenericPrimeOrderCurve(
   const BigInt& p, const BigInt& a, const BigInt& b, const BigInt& base_x, const BigInt& base_y, const BigInt& order) :
      m_params(std::make_unique<GenericCurveParams>(p, a, b, base_x, base_y, order)) {}

void GenericPrimeOrderCurve::_precompute_base_mul() {
   BOTAN_STATE_CHECK(m_basemul == nullptr);
   m_basemul = std::make_unique<GenericBaseMulTable>(from_stash(generator()));
}

size_t GenericPrimeOrderCurve::order_bits() const {
   return _params().order_bits();
}

size_t GenericPrimeOrderCurve::scalar_bytes() const {
   return _params().order_bytes();
}

size_t GenericPrimeOrderCurve::field_element_bytes() const {
   return _params().field_bytes();
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::mul_by_g(const Scalar& scalar,
                                                                  RandomNumberGenerator& rng) const {
   BOTAN_STATE_CHECK(m_basemul != nullptr);
   return stash(m_basemul->mul(from_stash(scalar), rng));
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::base_point_mul_x_mod_order(const Scalar& scalar,
                                                                           RandomNumberGenerator& rng) const {
   BOTAN_STATE_CHECK(m_basemul != nullptr);
   auto pt_s = m_basemul->mul(from_stash(scalar), rng);
   secure_vector<uint8_t> x_bytes(_params().field_bytes());
   pt_s.to_affine().x().serialize_to(x_bytes);
   return stash(GenericScalar::from_wide_bytes(this, x_bytes).value());
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::mul(const AffinePoint& pt,
                                                             const Scalar& scalar,
                                                             RandomNumberGenerator& rng) const {
   GenericWindowedMul pt_table(from_stash(pt), 4);
   return stash(pt_table.mul(from_stash(scalar), rng));
}

secure_vector<uint8_t> GenericPrimeOrderCurve::mul_x_only(const AffinePoint& pt,
                                                          const Scalar& scalar,
                                                          RandomNumberGenerator& rng) const {
   GenericWindowedMul pt_table(from_stash(pt), 4);
   auto pt_s = pt_table.mul(from_stash(scalar), rng);
   secure_vector<uint8_t> x_bytes(_params().field_bytes());
   pt_s.to_affine().x().serialize_to(x_bytes);
   return x_bytes;
}

std::unique_ptr<const PrimeOrderCurve::PrecomputedMul2Table> GenericPrimeOrderCurve::mul2_setup(
   const AffinePoint& p, const AffinePoint& q) const {
   return std::make_unique<GenericWindowedMul2>(from_stash(p), from_stash(q));
}

std::unique_ptr<const PrimeOrderCurve::PrecomputedMul2Table> GenericPrimeOrderCurve::mul2_setup_g(
   const AffinePoint& q) const {
   return std::make_unique<GenericWindowedMul2>(from_stash(generator()), from_stash(q));
}

std::optional<PrimeOrderCurve::ProjectivePoint> GenericPrimeOrderCurve::mul2_vartime(const PrecomputedMul2Table& tableb,
                                                                                     const Scalar& s1,
                                                                                     const Scalar& s2) const {
   const auto& tbl = dynamic_cast<const GenericWindowedMul2&>(tableb);
   auto pt = tbl.mul2_vartime(from_stash(s1), from_stash(s2));
   if(pt.is_identity().as_bool()) {
      return {};
   } else {
      return stash(pt);
   }
};

std::optional<PrimeOrderCurve::ProjectivePoint> GenericPrimeOrderCurve::mul_px_qy(
   const AffinePoint& p, const Scalar& x, const AffinePoint& q, const Scalar& y, RandomNumberGenerator& rng) const {
   // TODO this could be much faster using Mul2
   GenericWindowedMul p_table(from_stash(p), 4);
   GenericWindowedMul q_table(from_stash(q), 4);

   auto pt = p_table.mul(from_stash(x), rng) + q_table.mul(from_stash(y), rng);

   if(pt.is_identity().as_bool()) {
      return {};
   } else {
      return stash(pt);
   }
};

bool GenericPrimeOrderCurve::mul2_vartime_x_mod_order_eq(const PrecomputedMul2Table& tableb,
                                                         const Scalar& v,
                                                         const Scalar& s1,
                                                         const Scalar& s2) const {
   const auto& tbl = dynamic_cast<const GenericWindowedMul2&>(tableb);
   auto pt = tbl.mul2_vartime(from_stash(s1), from_stash(s2));

   if(!pt.is_identity().as_bool()) {
      const auto z2 = pt.z().square();

      std::vector<uint8_t> v_bytes(_params().order_bytes());
      from_stash(v).serialize_to(v_bytes);

      if(auto fe_v = GenericField::deserialize(this, v_bytes)) {
         if((*fe_v * z2 == pt.x()).as_bool()) {
            return true;
         }

         if(_params().order_is_less_than_field()) {
            const auto n = GenericField::from_words(this, _params().order());
            const auto neg_n = n.negate().to_words();

            const auto vw = fe_v->to_words();
            if(bigint_ct_is_lt(vw.data(), vw.size(), neg_n.data(), neg_n.size()).as_bool()) {
               return (((*fe_v + n) * z2) == pt.x()).as_bool();
            }
         }
      }
   }

   return false;
}

PrimeOrderCurve::AffinePoint GenericPrimeOrderCurve::generator() const {
   return PrimeOrderCurve::AffinePoint::_create(shared_from_this(), _params().base_x(), _params().base_y());
}

PrimeOrderCurve::AffinePoint GenericPrimeOrderCurve::point_to_affine(const ProjectivePoint& pt) const {
   return stash(from_stash(pt).to_affine());
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::point_to_projective(const AffinePoint& pt) const {
   return stash(GenericProjectivePoint::from_affine(from_stash(pt)));
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::point_add(const AffinePoint& a,
                                                                   const AffinePoint& b) const {
   return stash(GenericProjectivePoint::from_affine(from_stash(a)) + from_stash(b));
}

PrimeOrderCurve::AffinePoint GenericPrimeOrderCurve::point_negate(const AffinePoint& pt) const {
   return stash(from_stash(pt).negate());
}

bool GenericPrimeOrderCurve::affine_point_is_identity(const AffinePoint& pt) const {
   return from_stash(pt).is_identity().as_bool();
}

void GenericPrimeOrderCurve::serialize_point(std::span<uint8_t> bytes, const AffinePoint& pt) const {
   from_stash(pt).serialize_to(bytes);
}

void GenericPrimeOrderCurve::serialize_scalar(std::span<uint8_t> bytes, const Scalar& scalar) const {
   BOTAN_ARG_CHECK(bytes.size() == _params().order_bytes(), "Invalid length to serialize_scalar");
   from_stash(scalar).serialize_to(bytes);
}

std::optional<PrimeOrderCurve::Scalar> GenericPrimeOrderCurve::deserialize_scalar(
   std::span<const uint8_t> bytes) const {
   if(auto s = GenericScalar::deserialize(this, bytes)) {
      return stash(s.value());
   } else {
      return {};
   }
}

std::optional<PrimeOrderCurve::Scalar> GenericPrimeOrderCurve::scalar_from_wide_bytes(
   std::span<const uint8_t> bytes) const {
   if(auto s = GenericScalar::from_wide_bytes(this, bytes)) {
      return stash(s.value());
   } else {
      return {};
   }
}

std::optional<PrimeOrderCurve::AffinePoint> GenericPrimeOrderCurve::deserialize_point(
   std::span<const uint8_t> bytes) const {
   if(auto pt = GenericAffinePoint::deserialize(this, bytes)) {
      return stash(pt.value());
   } else {
      return {};
   }
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_add(const Scalar& a, const Scalar& b) const {
   return stash(from_stash(a) + from_stash(b));
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_sub(const Scalar& a, const Scalar& b) const {
   return stash(from_stash(a) - from_stash(b));
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_mul(const Scalar& a, const Scalar& b) const {
   return stash(from_stash(a) * from_stash(b));
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_square(const Scalar& s) const {
   return stash(from_stash(s).square());
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_invert(const Scalar& s) const {
   return stash(from_stash(s).invert());
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_invert_vartime(const Scalar& s) const {
   // TODO support BEEA for this
   return stash(from_stash(s).invert());
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_negate(const Scalar& s) const {
   return stash(from_stash(s).negate());
}

bool GenericPrimeOrderCurve::scalar_is_zero(const Scalar& s) const {
   return from_stash(s).is_zero().as_bool();
}

bool GenericPrimeOrderCurve::scalar_equal(const Scalar& a, const Scalar& b) const {
   return (from_stash(a) == from_stash(b)).as_bool();
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_one() const {
   return stash(GenericScalar::one(this));
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::random_scalar(RandomNumberGenerator& rng) const {
   return stash(GenericScalar::random(this, rng));
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::stash(const GenericScalar& s) const {
   return Scalar::_create(shared_from_this(), s.stash_value());
}

GenericScalar GenericPrimeOrderCurve::from_stash(const PrimeOrderCurve::Scalar& s) const {
   BOTAN_ARG_CHECK(s._curve().get() == this, "Curve mismatch");
   return GenericScalar(this, s._value());
}

PrimeOrderCurve::AffinePoint GenericPrimeOrderCurve::stash(const GenericAffinePoint& pt) const {
   auto x_w = pt.x().stash_value();
   auto y_w = pt.y().stash_value();
   return AffinePoint::_create(shared_from_this(), x_w, y_w);
}

GenericAffinePoint GenericPrimeOrderCurve::from_stash(const PrimeOrderCurve::AffinePoint& pt) const {
   BOTAN_ARG_CHECK(pt._curve().get() == this, "Curve mismatch");
   auto x = GenericField(this, pt._x());
   auto y = GenericField(this, pt._y());
   return GenericAffinePoint(x, y);
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::stash(const GenericProjectivePoint& pt) const {
   auto x_w = pt.x().stash_value();
   auto y_w = pt.y().stash_value();
   auto z_w = pt.z().stash_value();
   return ProjectivePoint::_create(shared_from_this(), x_w, y_w, z_w);
}

GenericProjectivePoint GenericPrimeOrderCurve::from_stash(const PrimeOrderCurve::ProjectivePoint& pt) const {
   BOTAN_ARG_CHECK(pt._curve().get() == this, "Curve mismatch");
   auto x = GenericField(this, pt._x());
   auto y = GenericField(this, pt._y());
   auto z = GenericField(this, pt._z());
   return GenericProjectivePoint(x, y, z);
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

std::shared_ptr<const PrimeOrderCurve> PCurveInstance::from_params(
   const BigInt& p, const BigInt& a, const BigInt& b, const BigInt& base_x, const BigInt& base_y, const BigInt& order) {
   // We don't check that p and order are prime here on the assumption this has
   // been checked already by EC_Group

   BOTAN_ARG_CHECK(a >= 0 && a < p, "a is invalid");
   BOTAN_ARG_CHECK(b > 0 && b < p, "b is invalid");
   BOTAN_ARG_CHECK(base_x >= 0 && base_x < p, "base_x is invalid");
   BOTAN_ARG_CHECK(base_y >= 0 && base_y < p, "base_y is invalid");

   const size_t p_bits = p.bits();

   // Same size restrictions as EC_Group however here we do not require
   // exactly the primes for the 521 or 239 bit exceptions; this code
   // should work fine with any such prime and we are relying on the higher
   // levels to prevent creating such a group in the first place

   if(p_bits != 521 && p_bits != 239 && (p_bits < 128 || p_bits > 512 || p_bits % 32 != 0)) {
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

   auto gpoc = std::make_shared<GenericPrimeOrderCurve>(p, a, b, base_x, base_y, order);
   /*
   The implementation of this needs to call shared_from_this which is not usable
   until after the constructor has completed, so we have to do a two-stage
   construction process. This is certainly not so clean but it is contained to
   this single file so seems tolerable.

   Alternately we could lazily compute the base mul table but this brings in
   locking issues which seem a worse alternative overall.
   */
   gpoc->_precompute_base_mul();
   return gpoc;
}

}  // namespace Botan::PCurve
