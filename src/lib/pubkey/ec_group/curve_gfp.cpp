/*
* Elliptic curves over GF(p) Montgomery Representation
* (C) 2014,2015,2018 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/curve_gfp.h>

#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/internal/curve_nistp.h>
#include <botan/internal/monty.h>
#include <botan/internal/mp_core.h>

namespace Botan {

namespace {

class CurveGFp_Montgomery final : public CurveGFp_Repr {
   public:
      CurveGFp_Montgomery(const BigInt& p, const BigInt& a, const BigInt& b) :
            m_p(p),
            m_a(a),
            m_b(b),
            m_p_bits(m_p.bits()),
            m_p_words(m_p.sig_words()),
            m_p_dash(monty_inverse(m_p.word_at(0))) {
         Modular_Reducer mod_p(m_p);

         m_r.set_bit(m_p_words * BOTAN_MP_WORD_BITS);
         m_r = mod_p.reduce(m_r);

         m_r2 = mod_p.square(m_r);
         m_r3 = mod_p.multiply(m_r, m_r2);
         m_a_r = mod_p.multiply(m_r, m_a);
         m_b_r = mod_p.multiply(m_r, m_b);

         m_a_is_zero = m_a.is_zero();
         m_a_is_minus_3 = (m_a + 3 == m_p);
      }

      bool a_is_zero() const override { return m_a_is_zero; }

      bool a_is_minus_3() const override { return m_a_is_minus_3; }

      const BigInt& get_a() const override { return m_a; }

      const BigInt& get_b() const override { return m_b; }

      const BigInt& get_p() const override { return m_p; }

      const BigInt& get_a_rep() const override { return m_a_r; }

      const BigInt& get_b_rep() const override { return m_b_r; }

      const BigInt& get_1_rep() const override { return m_r; }

      bool is_one(const BigInt& x) const override { return x == m_r; }

      size_t get_p_bits() const override { return m_p_bits; }

      size_t get_ws_size() const override { return 2 * m_p_words; }

      BigInt invert_element(const BigInt& x, secure_vector<word>& ws) const override;

      void to_curve_rep(BigInt& x, secure_vector<word>& ws) const override;

      void from_curve_rep(BigInt& x, secure_vector<word>& ws) const override;

      void curve_mul_words(
         BigInt& z, const word x_words[], size_t x_size, const BigInt& y, secure_vector<word>& ws) const override;

      void curve_sqr_words(BigInt& z, const word x_words[], size_t x_size, secure_vector<word>& ws) const override;

   private:
      BigInt m_p;
      BigInt m_a, m_b;
      BigInt m_a_r, m_b_r;
      size_t m_p_bits;   // cache of m_p.bits()
      size_t m_p_words;  // cache of m_p.sig_words()

      // Montgomery parameters
      BigInt m_r, m_r2, m_r3;
      word m_p_dash;

      bool m_a_is_zero;
      bool m_a_is_minus_3;
};

BigInt CurveGFp_Montgomery::invert_element(const BigInt& x, secure_vector<word>& ws) const {
   // Should we use Montgomery inverse instead?
   const BigInt inv = inverse_mod(x, m_p);
   BigInt res;
   curve_mul(res, inv, m_r3, ws);
   return res;
}

void CurveGFp_Montgomery::to_curve_rep(BigInt& x, secure_vector<word>& ws) const {
   const BigInt tx = x;
   curve_mul(x, tx, m_r2, ws);
}

void CurveGFp_Montgomery::from_curve_rep(BigInt& z, secure_vector<word>& ws) const {
   if(ws.size() < get_ws_size()) {
      ws.resize(get_ws_size());
   }

   const size_t output_size = 2 * m_p_words;
   if(z.size() < output_size) {
      z.grow_to(output_size);
   }

   bigint_monty_redc(z.mutable_data(), m_p._data(), m_p_words, m_p_dash, ws.data(), ws.size());
}

void CurveGFp_Montgomery::curve_mul_words(
   BigInt& z, const word x_w[], size_t x_size, const BigInt& y, secure_vector<word>& ws) const {
   BOTAN_DEBUG_ASSERT(y.sig_words() <= m_p_words);

   if(ws.size() < get_ws_size()) {
      ws.resize(get_ws_size());
   }

   const size_t output_size = 2 * m_p_words;
   if(z.size() < output_size) {
      z.grow_to(output_size);
   }

   bigint_mul(z.mutable_data(),
              z.size(),
              x_w,
              x_size,
              std::min(m_p_words, x_size),
              y._data(),
              y.size(),
              std::min(m_p_words, y.size()),
              ws.data(),
              ws.size());

   bigint_monty_redc(z.mutable_data(), m_p._data(), m_p_words, m_p_dash, ws.data(), ws.size());
}

void CurveGFp_Montgomery::curve_sqr_words(BigInt& z, const word x[], size_t x_size, secure_vector<word>& ws) const {
   if(ws.size() < get_ws_size()) {
      ws.resize(get_ws_size());
   }

   const size_t output_size = 2 * m_p_words;
   if(z.size() < output_size) {
      z.grow_to(output_size);
   }

   bigint_sqr(z.mutable_data(), z.size(), x, x_size, std::min(m_p_words, x_size), ws.data(), ws.size());

   bigint_monty_redc(z.mutable_data(), m_p._data(), m_p_words, m_p_dash, ws.data(), ws.size());
}

class CurveGFp_NIST : public CurveGFp_Repr {
   public:
      CurveGFp_NIST(size_t p_bits, const BigInt& a, const BigInt& b) :
            m_1(1),
            m_a(a),
            m_b(b),
            m_p_bits(p_bits),
            m_p_words((p_bits + BOTAN_MP_WORD_BITS - 1) / BOTAN_MP_WORD_BITS) {
         // All Solinas prime curves are assumed a == -3
      }

      bool a_is_zero() const override { return false; }

      bool a_is_minus_3() const override { return true; }

      const BigInt& get_a() const override { return m_a; }

      const BigInt& get_b() const override { return m_b; }

      const BigInt& get_1_rep() const override { return m_1; }

      size_t get_p_bits() const override { return m_p_bits; }

      size_t get_ws_size() const override { return 2 * m_p_words; }

      const BigInt& get_a_rep() const override { return m_a; }

      const BigInt& get_b_rep() const override { return m_b; }

      bool is_one(const BigInt& x) const override { return x == 1; }

      void to_curve_rep(BigInt& x, secure_vector<word>& ws) const override { redc_mod_p(x, ws); }

      void from_curve_rep(BigInt& x, secure_vector<word>& ws) const override { redc_mod_p(x, ws); }

      virtual void redc_mod_p(BigInt& z, secure_vector<word>& ws) const = 0;

      BigInt invert_element(const BigInt& x, secure_vector<word>& ws) const override;

      void curve_mul_words(
         BigInt& z, const word x_words[], size_t x_size, const BigInt& y, secure_vector<word>& ws) const override;

      void curve_mul_tmp(BigInt& x, const BigInt& y, BigInt& tmp, secure_vector<word>& ws) const {
         curve_mul(tmp, x, y, ws);
         x.swap(tmp);
      }

      void curve_sqr_tmp(BigInt& x, BigInt& tmp, secure_vector<word>& ws) const {
         curve_sqr(tmp, x, ws);
         x.swap(tmp);
      }

      void curve_sqr_words(BigInt& z, const word x_words[], size_t x_size, secure_vector<word>& ws) const override;

   private:
      // Curve parameters
      BigInt m_1;
      BigInt m_a, m_b;
      size_t m_p_bits;   // cache of m_p.bits()
      size_t m_p_words;  // cache of m_p.sig_words()
};

BigInt CurveGFp_NIST::invert_element(const BigInt& x, secure_vector<word>& ws) const {
   BOTAN_UNUSED(ws);
   return inverse_mod(x, get_p());
}

void CurveGFp_NIST::curve_mul_words(
   BigInt& z, const word x_w[], size_t x_size, const BigInt& y, secure_vector<word>& ws) const {
   BOTAN_DEBUG_ASSERT(y.sig_words() <= m_p_words);

   if(ws.size() < get_ws_size()) {
      ws.resize(get_ws_size());
   }

   const size_t output_size = 2 * m_p_words;
   if(z.size() < output_size) {
      z.grow_to(output_size);
   }

   bigint_mul(z.mutable_data(),
              z.size(),
              x_w,
              x_size,
              std::min(m_p_words, x_size),
              y._data(),
              y.size(),
              std::min(m_p_words, y.size()),
              ws.data(),
              ws.size());

   this->redc_mod_p(z, ws);
}

void CurveGFp_NIST::curve_sqr_words(BigInt& z, const word x[], size_t x_size, secure_vector<word>& ws) const {
   if(ws.size() < get_ws_size()) {
      ws.resize(get_ws_size());
   }

   const size_t output_size = 2 * m_p_words;
   if(z.size() < output_size) {
      z.grow_to(output_size);
   }

   bigint_sqr(z.mutable_data(), output_size, x, x_size, std::min(m_p_words, x_size), ws.data(), ws.size());

   this->redc_mod_p(z, ws);
}

/**
* The NIST P-192 curve
*/
class CurveGFp_P192 final : public CurveGFp_NIST {
   public:
      CurveGFp_P192(const BigInt& a, const BigInt& b) : CurveGFp_NIST(192, a, b) {}

      const BigInt& get_p() const override { return prime_p192(); }

   private:
      void redc_mod_p(BigInt& x, secure_vector<word>& ws) const override { redc_p192(x, ws); }
};

/**
* The NIST P-224 curve
*/
class CurveGFp_P224 final : public CurveGFp_NIST {
   public:
      CurveGFp_P224(const BigInt& a, const BigInt& b) : CurveGFp_NIST(224, a, b) {}

      const BigInt& get_p() const override { return prime_p224(); }

   private:
      void redc_mod_p(BigInt& x, secure_vector<word>& ws) const override { redc_p224(x, ws); }
};

/**
* The NIST P-256 curve
*/
class CurveGFp_P256 final : public CurveGFp_NIST {
   public:
      CurveGFp_P256(const BigInt& a, const BigInt& b) : CurveGFp_NIST(256, a, b) {}

      const BigInt& get_p() const override { return prime_p256(); }

   private:
      void redc_mod_p(BigInt& x, secure_vector<word>& ws) const override { redc_p256(x, ws); }

      BigInt invert_element(const BigInt& x, secure_vector<word>& ws) const override;
};

BigInt CurveGFp_P256::invert_element(const BigInt& x, secure_vector<word>& ws) const {
   BigInt r, p2, p4, p8, p16, p32, tmp;

   curve_sqr(r, x, ws);

   curve_mul(p2, r, x, ws);
   curve_sqr(r, p2, ws);
   curve_sqr_tmp(r, tmp, ws);

   curve_mul(p4, r, p2, ws);

   curve_sqr(r, p4, ws);
   for(size_t i = 0; i != 3; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul(p8, r, p4, ws);

   curve_sqr(r, p8, ws);
   for(size_t i = 0; i != 7; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul(p16, r, p8, ws);

   curve_sqr(r, p16, ws);
   for(size_t i = 0; i != 15; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul(p32, r, p16, ws);

   curve_sqr(r, p32, ws);
   for(size_t i = 0; i != 31; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, x, tmp, ws);

   for(size_t i = 0; i != 32 * 4; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, p32, tmp, ws);

   for(size_t i = 0; i != 32; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, p32, tmp, ws);

   for(size_t i = 0; i != 16; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, p16, tmp, ws);
   for(size_t i = 0; i != 8; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, p8, tmp, ws);

   for(size_t i = 0; i != 4; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, p4, tmp, ws);

   for(size_t i = 0; i != 2; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, p2, tmp, ws);

   for(size_t i = 0; i != 2; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, x, tmp, ws);

   return r;
}

/**
* The NIST P-384 curve
*/
class CurveGFp_P384 final : public CurveGFp_NIST {
   public:
      CurveGFp_P384(const BigInt& a, const BigInt& b) : CurveGFp_NIST(384, a, b) {}

      const BigInt& get_p() const override { return prime_p384(); }

   private:
      void redc_mod_p(BigInt& x, secure_vector<word>& ws) const override { redc_p384(x, ws); }

      BigInt invert_element(const BigInt& x, secure_vector<word>& ws) const override;
};

BigInt CurveGFp_P384::invert_element(const BigInt& x, secure_vector<word>& ws) const {
   // From https://briansmith.org/ecc-inversion-addition-chains-01

   BigInt r, x2, x3, x15, x30, tmp, rl;

   r = x;
   curve_sqr_tmp(r, tmp, ws);
   curve_mul_tmp(r, x, tmp, ws);
   x2 = r;

   curve_sqr_tmp(r, tmp, ws);
   curve_mul_tmp(r, x, tmp, ws);

   x3 = r;

   for(size_t i = 0; i != 3; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, x3, tmp, ws);

   rl = r;
   for(size_t i = 0; i != 6; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, rl, tmp, ws);

   for(size_t i = 0; i != 3; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, x3, tmp, ws);

   x15 = r;
   for(size_t i = 0; i != 15; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, x15, tmp, ws);

   x30 = r;
   for(size_t i = 0; i != 30; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, x30, tmp, ws);

   rl = r;
   for(size_t i = 0; i != 60; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, rl, tmp, ws);

   rl = r;
   for(size_t i = 0; i != 120; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, rl, tmp, ws);

   for(size_t i = 0; i != 15; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, x15, tmp, ws);

   for(size_t i = 0; i != 31; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, x30, tmp, ws);

   for(size_t i = 0; i != 2; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, x2, tmp, ws);

   for(size_t i = 0; i != 94; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, x30, tmp, ws);

   for(size_t i = 0; i != 2; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }

   curve_mul_tmp(r, x, tmp, ws);

   return r;
}

/**
* The NIST P-521 curve
*/
class CurveGFp_P521 final : public CurveGFp_NIST {
   public:
      CurveGFp_P521(const BigInt& a, const BigInt& b) : CurveGFp_NIST(521, a, b) {}

      const BigInt& get_p() const override { return prime_p521(); }

   private:
      void redc_mod_p(BigInt& x, secure_vector<word>& ws) const override { redc_p521(x, ws); }

      BigInt invert_element(const BigInt& x, secure_vector<word>& ws) const override;
};

BigInt CurveGFp_P521::invert_element(const BigInt& x, secure_vector<word>& ws) const {
   // Addition chain from https://eprint.iacr.org/2014/852.pdf section

   BigInt r;
   BigInt rl;
   BigInt a7;
   BigInt tmp;

   curve_sqr(r, x, ws);
   curve_mul_tmp(r, x, tmp, ws);

   curve_sqr_tmp(r, tmp, ws);
   curve_mul_tmp(r, x, tmp, ws);

   rl = r;

   for(size_t i = 0; i != 3; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, rl, tmp, ws);

   curve_sqr_tmp(r, tmp, ws);
   curve_mul_tmp(r, x, tmp, ws);
   a7 = r;  // need this value later

   curve_sqr_tmp(r, tmp, ws);
   curve_mul_tmp(r, x, tmp, ws);

   rl = r;
   for(size_t i = 0; i != 8; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, rl, tmp, ws);

   rl = r;
   for(size_t i = 0; i != 16; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, rl, tmp, ws);

   rl = r;
   for(size_t i = 0; i != 32; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, rl, tmp, ws);

   rl = r;
   for(size_t i = 0; i != 64; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, rl, tmp, ws);

   rl = r;
   for(size_t i = 0; i != 128; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, rl, tmp, ws);

   rl = r;
   for(size_t i = 0; i != 256; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, rl, tmp, ws);

   for(size_t i = 0; i != 7; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, a7, tmp, ws);

   for(size_t i = 0; i != 2; ++i) {
      curve_sqr_tmp(r, tmp, ws);
   }
   curve_mul_tmp(r, x, tmp, ws);

   return r;
}

}  // namespace

std::shared_ptr<CurveGFp_Repr> CurveGFp::choose_repr(const BigInt& p, const BigInt& a, const BigInt& b) {
   if(p == prime_p192() && p == a + 3) {
      return std::make_shared<CurveGFp_P192>(a, b);
   }
   if(p == prime_p224() && p == a + 3) {
      return std::make_shared<CurveGFp_P224>(a, b);
   }
   if(p == prime_p256() && p == a + 3) {
      return std::make_shared<CurveGFp_P256>(a, b);
   }
   if(p == prime_p384() && p == a + 3) {
      return std::make_shared<CurveGFp_P384>(a, b);
   }
   if(p == prime_p521() && p == a + 3) {
      return std::make_shared<CurveGFp_P521>(a, b);
   }

   return std::make_shared<CurveGFp_Montgomery>(p, a, b);
}

}  // namespace Botan
