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

}  // namespace

std::shared_ptr<CurveGFp_Repr> CurveGFp::choose_repr(const BigInt& p, const BigInt& a, const BigInt& b) {
   return std::make_shared<CurveGFp_Montgomery>(p, a, b);
}

}  // namespace Botan
