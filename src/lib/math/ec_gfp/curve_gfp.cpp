/*
* Elliptic curves over GF(p) Montgomery Representation
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/curve_gfp.h>
#include <botan/internal/curve_nistp.h>
#include <botan/internal/mp_core.h>

namespace Botan {

namespace {

class CurveGFp_Montgomery : public CurveGFp_Repr
   {
   public:
      CurveGFp_Montgomery(const BigInt& p, const BigInt& a, const BigInt& b) :
         m_p(p), m_a(a), m_b(b),
         m_p_words(m_p.sig_words()),
         m_p_dash(monty_inverse(m_p.word_at(0)))
         {
         const BigInt r = BigInt::power_of_2(m_p_words * BOTAN_MP_WORD_BITS);

         m_r2  = (r * r) % p;
         m_a_r = (m_a * r) % p;
         m_b_r = (m_b * r) % p;
         }

      const BigInt& get_a() const override { return m_a; }

      const BigInt& get_b() const override { return m_b; }

      const BigInt& get_p() const override { return m_p; }

      const BigInt& get_a_rep() const override { return m_a_r; }

      const BigInt& get_b_rep() const override { return m_b_r; }

      size_t get_p_words() const override { return m_p_words; }

      void to_curve_rep(BigInt& x, secure_vector<word>& ws) const override;

      void from_curve_rep(BigInt& x, secure_vector<word>& ws) const override;

      void curve_mul(BigInt& z, const BigInt& x, const BigInt& y,
                     secure_vector<word>& ws) const override;

      void curve_sqr(BigInt& z, const BigInt& x,
                     secure_vector<word>& ws) const override;
   private:
      BigInt m_p, m_a, m_b;
      size_t m_p_words; // cache of m_p.sig_words()

      // Montgomery parameters
      BigInt m_r2, m_a_r, m_b_r;
      word m_p_dash;
   };

void CurveGFp_Montgomery::to_curve_rep(BigInt& x, secure_vector<word>& ws) const
   {
   const BigInt tx = x;
   curve_mul(x, tx, m_r2, ws);
   }

void CurveGFp_Montgomery::from_curve_rep(BigInt& x, secure_vector<word>& ws) const
   {
   const BigInt tx = x;
   curve_mul(x, tx, 1, ws);
   }

void CurveGFp_Montgomery::curve_mul(BigInt& z, const BigInt& x, const BigInt& y,
                                    secure_vector<word>& ws) const
   {
   if(x.is_zero() || y.is_zero())
      {
      z = 0;
      return;
      }

   const size_t output_size = 2*m_p_words + 1;
   ws.resize(2*(m_p_words+2));

   z.grow_to(output_size);
   z.clear();

   bigint_monty_mul(z.mutable_data(), output_size,
                    x.data(), x.size(), x.sig_words(),
                    y.data(), y.size(), y.sig_words(),
                    m_p.data(), m_p_words, m_p_dash,
                    ws.data());
   }

void CurveGFp_Montgomery::curve_sqr(BigInt& z, const BigInt& x,
                                    secure_vector<word>& ws) const
   {
   if(x.is_zero())
      {
      z = 0;
      return;
      }

   const size_t output_size = 2*m_p_words + 1;

   ws.resize(2*(m_p_words+2));

   z.grow_to(output_size);
   z.clear();

   bigint_monty_sqr(z.mutable_data(), output_size,
                    x.data(), x.size(), x.sig_words(),
                    m_p.data(), m_p_words, m_p_dash,
                    ws.data());
   }

}

// Default implementation
void CurveGFp_Repr::normalize(BigInt& x, secure_vector<word>& ws, size_t /*bound*/) const
   {
   const BigInt& p = get_p();

   while(x.is_negative())
      x += p;

   const size_t p_words = get_p_words();
   const word* prime = p.data();

   x.grow_to(p_words + 1);

   if(ws.size() < p_words + 1)
      ws.resize(p_words + 1);

   //FIXME: take into account bound if > 0
   while(true)
      {
      if(bigint_sub3(ws.data(), x.data(), p_words, prime, p_words)) // borrow?
         break;

      x.swap_reg(ws);
      }
   }

std::shared_ptr<CurveGFp_Repr>
CurveGFp::choose_repr(const BigInt& p, const BigInt& a, const BigInt& b)
   {
   if(p == CurveGFp_P521::prime())
      return std::shared_ptr<CurveGFp_Repr>(new CurveGFp_P521(a, b));

   return std::shared_ptr<CurveGFp_Repr>(new CurveGFp_Montgomery(p, a, b));
   }

}
