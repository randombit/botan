/*
* (C) 2015,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/point_mul.h>
#include <botan/rng.h>
#include <botan/internal/rounding.h>

namespace Botan {

PointGFp multi_exponentiate(const PointGFp& x, const BigInt& z1,
                            const PointGFp& y, const BigInt& z2)
   {
   PointGFp_Multi_Point_Precompute xy_mul(x, y);
   return xy_mul.multi_exp(z1, z2);
   }

Blinded_Point_Multiply::Blinded_Point_Multiply(const PointGFp& base,
                                               const BigInt& order,
                                               size_t h) :
   m_ws(PointGFp::WORKSPACE_SIZE),
   m_order(order)
   {
   BOTAN_UNUSED(h);
   m_point_mul.reset(new PointGFp_Var_Point_Precompute(base));
   }

Blinded_Point_Multiply::~Blinded_Point_Multiply()
   {
   /* for ~unique_ptr */
   }

PointGFp Blinded_Point_Multiply::blinded_multiply(const BigInt& scalar,
                                                  RandomNumberGenerator& rng)
   {
   return m_point_mul->mul(scalar, rng, m_order, m_ws);
   }


PointGFp_Base_Point_Precompute::PointGFp_Base_Point_Precompute(const PointGFp& base)
   {
   std::vector<BigInt> ws(PointGFp::WORKSPACE_SIZE);

   const size_t p_bits = base.get_curve().get_p().bits();

   /*
   * Some of the curves (eg secp160k1) have an order slightly larger than
   * the size of the prime modulus. In all cases they are at most 1 bit
   * longer. The +1 compensates for this.
   */
   const size_t T_bits = round_up(p_bits + PointGFp_SCALAR_BLINDING_BITS + 1, 2) / 2;

   m_T.resize(3*T_bits);

   m_T[0] = base;
   m_T[1] = m_T[0];
   m_T[1].mult2(ws);
   m_T[2] = m_T[1];
   m_T[2].add(m_T[0], ws);

   for(size_t i = 1; i != T_bits; ++i)
      {
      m_T[3*i+0] = m_T[3*i - 2];
      m_T[3*i+0].mult2(ws);
      m_T[3*i+1] = m_T[3*i+0];
      m_T[3*i+1].mult2(ws);
      m_T[3*i+2] = m_T[3*i+1];
      m_T[3*i+2].add(m_T[3*i+0], ws);
      }

   PointGFp::force_all_affine(m_T, ws[0].get_word_vector());
   }

PointGFp PointGFp_Base_Point_Precompute::mul(const BigInt& k,
                                             RandomNumberGenerator& rng,
                                             const BigInt& group_order,
                                             std::vector<BigInt>& ws) const
   {
   if(k.is_negative())
      throw Invalid_Argument("PointGFp_Base_Point_Precompute scalar must be positive");

   // Choose a small mask m and use k' = k + m*order (Coron's 1st countermeasure)
   const BigInt mask(rng, PointGFp_SCALAR_BLINDING_BITS, false);
   const BigInt scalar = k + group_order * mask;

   size_t windows = round_up(scalar.bits(), 2) / 2;

   BOTAN_ASSERT(windows <= m_T.size() / 3,
                "Precomputed sufficient values for scalar mult");

   if(ws.size() < PointGFp::WORKSPACE_SIZE)
      ws.resize(PointGFp::WORKSPACE_SIZE);

   PointGFp R = m_T[0].zero();

   for(size_t i = 0; i != windows; ++i)
      {
      if(i == 4)
         {
         R.randomize_repr(rng, ws[0].get_word_vector());
         }

      const uint32_t w = scalar.get_substring(2*i, 2);

      if(w > 0)
         R.add_affine(m_T[3*i + w - 1], ws);
      }

   BOTAN_DEBUG_ASSERT(R.on_the_curve());

   return R;
   }

PointGFp_Var_Point_Precompute::PointGFp_Var_Point_Precompute(const PointGFp& point)
   {
   m_window_bits = 4;

   m_U.resize(1U << m_window_bits);
   m_U[0] = point.zero();
   m_U[1] = point;

   std::vector<BigInt> ws(PointGFp::WORKSPACE_SIZE);
   for(size_t i = 2; i < m_U.size(); ++i)
      {
      m_U[i] = m_U[i-1];
      m_U[i].add(point, ws);
      }
   }

void PointGFp_Var_Point_Precompute::randomize_repr(RandomNumberGenerator& rng)
   {
   for(size_t i = 1; i != m_U.size(); ++i)
      m_U[i].randomize_repr(rng);
   }

PointGFp PointGFp_Var_Point_Precompute::mul(const BigInt& k,
                                            RandomNumberGenerator& rng,
                                            const BigInt& group_order,
                                            std::vector<BigInt>& ws) const
   {
   if(k.is_negative())
      throw Invalid_Argument("PointGFp_Base_Point_Precompute scalar must be positive");
   if(ws.size() < PointGFp::WORKSPACE_SIZE)
      ws.resize(PointGFp::WORKSPACE_SIZE);

   // Choose a small mask m and use k' = k + m*order (Coron's 1st countermeasure)
   const BigInt mask(rng, PointGFp_SCALAR_BLINDING_BITS, false);
   const BigInt scalar = k + group_order * mask;

   const size_t scalar_bits = scalar.bits();

   size_t windows = round_up(scalar_bits, m_window_bits) / m_window_bits;

   PointGFp R = m_U[0];

   if(windows > 0)
      {
      windows--;
      const uint32_t nibble = scalar.get_substring(windows*m_window_bits, m_window_bits);
      R.add(m_U[nibble], ws);

      /*
      Randomize after adding the first nibble as before the addition R
      is zero, and we cannot effectively randomize the point
      representation of the zero point.
      */
      R.randomize_repr(rng);

      while(windows)
         {
         for(size_t i = 0; i != m_window_bits; ++i)
            R.mult2(ws);

         const uint32_t inner_nibble = scalar.get_substring((windows-1)*m_window_bits, m_window_bits);
         // cache side channel here, we are relying on blinding...
         R.add(m_U[inner_nibble], ws);
         windows--;
         }
      }

   BOTAN_DEBUG_ASSERT(R.on_the_curve());

   return R;
   }


PointGFp_Multi_Point_Precompute::PointGFp_Multi_Point_Precompute(const PointGFp& x,
                                                                 const PointGFp& y)
   {
   std::vector<BigInt> ws(PointGFp::WORKSPACE_SIZE);

   PointGFp x2 = x;
   x2.mult2(ws);

   const PointGFp x3(x2.plus(x, ws));

   PointGFp y2 = y;
   y2.mult2(ws);

   const PointGFp y3(y2.plus(y, ws));

   m_M.reserve(15);

   m_M.push_back(x);
   m_M.push_back(x2);
   m_M.push_back(x3);

   m_M.push_back(y);
   m_M.push_back(y.plus(x, ws));
   m_M.push_back(y.plus(x2, ws));
   m_M.push_back(y.plus(x3, ws));

   m_M.push_back(y2);
   m_M.push_back(y2.plus(x, ws));
   m_M.push_back(y2.plus(x2, ws));
   m_M.push_back(y2.plus(x3, ws));

   m_M.push_back(y3);
   m_M.push_back(y3.plus(x, ws));
   m_M.push_back(y3.plus(x2, ws));
   m_M.push_back(y3.plus(x3, ws));

   PointGFp::force_all_affine(m_M, ws[0].get_word_vector());
   }

PointGFp PointGFp_Multi_Point_Precompute::multi_exp(const BigInt& z1,
                                                    const BigInt& z2) const
   {
   std::vector<BigInt> ws(PointGFp::WORKSPACE_SIZE);

   const size_t z_bits = round_up(std::max(z1.bits(), z2.bits()), 2);

   PointGFp H = m_M[0].zero();

   for(size_t i = 0; i != z_bits; i += 2)
      {
      if(i > 0)
         {
         H.mult2(ws);
         H.mult2(ws);
         }

      const uint8_t z1_b = z1.get_substring(z_bits - i - 2, 2);
      const uint8_t z2_b = z2.get_substring(z_bits - i - 2, 2);

      const uint8_t z12 = (4*z2_b) + z1_b;

      if(z12)
         {
         H.add_affine(m_M[z12-1], ws);
         }
      }

   if(z1.is_negative() != z2.is_negative())
      H.negate();

   return H;
   }

}
