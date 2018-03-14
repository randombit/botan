/*
* (C) 2015,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/point_mul.h>
#include <botan/rng.h>
#include <botan/internal/rounding.h>

namespace Botan {

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
   const size_t T_bits = p_bits + PointGFp_SCALAR_BLINDING_BITS + 1;

   m_T.push_back(base);

   for(size_t i = 1; i != T_bits; ++i)
      {
      m_T.push_back(m_T[i-1]);
      m_T[i].mult2(ws);
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

   const size_t scalar_bits = scalar.bits();

   BOTAN_ASSERT(scalar_bits <= m_T.size(),
                "Precomputed sufficient values for scalar mult");

   PointGFp R = m_T[0].zero();

   if(ws.size() < PointGFp::WORKSPACE_SIZE)
      ws.resize(PointGFp::WORKSPACE_SIZE);

   for(size_t i = 0; i != scalar_bits; ++i)
      {
      //if(i % 4 == 3)
      if(i == 4)
         {
         R.randomize_repr(rng, ws[0].get_word_vector());
         }

      if(scalar.get_bit(i))
         R.add_affine(m_T[i], ws);
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

}
