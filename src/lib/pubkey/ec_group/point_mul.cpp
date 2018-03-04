/*
* (C) 2015,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/point_gfp.h>
#include <botan/rng.h>
#include <botan/internal/rounding.h>

namespace Botan {

PointGFp_Blinded_Multiplier::PointGFp_Blinded_Multiplier(const PointGFp& base,
                                                         std::vector<BigInt>& ws,
                                                         size_t w)
   {
   init(base, w, ws);
   }

PointGFp_Blinded_Multiplier::PointGFp_Blinded_Multiplier(const PointGFp& base,
                                                         size_t w)
   {
   std::vector<BigInt> ws(PointGFp::WORKSPACE_SIZE);
   init(base, w, ws);
   }

void PointGFp_Blinded_Multiplier::init(const PointGFp& base,
                                       size_t w,
                                       std::vector<BigInt>& ws)
   {
   m_h = (w == 0 ? 5 : w);

   if(ws.size() < PointGFp::WORKSPACE_SIZE)
      ws.resize(PointGFp::WORKSPACE_SIZE);

   // Upper bound is a sanity check rather than hard limit
   if(m_h < 1 || m_h > 8)
      throw Invalid_Argument("PointGFp_Blinded_Multiplier invalid w param");

   m_U.resize(1 << m_h);
   m_U[0] = base.zero();
   m_U[1] = base;

   for(size_t i = 2; i < m_U.size(); ++i)
      {
      m_U[i] = m_U[i-1];
      m_U[i].add(base, ws);
      }
   }

void PointGFp_Blinded_Multiplier::randomize(RandomNumberGenerator& rng)
   {
   // Randomize each point representation (Coron's 3rd countermeasure)
   for(size_t i = 0; i != m_U.size(); ++i)
      m_U[i].randomize_repr(rng);
   }

PointGFp PointGFp_Blinded_Multiplier::mul(const BigInt& k,
                                          const BigInt& group_order,
                                          RandomNumberGenerator& rng,
                                          std::vector<BigInt>& ws) const
   {
   if(k.is_negative())
      throw Invalid_Argument("PointGFp_Blinded_Multiplier scalar must be positive");

#if BOTAN_POINTGFP_USE_SCALAR_BLINDING
   // Choose a small mask m and use k' = k + m*order (Coron's 1st countermeasure)
   const BigInt mask(rng, group_order.bits() / 4, false);
   const BigInt scalar = k + group_order * mask;
#else
   const BigInt& scalar = k;
#endif

   if(ws.size() < PointGFp::WORKSPACE_SIZE)
      ws.resize(PointGFp::WORKSPACE_SIZE);

   const size_t scalar_bits = scalar.bits();

   size_t windows = round_up(scalar_bits, m_h) / m_h;

   PointGFp R = m_U[0];

   if(windows > 0)
      {
      windows--;
      const uint32_t nibble = scalar.get_substring(windows*m_h, m_h);
      R.add(m_U[nibble], ws);

      /*
      Randomize after adding the first nibble as before the addition R
      is zero, and we cannot effectively randomize the point
      representation of the zero point.
      */
      R.randomize_repr(rng);

      while(windows)
         {
         for(size_t i = 0; i != m_h; ++i)
            R.mult2(ws);

         const uint32_t inner_nibble = scalar.get_substring((windows-1)*m_h, m_h);
         // cache side channel here, we are relying on blinding...
         R.add(m_U[inner_nibble], ws);
         windows--;
         }
      }

   //BOTAN_ASSERT(R.on_the_curve(), "Output is on the curve");

   return R;
   }

}
