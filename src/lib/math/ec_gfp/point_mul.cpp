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
   std::vector<BigInt> ws(9);
   init(base, w, ws);
   }

#define USE_RANDOM_MONTY_WALK 0

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

   #if USE_RANDOM_MONTY_WALK
   const PointGFp inv = -base;

   m_U.resize(6*m_h + 3);

   m_U[3*m_h+0] = inv;
   m_U[3*m_h+1] = base.zero();
   m_U[3*m_h+2] = base;

   for(size_t i = 1; i <= 3 * m_h + 1; ++i)
      {
      m_U[3*m_h+1+i] = m_U[3*m_h+i];
      m_U[3*m_h+1+i].add(base, ws);

      m_U[3*m_h+1-i] = m_U[3*m_h+2-i];
      m_U[3*m_h+1-i].add(inv, ws);
      }
   #else

   m_U.resize(1 << m_h);
   m_U[0] = base.zero();
   m_U[1] = base;

   for(size_t i = 2; i < m_U.size(); ++i)
      {
      m_U[i] = m_U[i-1];
      m_U[i].add(base, ws);
      }

   #endif
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

#if USE_RANDOM_MONTY_WALK
   const size_t w = (m_U.size() - 3) / 6;

   PointGFp R = m_U.at(3*w + 2); // base point
   int32_t alpha = 0;

   R.randomize_repr(rng);

   /*
   Algorithm 7 from "Randomizing the Montgomery Powering Ladder"
   Duc-Phong Le, Chik How Tan and Michael Tunstall
   https://eprint.iacr.org/2015/657

   It takes a random walk through (a subset of) the set of addition
   chains that end in k.
   */
   for(size_t i = scalar_bits; i > 0; i--)
      {
      const int32_t ki = scalar.get_bit(i);

      // choose gamma from -h,...,h
      const int32_t gamma = static_cast<int32_t>((rng.next_byte() % (2*w))) - w;
      const int32_t l = gamma - 2*alpha + ki - (ki ^ 1);

      R.mult2(ws);
      R.add(m_U.at(3*w + 1 + l), ws);
      alpha = gamma;
      }

   const int32_t k0 = scalar.get_bit(0);
   R.add(m_U[3*w + 1 - alpha - (k0 ^ 1)], ws);

   #else

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


   #endif

   //BOTAN_ASSERT(R.on_the_curve(), "Output is on the curve");

   return R;
   }

}
