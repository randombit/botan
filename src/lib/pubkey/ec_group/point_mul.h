/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_POINT_MUL_H_
#define BOTAN_POINT_MUL_H_

#include <botan/point_gfp.h>

namespace Botan {

static const size_t PointGFp_SCALAR_BLINDING_BITS = 80;

class PointGFp_Base_Point_Precompute
   {
   public:
      PointGFp_Base_Point_Precompute(const PointGFp& base_point);

      PointGFp mul(const BigInt& k,
                   RandomNumberGenerator& rng,
                   const BigInt& group_order,
                   std::vector<BigInt>& ws) const;
   private:
      size_t m_T_bits;
      std::vector<PointGFp> m_T;
   };

class PointGFp_Var_Point_Precompute
   {
   public:
      PointGFp_Var_Point_Precompute(const PointGFp& point);

      void randomize_repr(RandomNumberGenerator& rng);

      PointGFp mul(const BigInt& k,
                   RandomNumberGenerator& rng,
                   const BigInt& group_order,
                   std::vector<BigInt>& ws) const;
   private:
      size_t m_window_bits;
      std::vector<PointGFp> m_U;
   };

}

#endif
