/*
 * XMSS Common Ops
 * Operations shared by XMSS signature generation and verification operations.
 * (C) 2016 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/xmss_common_ops.h>

namespace Botan {

void
XMSS_Common_Ops::randomize_tree_hash(secure_vector<byte>& result,
                                     const secure_vector<byte>& left,
                                     const secure_vector<byte>& right,
                                     XMSS_Address& adrs,
                                     const secure_vector<byte>& seed)
   {
   adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Key_Mode);
   secure_vector<byte> key { m_hash.prf(seed, adrs.bytes()) };

   adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Mask_MSB_Mode);
   secure_vector<byte> bitmask_l { m_hash.prf(seed, adrs.bytes()) };

   adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Mask_LSB_Mode);
   secure_vector<byte> bitmask_r { m_hash.prf(seed, adrs.bytes()) };

   BOTAN_ASSERT(bitmask_l.size() == left.size() &&
                bitmask_r.size() == right.size(),
                "Bitmask size doesn't match node size.");

   secure_vector<byte> concat_xor(m_xmss_params.element_size() * 2);
   for(size_t i = 0; i < left.size(); i++)
      {
      concat_xor[i] = left[i] ^ bitmask_l[i];
      concat_xor[i + left.size()] = right[i] ^ bitmask_r[i];
      }

   m_hash.h(result, key, concat_xor);
   }


void
XMSS_Common_Ops::create_l_tree(secure_vector<byte>& result,
                               wots_keysig_t pk,
                               XMSS_Address& adrs,
                               const secure_vector<byte>& seed)
   {
   size_t l = m_xmss_params.len();
   adrs.set_tree_height(0);

   while(l > 1)
      {
      for(size_t i = 0; i < l >> 1; i++)
         {
         adrs.set_tree_index(i);
         randomize_tree_hash(pk[i], pk[2 * i], pk[2 * i + 1], adrs, seed);
         }
      if(l & 0x01)
         {
         pk[l >> 1] = pk[l - 1];
         }
      l = (l >> 1) + (l & 0x01);
      adrs.set_tree_height(adrs.get_tree_height() + 1);
      }
   result = pk[0];
   }

}
