/*
 * XMSS Common Ops
 * Operations shared by XMSS signature generation and verification operations.
 * (C) 2016,2017 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmss_common_ops.h>

#include <botan/internal/xmss_hash.h>

namespace Botan {

void XMSS_Common_Ops::randomize_tree_hash(secure_vector<uint8_t>& result,
                                          const secure_vector<uint8_t>& left,
                                          const secure_vector<uint8_t>& right,
                                          XMSS_Address& adrs,
                                          const secure_vector<uint8_t>& seed,
                                          XMSS_Hash& hash,
                                          const XMSS_Parameters& params) {
   adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Key_Mode);
   secure_vector<uint8_t> key;
   hash.prf(key, seed, adrs.bytes());

   adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Mask_MSB_Mode);
   secure_vector<uint8_t> bitmask_l;
   hash.prf(bitmask_l, seed, adrs.bytes());

   adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Mask_LSB_Mode);
   secure_vector<uint8_t> bitmask_r;
   hash.prf(bitmask_r, seed, adrs.bytes());

   BOTAN_ASSERT(bitmask_l.size() == left.size() && bitmask_r.size() == right.size(),
                "Bitmask size doesn't match node size.");

   secure_vector<uint8_t> concat_xor(params.element_size() * 2);
   for(size_t i = 0; i < left.size(); i++) {
      concat_xor[i] = left[i] ^ bitmask_l[i];
      concat_xor[i + left.size()] = right[i] ^ bitmask_r[i];
   }

   hash.h(result, key, concat_xor);
}

void XMSS_Common_Ops::create_l_tree(secure_vector<uint8_t>& result,
                                    wots_keysig_t pk,
                                    XMSS_Address& adrs,
                                    const secure_vector<uint8_t>& seed,
                                    XMSS_Hash& hash,
                                    const XMSS_Parameters& params) {
   size_t l = params.len();
   adrs.set_tree_height(0);

   while(l > 1) {
      for(size_t i = 0; i < l >> 1; i++) {
         adrs.set_tree_index(static_cast<uint32_t>(i));
         randomize_tree_hash(pk[i], pk[2 * i], pk[2 * i + 1], adrs, seed, hash, params);
      }
      if(l & 0x01) {
         pk[l >> 1] = pk[l - 1];
      }
      l = (l >> 1) + (l & 0x01);
      adrs.set_tree_height(adrs.get_tree_height() + 1);
   }
   result = pk[0];
}

}  // namespace Botan
