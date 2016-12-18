/**
 * XMSS WOTS Common Ops
 * Operations shared by XMSS WOTS signature generation and verification
 * operations.
 *
 * (C) 2016 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmss_wots_common_ops.h>

namespace Botan {

void
XMSS_WOTS_Common_Ops::chain(secure_vector<uint8_t>& result,
                            size_t start_idx,
                            size_t steps,
                            XMSS_Address& adrs,
                            const secure_vector<uint8_t>& seed)
   {
   for(size_t i = start_idx;
         i < (start_idx + steps) && i < m_wots_params.wots_parameter();
         i++)
      {
      adrs.set_hash_address(i);

      //Calculate tmp XOR bitmask
      adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Mask_Mode);
      xor_buf(result, m_hash.prf(seed, adrs.bytes()), result.size());

      // Calculate key
      adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Key_Mode);

      //Calculate f(key, tmp XOR bitmask)
      m_hash.f(result, m_hash.prf(seed, adrs.bytes()), result);
      }
   }

}
