/*
 * XMSS WOTS Private Key
 * A Winternitz One Time Signature private key for use with Extended Hash-Based
 * Signatures.
 *
 * (C) 2016,2017 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/xmss_wots.h>
#include <botan/internal/xmss_tools.h>
#include <botan/internal/xmss_address.h>

namespace Botan {

wots_keysig_t
XMSS_WOTS_PrivateKey::generate(const secure_vector<uint8_t>& priv_seed,
                               XMSS_Hash& hash)
   {
   wots_keysig_t priv_key(m_wots_params.len(),
                          secure_vector<uint8_t>(0));

   for(size_t i = 0; i < m_wots_params.len(); i++)
      {
      XMSS_Tools::concat<size_t>(priv_key[i], i, 32);
      hash.prf(priv_key[i], priv_seed, priv_key[i]);
      }
   return priv_key;
   }


XMSS_WOTS_PublicKey
XMSS_WOTS_PrivateKey::generate_public_key(XMSS_Address& adrs)
   {
   XMSS_WOTS_PublicKey pub_key(m_wots_params.oid(),
                               public_seed());
   generate_public_key(pub_key, wots_keysig_t((*this)[adrs]), adrs);
   return pub_key;
   }

void
XMSS_WOTS_PrivateKey::generate_public_key(XMSS_WOTS_PublicKey& pub_key,
                                          wots_keysig_t&& in_key_data,
                                          XMSS_Address& adrs,
                                          XMSS_Hash& hash)
   {
   BOTAN_ASSERT(wots_parameters() == pub_key.wots_parameters() &&
                public_seed() == pub_key.public_seed(),
                "Conflicting public key data.");

   pub_key.set_key_data(std::move(in_key_data));
   for(size_t i = 0; i < m_wots_params.len(); i++)
      {
      adrs.set_chain_address(static_cast<uint32_t>(i));
      chain(pub_key[i], 0, m_wots_params.wots_parameter() - 1, adrs,
            public_seed(), hash);
      }
   }

wots_keysig_t
XMSS_WOTS_PrivateKey::sign(const secure_vector<uint8_t>& msg,
                           XMSS_Address& adrs,
                           XMSS_Hash& hash)

   {
   secure_vector<uint8_t> msg_digest
      {
      m_wots_params.base_w(msg, m_wots_params.len_1())
      };

   m_wots_params.append_checksum(msg_digest);
   wots_keysig_t sig(this->at(adrs, hash));

   for(size_t i = 0; i < m_wots_params.len(); i++)
      {
      adrs.set_chain_address(static_cast<uint32_t>(i));
      chain(sig[i], 0 , msg_digest[i], adrs, m_public_seed, hash);
      }

   return sig;
   }

wots_keysig_t XMSS_WOTS_PrivateKey::at(const XMSS_Address& adrs, XMSS_Hash& hash)
   {
   secure_vector<uint8_t> result;
   hash.prf(result, m_private_seed, adrs.bytes());
   return generate(result, hash);
   }

wots_keysig_t XMSS_WOTS_PrivateKey::at(size_t i, XMSS_Hash& hash)
   {
   secure_vector<uint8_t> idx_bytes;
   XMSS_Tools::concat(idx_bytes, i, m_wots_params.element_size());
   hash.h(idx_bytes, m_private_seed, idx_bytes);
   return generate(idx_bytes, hash);
   }

}
