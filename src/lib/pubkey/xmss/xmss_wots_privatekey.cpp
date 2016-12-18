/*
 * XMSS WOTS Private Key
 * A Winternitz One Time Signature private key for use with Extended Hash-Based
 * Signatures.
 *
 * (C) 2016 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmss_wots_signature_operation.h>
#include <botan/xmss_wots_privatekey.h>

namespace Botan {

wots_keysig_t
XMSS_WOTS_PrivateKey::generate(const secure_vector<uint8_t>& priv_seed)
   {
   wots_keysig_t priv_key(m_wots_params.len(),
                          secure_vector<uint8_t>(0));

   for(size_t i = 0; i < m_wots_params.len(); i++)
      {
      XMSS_Tools::concat<size_t>(priv_key[i], i, 32);
      m_hash.prf(priv_key[i], priv_seed, priv_key[i]);
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
      XMSS_Address& adrs)
   {
   BOTAN_ASSERT(wots_parameters() == pub_key.wots_parameters() &&
                public_seed() == pub_key.public_seed(),
                "Conflicting public key data.");

   pub_key.set_key_data(std::move(in_key_data));
   for(size_t i = 0; i < m_wots_params.len(); i++)
      {
      adrs.set_chain_address(i);
      chain(pub_key[i], 0, m_wots_params.wots_parameter() - 1, adrs,
            public_seed());
      }
   }

wots_keysig_t
XMSS_WOTS_PrivateKey::sign(
   const secure_vector<uint8_t>& msg,
   XMSS_Address& adrs)

   {
   secure_vector<uint8_t> msg_digest
      {
      m_wots_params.base_w(msg, m_wots_params.len_1())
      };

   m_wots_params.append_checksum(msg_digest);
   wots_keysig_t sig((*this)[adrs]);

   for(size_t i = 0; i < m_wots_params.len(); i++)
      {
      adrs.set_chain_address(i);
      chain(sig[i], 0 , msg_digest[i], adrs, m_public_seed);
      }

   return sig;
   }

std::unique_ptr<PK_Ops::Signature>
XMSS_WOTS_PrivateKey::create_signature_op(RandomNumberGenerator&,
                                          const std::string&,
                                          const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::Signature>(
           new XMSS_WOTS_Signature_Operation(*this));

   throw Provider_Not_Found(algo_name(), provider);
   }

}
