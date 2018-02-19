/*
* DL Scheme
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/dl_algo.h>
#include <botan/numthry.h>
#include <botan/workfactor.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>

namespace Botan {

size_t DL_Scheme_PublicKey::key_length() const
   {
   return m_group.get_p().bits();
   }

size_t DL_Scheme_PublicKey::estimated_strength() const
   {
   return dl_work_factor(key_length());
   }

AlgorithmIdentifier DL_Scheme_PublicKey::algorithm_identifier() const
   {
   return AlgorithmIdentifier(get_oid(),
                              m_group.DER_encode(group_format()));
   }

std::vector<uint8_t> DL_Scheme_PublicKey::public_key_bits() const
   {
   return DER_Encoder().encode(m_y).get_contents_unlocked();
   }

DL_Scheme_PublicKey::DL_Scheme_PublicKey(const DL_Group& group, const BigInt& y) :
   m_y(y),
   m_group(group)
   {
   }

DL_Scheme_PublicKey::DL_Scheme_PublicKey(const AlgorithmIdentifier& alg_id,
                                         const std::vector<uint8_t>& key_bits,
                                         DL_Group::Format format) :
   m_group(alg_id.get_parameters(), format)
   {
   BER_Decoder(key_bits).decode(m_y);
   }

secure_vector<uint8_t> DL_Scheme_PrivateKey::private_key_bits() const
   {
   return DER_Encoder().encode(m_x).get_contents();
   }

DL_Scheme_PrivateKey::DL_Scheme_PrivateKey(const AlgorithmIdentifier& alg_id,
                                           const secure_vector<uint8_t>& key_bits,
                                           DL_Group::Format format)
   {
   m_group.BER_decode(alg_id.get_parameters(), format);

   BER_Decoder(key_bits).decode(m_x);
   }

/*
* Check Public DL Parameters
*/
bool DL_Scheme_PublicKey::check_key(RandomNumberGenerator& rng,
                                    bool strong) const
   {
   const BigInt& p = group_p();

   if(m_y < 2 || m_y >= p)
      return false;
   if(!m_group.verify_group(rng, strong))
      return false;

   try
      {
      const BigInt& q = group_q();
      if(power_mod(m_y, q, p) != 1)
         return false;
      }
   catch(const Invalid_State&)
      {
      return true;
      }

   return true;
   }

/*
* Check DL Scheme Private Parameters
*/
bool DL_Scheme_PrivateKey::check_key(RandomNumberGenerator& rng,
                                     bool strong) const
   {
   const BigInt& p = group_p();

   if(m_y < 2 || m_y >= p || m_x < 2 || m_x >= p)
      return false;
   if(!m_group.verify_group(rng, strong))
      return false;

   if(!strong)
      return true;

   if(m_y != m_group.power_g_p(m_x))
      return false;

   return true;
   }

}
