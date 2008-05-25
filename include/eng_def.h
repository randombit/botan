/*************************************************
* Default Engine Header File                     *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_DEFAULT_ENGINE_H__
#define BOTAN_DEFAULT_ENGINE_H__

#include <botan/pointers.h>

#include <botan/engine.h>

namespace Botan {

/*************************************************
* Default Engine                                 *
*************************************************/
class Default_Engine : public Engine
   {
   public:
      std::tr1::shared_ptr<IF_Operation>
		  if_op(const BigInt&, const BigInt&, const BigInt&,
               const BigInt&, const BigInt&, const BigInt&,
               const BigInt&, const BigInt&) const;

      std::tr1::shared_ptr<DSA_Operation>
         dsa_op(const DL_Group&, const BigInt&, const BigInt&) const;
      
      std::tr1::shared_ptr<ECDSA_Operation>
         ecdsa_op(EC_Domain_Params const& dom_pars, BigInt const& priv_key, Botan::math::ec::PointGFp const& pub_key) const;
      
      std::tr1::shared_ptr<ECKAEG_Operation>
         eckaeg_op(EC_Domain_Params const& dom_pars, BigInt const& priv_key, Botan::math::ec::PointGFp const& pub_key) const;

      std::tr1::shared_ptr<DH_Operation>
         dh_op(const DL_Group&, const BigInt&) const;

      std::auto_ptr<Modular_Exponentiator>
         mod_exp(const BigInt&, Power_Mod::Usage_Hints) const;

      std::tr1::shared_ptr<Keyed_Filter>
         get_cipher(const std::string&, Cipher_Dir);

   private:
      std::tr1::shared_ptr<BlockCipher>
         find_block_cipher(const std::string&) const;

      std::tr1::shared_ptr<StreamCipher>
         find_stream_cipher(const std::string&) const;
      
      std::tr1::shared_ptr<HashFunction>
        find_hash(const std::string&) const;

      std::tr1::shared_ptr<MessageAuthenticationCode>
         find_mac(const std::string&) const;

      std::tr1::shared_ptr<class S2K>
         find_s2k(const std::string&) const;
      
      std::tr1::shared_ptr<class BlockCipherModePaddingMethod>
         find_bc_pad(const std::string&) const;
   };

}

#endif
