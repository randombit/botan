/*
* ECKAEG
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*          Manuel Hartl, FlexSecure GmbH
* (C) 2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ECKAEG_KEY_H__
#define BOTAN_ECKAEG_KEY_H__

#include <botan/ecc_key.h>
#include <botan/eckaeg_core.h>

namespace Botan {

/**
* This class represents ECKAEG Public Keys.
*/
class BOTAN_DLL ECKAEG_PublicKey : public virtual EC_PublicKey
   {
   public:

      /**
      * Default constructor. Use this one if you want to later fill
      * this object with data from an encoded key.
      */
      ECKAEG_PublicKey() {}

      /**
      * Construct a public key from a given public point.
      * @param dom_par the domain parameters associated with this key
      * @param public_point the public point defining this key
      */
      ECKAEG_PublicKey(const EC_Domain_Params& dom_par,
                       const PointGFp& public_point);

      /**
      * Get this keys algorithm name.
      * @result this keys algorithm name
      */
      std::string algo_name() const { return "ECKAEG"; }

      /**
      * Get the maximum number of bits allowed to be fed to this key.
      * This is the bitlength of the order of the base point.

      * @result the maximum number of input bits
      */
      u32bit max_input_bits() const
         {
         if(!mp_dom_pars.get())
            throw Invalid_State("ECKAEG_PublicKey::max_input_bits(): domain parameters not set");

         return mp_dom_pars->get_order().bits();
         }

      ECKAEG_PublicKey(ECKAEG_PublicKey const& other);
      ECKAEG_PublicKey const& operator= (ECKAEG_PublicKey const& rhs);

      /**
      * Make sure that the public point and domain parameters of this
      * key are set.
      * @throw Invalid_State if either of the two data members is not set
      */
      virtual void affirm_init() const;

   protected:
      void X509_load_hook();
      virtual void set_all_values(const ECKAEG_PublicKey& other);

      ECKAEG_Core m_eckaeg_core;
   };

/**
* This class represents ECKAEG Private Keys.
*/
class BOTAN_DLL ECKAEG_PrivateKey : public ECKAEG_PublicKey,
                                    public EC_PrivateKey,
                                    public PK_Key_Agreement_Key
   {
   public:

      /**
      * Generate a new private key
      * @param the domain parameters to used for this key
      */
      ECKAEG_PrivateKey(RandomNumberGenerator& rng,
                        const EC_Domain_Params& dom_pars)
         {
         mp_dom_pars = std::auto_ptr<EC_Domain_Params>(new EC_Domain_Params(dom_pars));
         generate_private_key(rng);
         mp_public_point->check_invariants();
         m_eckaeg_core = ECKAEG_Core(*mp_dom_pars, m_private_value, *mp_public_point);
         }

      /**
      * Default constructor. Use this one if you want to later fill this object with data
      * from an encoded key.
      */
      ECKAEG_PrivateKey() {}
      ECKAEG_PrivateKey(ECKAEG_PrivateKey const& other);
      ECKAEG_PrivateKey const& operator=(ECKAEG_PrivateKey const& rhs);

      MemoryVector<byte> public_value() const;

      void PKCS8_load_hook(bool = false);

      /**
      * Derive a shared key with the other partys public key.
      * @param key the other partys public key
      * @param key_len the other partys public key
      */
      SecureVector<byte> derive_key(const byte key[], u32bit key_len) const;

      /**
      * Derive a shared key with the other partys public key.
      * @param other the other partys public key
      */
      SecureVector<byte> derive_key(const ECKAEG_PublicKey& other) const;

      /**
      * Make sure that the public key parts of this object are set
      * (calls EC_PublicKey::affirm_init()) as well as the private key
      * value.
      * @throw Invalid_State if the above conditions are not satisfied
      */
      virtual void affirm_init() const;

   protected:
      virtual void set_all_values(const ECKAEG_PrivateKey& other);
   };

}

#endif
