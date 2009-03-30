/*
* ECDSA
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*          Manuel Hartl, FlexSecure GmbH
* (C) 2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ECDSA_KEY_H__
#define BOTAN_ECDSA_KEY_H__

#include <botan/ecc_key.h>
#include <botan/ecdsa_core.h>

namespace Botan {

/**
* This class represents ECDSA Public Keys.
*/
class BOTAN_DLL ECDSA_PublicKey : public virtual EC_PublicKey,
                                  public PK_Verifying_wo_MR_Key
   {
   public:

      /**
      * Get this keys algorithm name.
      * @result this keys algorithm name ("ECDSA")
      */
      std::string algo_name() const { return "ECDSA"; }

      /**
      * Get the maximum number of bits allowed to be fed to this key.
      * This is the bitlength of the order of the base point.

      * @result the maximum number of input bits
      */
      u32bit max_input_bits() const;

      /**
      * Verify a message with this key.
      * @param message the byte array containing the message
      * @param mess_len the number of bytes in the message byte array
      * @param signature the byte array containing the signature
      * @param sig_len the number of bytes in the signature byte array
      */
      bool verify(const byte message[], u32bit mess_len,
                  const byte signature[], u32bit sig_len) const;

      /**
      * Default constructor. Use this one if you want to later fill
      * this object with data from an encoded key.
      */
      ECDSA_PublicKey() {}

      /**
      * Construct a public key from a given public point.
      * @param dom_par the domain parameters associated with this key
      * @param public_point the public point defining this key
      */
      ECDSA_PublicKey(const EC_Domain_Params& dom_par,
                      const PointGFp& public_point); // sets core

      ECDSA_PublicKey const& operator=(const ECDSA_PublicKey& rhs);

      ECDSA_PublicKey(const ECDSA_PublicKey& other);

      /**
      * Set the domain parameters of this key. This function has to be
      * used when a key encoded without domain parameters was decoded into
      * this key. Otherwise it will not be able to verify a signature.
      * @param dom_pars the domain_parameters associated with this key
      * @throw Invalid_Argument if the point was found not to be satisfying the
      * curve equation of the provided domain parameters
      * or if this key already has domain parameters set
      * and these are differing from those given as the parameter
      */
      void set_domain_parameters(const EC_Domain_Params& dom_pars);

      /**
      * Ensure that the public point and domain parameters of this key are set.
      * @throw Invalid_State if either of the two data members is not set
      */
      virtual void affirm_init() const;

   protected:
      void X509_load_hook();
      virtual void set_all_values(const ECDSA_PublicKey& other);

      ECDSA_Core m_ecdsa_core;
   };

/**
* This class represents ECDSA Private Keys
*/
class BOTAN_DLL ECDSA_PrivateKey : public ECDSA_PublicKey,
                                   public EC_PrivateKey,
                                   public PK_Signing_Key
   {
   public:
      //ctors

      /**
      * Default constructor. Use this one if you want to later fill
      * this object with data from an encoded key.
      */
      ECDSA_PrivateKey() {}

      /**
      * Generate a new private key
      * @param the domain parameters to used for this key
      */
      ECDSA_PrivateKey(RandomNumberGenerator& rng,
                       const EC_Domain_Params& domain);

      ECDSA_PrivateKey(const ECDSA_PrivateKey& other);
      ECDSA_PrivateKey const& operator=(const ECDSA_PrivateKey& rhs);

      /**
      * Sign a message with this key.
      * @param message the byte array representing the message to be signed
      * @param mess_len the length of the message byte array
      * @result the signature
      */

      SecureVector<byte> sign(const byte message[], u32bit mess_len,
                              RandomNumberGenerator& rng) const;

      /**
      * Make sure that the public key parts of this object are set
      * (calls EC_PublicKey::affirm_init()) as well as the private key
      * value.
      * @throw Invalid_State if the above conditions are not satisfied
      */
      virtual void affirm_init() const;

   protected:
      virtual void set_all_values(const ECDSA_PrivateKey& other);
   private:
      void PKCS8_load_hook(bool = false);
   };

}

#endif
