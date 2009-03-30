/*
* ECDSA
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*          Manuel Hartl, FlexSecure GmbH
* (C) 2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ECC_PUBLIC_KEY_BASE_H__
#define BOTAN_ECC_PUBLIC_KEY_BASE_H__

#include <botan/bigint.h>
#include <botan/curve_gfp.h>
#include <botan/pk_keys.h>
#include <botan/ec_dompar.h>
#include <botan/x509_key.h>
#include <botan/pkcs8.h>

namespace Botan {

/**
* This class represents abstract EC Public Keys. When encoding a key
* via an encoder that can be accessed via the corresponding member
* functions, the key will decide upon its internally stored encoding
* information whether to encode itself with or without domain
* parameters, or using the domain parameter oid. Furthermore, a public
* key without domain parameters can be decoded. In that case, it
* cannot be used for verification until its domain parameters are set
* by calling the corresponding member function.
*/
class BOTAN_DLL EC_PublicKey : public virtual Public_Key
   {
   public:

      /**
      * Tells whether this key knows his own domain parameters.
      * @result true if the domain parameters are set, false otherwise
      */
      bool domain_parameters_set();

      /**
      * Get the public point of this key.
      * @throw Invalid_State is thrown if the
      * domain parameters of this point are not set
      * @result the public point of this key
      */
      const PointGFp& public_point() const;

      /**
      * Get the domain parameters of this key.
      * @throw Invalid_State is thrown if the
      * domain parameters of this point are not set
      * @result the domain parameters of this key
      */
      const EC_Domain_Params& domain_parameters() const;

      /**
      * Set the domain parameter encoding to be used when encoding this key.
      * @param enc the encoding to use
      */
      void set_parameter_encoding(EC_dompar_enc enc);

      /**
      * Get the domain parameter encoding to be used when encoding this key.
      * @result the encoding to use
      */
      inline int get_parameter_encoding() const
         {
         return m_param_enc;
         }

      //ctors
      EC_PublicKey()
         : m_param_enc(ENC_EXPLICIT)
         {
         //assert(mp_dom_pars.get() == 0);
         //assert(mp_public_point.get() == 0);
         }

      /**
      * Get an x509_encoder that can be used to encode this key.
      * @result an x509_encoder for this key
      */
      X509_Encoder* x509_encoder() const;

      /**
      * Get an x509_decoder that can be used to decode a stored key into
      * this key.
      * @result an x509_decoder for this key
      */
      X509_Decoder* x509_decoder();

      /**
      * Make sure that the public point and domain parameters of this key are set.
      * @throw Invalid_State if either of the two data members is not set
      */
      virtual void affirm_init() const;

      virtual ~EC_PublicKey() {}
   protected:
      virtual void X509_load_hook();

      SecureVector<byte> m_enc_public_point; // stores the public point

      std::auto_ptr<EC_Domain_Params> mp_dom_pars;
      std::auto_ptr<PointGFp> mp_public_point;
      EC_dompar_enc m_param_enc;
   };

/**
* This abstract class represents general EC Private Keys
*/
class BOTAN_DLL EC_PrivateKey : public virtual EC_PublicKey, public virtual Private_Key
   {
   public:

      /**
      * Get an PKCS#8 encoder that can be used to encoded this key.
      * @result an PKCS#8 encoder for this key
      */
      PKCS8_Encoder* pkcs8_encoder() const;

      /**
      * Get an PKCS#8 decoder that can be used to decoded a stored key into
      * this key.
      * @result an PKCS#8 decoder for this key
      */
      PKCS8_Decoder* pkcs8_decoder(RandomNumberGenerator&);

      /**
      * Get the private key value of this key object.
      * @result the private key value of this key object
      */
      const BigInt& private_value() const;

      /**
      * Make sure that the public key parts of this object are set
      * (calls EC_PublicKey::affirm_init()) as well as the private key
      * value.
      * @throw Invalid_State if the above conditions are not satisfied
      */
      virtual void affirm_init() const;

      virtual ~EC_PrivateKey() {}
   protected:
      virtual void PKCS8_load_hook(bool = false);
      void generate_private_key(RandomNumberGenerator&);
      BigInt m_private_value;
   };

}

#endif
