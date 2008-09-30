/*************************************************
* ECDSA Header File                              *
* (C) 2007 Falko Strenzke, FlexSecure GmbH       *
*          Manuel hartl, FlexSecure GmbH         *
*************************************************/

#ifndef BOTAN_EC_H__
#define BOTAN_EC_H__

#include <botan/if_algo.h>
#include <botan/bigint.h>
#include <botan/curve_gfp.h>
#include <botan/pk_keys.h>
#include <botan/ec_dompar.h>

namespace Botan {

/**
* This class represents abstract EC Public Keys.
* When encoding a key via an encoder that can be accessed via
* the corresponding member functions, the key will decide upon its
* internally stored encoding information whether to encode itself with
* or without domain parameters, or using the domain parameter oid.
* Furthermore, a public key
* without domain parameters can be decoded. In that case, it cannot be used
* for verification until its domain parameters are set by calling the
* corresponding member function.
*/
class EC_PublicKey : public virtual Public_Key
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
      inline Botan::PointGFp get_public_point() const
         {
         if (!mp_public_point.get())
            {
            throw Invalid_State("EC_PublicKey::get_public_point(): public point not set because ec domain parameters are not yet set");
            }
         return *mp_public_point;
         }
      /**
      * Get the domain parameters of this key.
      * @throw Invalid_State is thrown if the
      * domain parameters of this point are not set
      * @result the domain parameters of this key
      */
      EC_Domain_Params const get_domain_parameters() const;
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
      std::auto_ptr<Botan::PointGFp> mp_public_point;
      EC_dompar_enc m_param_enc;
   };

/**
* This abstract class represents general EC Private Keys
*/
class EC_PrivateKey : public virtual EC_PublicKey, public virtual Private_Key
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
      inline BigInt const get_value() const
         {
         return m_private_value;
         }
      /**
      * Make sure that the public key parts of this object are set
      * (calls EC_PublicKey::affirm_init()) as well as the private key
      * value.
      * @throw Invalid_State if the above conditions are not satisfied
      */
      virtual void affirm_init()  const;
      virtual ~EC_PrivateKey()
         {}
   protected:
      virtual void PKCS8_load_hook(bool = false);
      void generate_private_key(RandomNumberGenerator&);
      BigInt m_private_value;
   };

/**
* This class represents ECDSA Public Keys.
*/
class ECDSA_PublicKey : public virtual EC_PublicKey, public PK_Verifying_wo_MR_Key
   {
   public:

      /**
      * Get this keys algorithm name.
      * @result this keys algorithm name ("ECDSA")
      */
      std::string algo_name() const
         {
         return "ECDSA";
         }

      /**
      * Get the maximum number of bits allowed to be fed to this key.
      * This is the bitlength of the order of the base point.
      *
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
                  const byte signature [], u32bit sig_len) const;

      /**
      * Default constructor. Use this one if you want to later fill this object with data
      * from an encoded key.
      */
      ECDSA_PublicKey() {}

      /**
      * Construct a public key from a given public point.
      * @param dom_par the domain parameters associated with this key
      * @param public_point the public point defining this key
      */
      ECDSA_PublicKey(EC_Domain_Params const& dom_par, Botan::PointGFp const& public_point); // sets core


      ECDSA_PublicKey const& operator= (ECDSA_PublicKey const& rhs);

      ECDSA_PublicKey(ECDSA_PublicKey const& other);

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
      void set_domain_parameters(EC_Domain_Params const& dom_pars);

      /**
      * Make sure that the public point and domain parameters of this key are set.
      * @throw Invalid_State if either of the two data members is not set
      */
      virtual void affirm_init() const;

   protected:
      void X509_load_hook();
      virtual void set_all_values(ECDSA_PublicKey const& other);

      ECDSA_Core m_ecdsa_core;
   };
/**
* This class represents ECDSA Public Keys.
*/
class ECDSA_PrivateKey : public ECDSA_PublicKey, public EC_PrivateKey, public PK_Signing_Key
   {
   public:
      //ctors
      /**
      * Default constructor. Use this one if you want to later fill this object with data
      * from an encoded key.
      */
      ECDSA_PrivateKey()
         {}
      /**
      * Generate a new private key
      * @param the domain parameters to used for this key
      */
      ECDSA_PrivateKey(RandomNumberGenerator& rng,
                       const EC_Domain_Params& domain);

      ECDSA_PrivateKey(ECDSA_PrivateKey const& other);
      ECDSA_PrivateKey const& operator= (ECDSA_PrivateKey const& rhs);

      /**
      * Sign a message with this key.
      * @param message the byte array representing the message to be signed
      * @param mess_len the length of the message byte array
      * @result the signature
      */
      SecureVector<byte> sign(const byte message[], u32bit mess_len, RandomNumberGenerator& rng) const;
      /**
      * Make sure that the public key parts of this object are set
      * (calls EC_PublicKey::affirm_init()) as well as the private key
      * value.
      * @throw Invalid_State if the above conditions are not satisfied
      */
      virtual void affirm_init() const;
   protected:
      virtual void set_all_values ( ECDSA_PrivateKey const& other );
   private:
      void PKCS8_load_hook(bool = false);
   };

/**
* This class represents ECKAEG Public Keys.
*/
class ECKAEG_PublicKey : public virtual EC_PublicKey
   {
   public:
      /**
      * Default constructor. Use this one if you want to later fill this object with data
      * from an encoded key.
      */
      ECKAEG_PublicKey()
         {};
      /**
      * Construct a public key from a given public point.
      * @param dom_par the domain parameters associated with this key
      * @param public_point the public point defining this key
      */
      ECKAEG_PublicKey(EC_Domain_Params const& dom_par, Botan::PointGFp const& public_point);

      /**
      * Get this keys algorithm name.
      * @result this keys algorithm name
      */
      std::string algo_name() const
         {
         return "ECKAEG";
         }
      /**
      * Get the maximum number of bits allowed to be fed to this key.
      * This is the bitlength of the order of the base point.
      *
      * @result the maximum number of input bits
      */
      u32bit max_input_bits() const
         {
         if (!mp_dom_pars.get())
            {
            throw Invalid_State("ECKAEG_PublicKey::max_input_bits(): domain parameters not set");
            }
         return mp_dom_pars->get_order().bits();
         }
      ECKAEG_PublicKey(ECKAEG_PublicKey const& other);
      ECKAEG_PublicKey const& operator= (ECKAEG_PublicKey const& rhs);


      /**
      * Make sure that the public point and domain parameters of this key are set.
      * @throw Invalid_State if either of the two data members is not set
      */
      virtual void affirm_init() const;
   protected:
      void X509_load_hook();
      virtual void set_all_values ( ECKAEG_PublicKey const& other );

      ECKAEG_Core m_eckaeg_core;
   };

/**
* This class represents ECKAEG Private Keys.
*/
class ECKAEG_PrivateKey : public ECKAEG_PublicKey, public EC_PrivateKey, public PK_Key_Agreement_Key
   {
   public:
      /**
      * Generate a new private key
      * @param the domain parameters to used for this key
      */
      ECKAEG_PrivateKey(RandomNumberGenerator& rng,
                        EC_Domain_Params const& dom_pars)
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
      ECKAEG_PrivateKey()
         {}
      ECKAEG_PrivateKey(ECKAEG_PrivateKey const& other);
      ECKAEG_PrivateKey const& operator= (ECKAEG_PrivateKey const& rhs);

      void PKCS8_load_hook(bool = false);

      /**
      * Derive a shared key with the other partys public key.
      * @param pub_key the other partys public key
      */
      SecureVector<byte> derive_key(const Public_Key& pub_key) const;

      /**
      * Make sure that the public key parts of this object are set
      * (calls EC_PublicKey::affirm_init()) as well as the private key
      * value.
      * @throw Invalid_State if the above conditions are not satisfied
      */
      virtual void affirm_init() const;

   protected:
      virtual void set_all_values ( ECKAEG_PrivateKey const& other );
   };

}

#endif
