/*************************************************
* ECDSA implemenation                            *
* (C) 2007 Manuel Hartl, FlexSecure GmbH         *
*     2007 Falko Strenzke, FlexSecure GmbH       *
*     2008 Jack Lloyd                            *
*************************************************/

#include <botan/ecdsa.h>
#include <botan/ecdsa_sig.h>
#include <botan/numthry.h>
#include <botan/util.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/secmem.h>
#include <botan/point_gfp.h>

namespace Botan {

ECDSA_PrivateKey::ECDSA_PrivateKey(RandomNumberGenerator& rng,
                                   const EC_Domain_Params& dom_pars)
   {
   mp_dom_pars = std::auto_ptr<EC_Domain_Params>(new EC_Domain_Params(dom_pars));
   generate_private_key(rng);

   try
      {
      mp_public_point->check_invariants();
      }
   catch(Illegal_Point& e)
      {
      throw Invalid_State("ECDSA key generation failed");
      }

   m_ecdsa_core = ECDSA_Core(*mp_dom_pars, m_private_value, *mp_public_point);
   }

/**
* EC_PrivateKey generator
**/
void EC_PrivateKey::generate_private_key(RandomNumberGenerator& rng)
   {
   if (mp_dom_pars.get() == 0)
      {
      throw Invalid_State("cannot generate private key when domain parameters are not set");
      }
   BigInt tmp_private_value(0);
   tmp_private_value = BigInt::random_integer(rng, 1, mp_dom_pars->get_order() );
   mp_public_point = std::auto_ptr<PointGFp>( new PointGFp (mp_dom_pars->get_base_point()));
   mp_public_point->mult_this_secure(tmp_private_value, mp_dom_pars->get_order(), mp_dom_pars->get_order()-1);

   //assert(mp_public_point.get() != 0);
   tmp_private_value.swap(m_private_value);
   }

/**
* Return the PKCS #8 public key encoder
**/
PKCS8_Encoder* EC_PrivateKey::pkcs8_encoder() const
   {
   class EC_Key_Encoder : public PKCS8_Encoder
      {
      public:
         AlgorithmIdentifier alg_id() const
            {
            key->affirm_init();
            SecureVector<byte> params = encode_der_ec_dompar ( * ( key->mp_dom_pars ), ENC_EXPLICIT );
            return AlgorithmIdentifier ( key->get_oid(),
                                         params );
            }

         MemoryVector<byte> key_bits() const
            {
            key->affirm_init();
            SecureVector<byte> octstr_secret = BigInt::encode_1363 ( key->m_private_value, key->m_private_value.bytes() );

            return DER_Encoder()
               .start_cons ( SEQUENCE )
               .encode ( BigInt ( 1 ) )
               .encode ( octstr_secret, OCTET_STRING )
               .end_cons()
               .get_contents();
            }

         EC_Key_Encoder ( const EC_PrivateKey* k ) : key ( k )
            {}
      private:
         const EC_PrivateKey* key;
      };

   return new EC_Key_Encoder(this);
   }

/**
* Return the PKCS #8 public key decoder
*/
PKCS8_Decoder* EC_PrivateKey::pkcs8_decoder(RandomNumberGenerator&)
   {
   class EC_Key_Decoder : public PKCS8_Decoder
      {
      public:
         void alg_id ( const AlgorithmIdentifier& alg_id )
            {
            key->mp_dom_pars.reset ( new EC_Domain_Params ( decode_ber_ec_dompar ( alg_id.parameters ) ) );
            }

         void key_bits ( const MemoryRegion<byte>& bits )
            {
            u32bit version;
            SecureVector<byte> octstr_secret;
            BER_Decoder ( bits )
               .start_cons ( SEQUENCE )
               .decode ( version )
               .decode ( octstr_secret, OCTET_STRING )
               .verify_end()
               .end_cons();
            key->m_private_value = BigInt::decode ( octstr_secret, octstr_secret.size() );
            if ( version != 1 )
               throw Decoding_Error ( "Wrong PKCS #1 key format version for EC key" );
            key->PKCS8_load_hook();
            }

         EC_Key_Decoder ( EC_PrivateKey* k ) : key ( k )
            {}
      private:
         EC_PrivateKey* key;
      };

   return new EC_Key_Decoder(this);
   }


void EC_PrivateKey::PKCS8_load_hook ( bool )
   {
   // we cannot use affirm_init() here because mp_public_point might still be null
   if (mp_dom_pars.get() == 0 )
      {
      throw Invalid_State("attempt to set public point for an uninitialized key");
      }
   mp_public_point.reset ( new PointGFp ( m_private_value * mp_dom_pars->get_base_point() ) );
   mp_public_point->check_invariants();

   }




/*************************************************
* ECDSA_PublicKey                                *
*************************************************/
void ECDSA_PublicKey::affirm_init() const // virtual
   {
   EC_PublicKey::affirm_init();
   }

void ECDSA_PublicKey::set_domain_parameters(EC_Domain_Params const& dom_pars)
   {
   if (mp_dom_pars.get())
      {
      // they are already set, we must ensure that they are equal to the arg
      if (dom_pars != *mp_dom_pars.get())
         {
         throw Invalid_Argument("EC_PublicKey::set_domain_parameters(): domain parameters are already set, and they are different from the argument");
         }
      else
         {
         // they are equal, so nothing to do
         return;
         }
      }
   // set them ...
   if (m_enc_public_point.size() == 0)
      {
      throw Invalid_State("EC_PublicKey::set_domain_parameters(): encoded public point isn´t set");
      }

   // now try to decode the public key ...
   PointGFp tmp_pp(OS2ECP(m_enc_public_point, dom_pars.get_curve()));
   try
      {
      tmp_pp.check_invariants();
      }
   catch(Illegal_Point e)
      {
      throw Invalid_State("EC_PublicKey::set_domain_parameters(): point does not lie on provided curve");
      }
   std::auto_ptr<EC_Domain_Params> p_tmp_pars(new EC_Domain_Params(dom_pars));
   ECDSA_Core tmp_ecdsa_core( *p_tmp_pars, BigInt ( 0 ), tmp_pp );
   mp_public_point.reset(new PointGFp(tmp_pp));
   m_ecdsa_core = tmp_ecdsa_core;
   mp_dom_pars = p_tmp_pars;
   }

void ECDSA_PublicKey::set_all_values ( ECDSA_PublicKey const& other )
   {
   m_param_enc = other.m_param_enc;
   m_ecdsa_core = other.m_ecdsa_core;
   m_enc_public_point = other.m_enc_public_point;
   if ( other.mp_dom_pars.get() )
      {
      mp_dom_pars.reset ( new EC_Domain_Params ( * ( other.mp_dom_pars ) ) );
      }
   if ( other.mp_public_point.get() )
      {
      mp_public_point.reset ( new PointGFp ( * ( other.mp_public_point ) ) );
      }
   }
ECDSA_PublicKey::ECDSA_PublicKey ( ECDSA_PublicKey const& other )
   : Public_Key(),
     EC_PublicKey(),
     PK_Verifying_wo_MR_Key()
   {
   set_all_values ( other );
   }
ECDSA_PublicKey const& ECDSA_PublicKey::operator= ( ECDSA_PublicKey const& rhs )
   {
   set_all_values ( rhs );
   return *this;
   }
bool ECDSA_PublicKey::verify ( const byte message[], u32bit mess_len, const byte signature [], u32bit sig_len ) const
   {
   affirm_init();
   ECDSA_Signature sig;
   std::auto_ptr<ECDSA_Signature_Decoder> dec(sig.x509_decoder());
   SecureVector<byte> sv_sig;
   sv_sig.set ( signature, sig_len );
   dec->signature_bits ( sv_sig );
   SecureVector<byte> sv_plain_sig = sig.get_concatenation();
   return m_ecdsa_core.verify ( sv_plain_sig, sv_plain_sig.size(), message, mess_len );
   }
ECDSA_PublicKey::ECDSA_PublicKey ( EC_Domain_Params const& dom_par, PointGFp const& public_point )
   {
   mp_dom_pars = std::auto_ptr<EC_Domain_Params> ( new EC_Domain_Params ( dom_par ) );
   mp_public_point = std::auto_ptr<PointGFp> ( new PointGFp ( public_point ) );
   m_param_enc = ENC_EXPLICIT;
   m_ecdsa_core = ECDSA_Core ( *mp_dom_pars, BigInt ( 0 ), *mp_public_point );
   }
void ECDSA_PublicKey::X509_load_hook()
   {
   EC_PublicKey::X509_load_hook();
   EC_PublicKey::affirm_init();
   m_ecdsa_core = ECDSA_Core ( *mp_dom_pars, BigInt ( 0 ), *mp_public_point );
   }
u32bit ECDSA_PublicKey::max_input_bits() const
   {
   if(!mp_dom_pars.get())
      {
      throw Invalid_State("ECDSA_PublicKey::max_input_bits(): domain parameters not set");
      }
   return mp_dom_pars->get_order().bits();
   }


/*************************
* ECDSA_PrivateKey       *
*************************/

void ECDSA_PrivateKey::affirm_init() const // virtual
   {
   EC_PrivateKey::affirm_init();
   }

void ECDSA_PrivateKey::PKCS8_load_hook ( bool generated )
   {
   EC_PrivateKey::PKCS8_load_hook ( generated );
   EC_PrivateKey::affirm_init();
   m_ecdsa_core = ECDSA_Core ( *mp_dom_pars, m_private_value, *mp_public_point );
   }


void ECDSA_PrivateKey::set_all_values ( ECDSA_PrivateKey const& other )
   {
   m_private_value = other.m_private_value;
   m_param_enc = other.m_param_enc;
   m_ecdsa_core = other.m_ecdsa_core;
   m_enc_public_point = other.m_enc_public_point;
   if ( other.mp_dom_pars.get() )
      {
      mp_dom_pars.reset ( new EC_Domain_Params ( * ( other.mp_dom_pars ) ) );
      }
   if ( other.mp_public_point.get() )
      {
      mp_public_point.reset ( new PointGFp ( * ( other.mp_public_point ) ) );
      }
   }

ECDSA_PrivateKey::ECDSA_PrivateKey(ECDSA_PrivateKey const& other)
   : Public_Key(),
     EC_PublicKey(),
     Private_Key(),
     ECDSA_PublicKey(),
     EC_PrivateKey(),
     PK_Signing_Key()
   {
   set_all_values(other);
   }
ECDSA_PrivateKey const& ECDSA_PrivateKey::operator= (ECDSA_PrivateKey const& rhs)
   {
   set_all_values(rhs);
   return *this;
   }

SecureVector<byte> ECDSA_PrivateKey::sign ( const byte message [], u32bit mess_len, RandomNumberGenerator&) const
   {
   affirm_init();
   SecureVector<byte> sv_sig = m_ecdsa_core.sign ( message, mess_len );
   //code which der encodes the signature returned
   ECDSA_Signature sig = decode_concatenation( sv_sig );
   std::auto_ptr<ECDSA_Signature_Encoder> enc(sig.x509_encoder());
   return enc->signature_bits();
   }

}
