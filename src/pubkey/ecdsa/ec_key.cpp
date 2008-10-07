/*************************************************
* ECC Key implemenation                          *
* (C) 2007 Manuel Hartl / FlexSecure GmbH        *
*                                                *
*          Falko Strenzke                        *
*          strenzke@flexsecure.de                *
*************************************************/

#include <botan/ec_key.h>
#include <botan/x509_key.h>
#include <botan/numthry.h>
#include <botan/util.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/secmem.h>
#include <botan/point_gfp.h>

namespace Botan {

/*************************************************
* EC_PublicKey                                   *
*************************************************/
void EC_PublicKey::affirm_init() const // virtual
   {
   if ((mp_dom_pars.get() == 0) || (mp_public_point.get() == 0))
      {
      throw Invalid_State("cannot use uninitialized EC_Key");
      }
   }
EC_Domain_Params const EC_PublicKey::get_domain_parameters() const
   {
   if(!mp_dom_pars.get())
      {
      throw Invalid_State("EC_PublicKey::get_domain_parameters(): ec domain parameters are not yet set");
      }
   return *mp_dom_pars;
   }
bool EC_PublicKey::domain_parameters_set()
   {
   if (mp_dom_pars.get())
      {
      return true;
      }
   return false;
   }
void EC_PublicKey::X509_load_hook()
   {
   try
      {
      // the base point is checked to be on curve already when decoding it
      affirm_init();
      mp_public_point->check_invariants();
      }
   catch ( Illegal_Point exc )
      {
      throw Decoding_Error ( "decoded public point was found not to lie on curve" );
      }
   }


X509_Encoder* EC_PublicKey::x509_encoder() const
   {
   class EC_Key_Encoder : public X509_Encoder
      {
      public:
         AlgorithmIdentifier alg_id() const
            {
            key->affirm_init();
            SecureVector<byte> params = encode_der_ec_dompar ( * ( key->mp_dom_pars ), key->m_param_enc );
            return AlgorithmIdentifier ( key->get_oid(),
                                         params );
            }

         MemoryVector<byte> key_bits() const
            {
            key->affirm_init();
            return EC2OSP ( * ( key->mp_public_point ), PointGFp::COMPRESSED );

            }

         EC_Key_Encoder ( const EC_PublicKey* k ) : key ( k )
            {}
      private:
         const EC_PublicKey* key;
      };

   return new EC_Key_Encoder(this);
   }

X509_Decoder* EC_PublicKey::x509_decoder()
   {
   class EC_Key_Decoder : public X509_Decoder
      {
      public:
         void alg_id ( const AlgorithmIdentifier& alg_id )
            {
            key->mp_dom_pars.reset ( new EC_Domain_Params ( decode_ber_ec_dompar ( alg_id.parameters ) ) );
            }

         void key_bits ( const MemoryRegion<byte>& bits )
            {
            key->mp_public_point.reset ( new PointGFp ( OS2ECP ( bits, key->mp_dom_pars->get_curve() ) ) );
            key->X509_load_hook();
            }

         EC_Key_Decoder ( EC_PublicKey* k ) : key ( k )
            {}
      private:
         EC_PublicKey* key;
      };

   return new EC_Key_Decoder(this);
   }

void EC_PublicKey::set_parameter_encoding ( EC_dompar_enc type )
   {
   if ( ( type != ENC_EXPLICIT ) && ( type != ENC_IMPLICITCA ) && ( type != ENC_OID ) )
      {
      throw Invalid_Argument ( "invalid encoding type for EC-key object specified" );
      }
   affirm_init();
   if ( ( mp_dom_pars->get_oid() == "" ) && ( type == ENC_OID ) )
      {
      throw Invalid_Argument ( "invalid encoding type ENC_OID specified for EC-key object whose corresponding domain parameters are without oid" );
      }
   m_param_enc = type;
   }

/********************************
* EC_PrivateKey                 *
********************************/
void EC_PrivateKey::affirm_init() const // virtual
   {
   EC_PublicKey::affirm_init();
   if (m_private_value == 0)
      {
      throw Invalid_State("cannot use EC_PrivateKey when private key is uninitialized");
      }
   }

}
