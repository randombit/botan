/*************************************************
* ECC Key implemenation                          *
* (C) 2007 Manuel Hartl / FlexSecure GmbH        *
*                                                *
*          Falko Strenzke                        *
*          strenzke@flexsecure.de                *
*************************************************/

#include <botan/ec.h>
#include <botan/bigintfuncs.h>
#include <botan/util.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/secmem.h>
#include <botan/point_gfp.h>
#include <botan/cvc_key.h>


using namespace Botan::math::ec;
using namespace Botan::math::gf;

namespace Botan
  {
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


    std::auto_ptr<X509_Encoder> EC_PublicKey::x509_encoder() const
      {
        class EC_Key_Encoder : public X509_Encoder
          {
          public:
            AlgorithmIdentifier alg_id() const
              {
                key->affirm_init();
                SecureVector<byte> params = Botan::encode_der_ec_dompar ( * ( key->mp_dom_pars ), key->m_param_enc );
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

        return std::auto_ptr<X509_Encoder> ( new EC_Key_Encoder ( this ) );
      }

    /**
    * Return the X.509 public key decoder
    */
    std::auto_ptr<X509_Decoder> EC_PublicKey::x509_decoder()
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

      return std::auto_ptr<X509_Decoder> ( new EC_Key_Decoder ( this ) );
    }

    std::auto_ptr<EAC1_1_CVC_Encoder> EC_PublicKey::cvc_eac1_1_encoder() const
      {
        class EC_Key_Encoder : public EAC1_1_CVC_Encoder
          {
          public:
            MemoryVector<byte> public_key(AlgorithmIdentifier const& sig_algo) const
              {
                if (key->m_param_enc == ENC_OID)
                  {
                    throw Encoding_Error("CVC encoder: cannot encode parameters by oid (ENC_OID)");
                  }
                EC_Domain_Params dom_pars(key->get_domain_parameters());
                CurveGFp curve(dom_pars.get_curve());
                BigInt mod(dom_pars.get_curve().get_p());
                BigInt order(dom_pars.get_order());
                BigInt cofactor(dom_pars.get_cofactor());
                MemoryVector<byte> enc_mod(BigInt::encode_1363(mod, mod.bytes()));
                MemoryVector<byte> enc_order(BigInt::encode_1363(order, order.bytes()));
                MemoryVector<byte> enc_cof(BigInt::encode_1363(cofactor, cofactor.bytes()));

                key->affirm_init();

                DER_Encoder enc;
                enc.start_cons(ASN1_Tag(73), APPLICATION)
                .encode(sig_algo.oid);
                if (key->m_param_enc == ENC_EXPLICIT)
                  {
                    enc.encode(enc_mod, OCTET_STRING, ASN1_Tag(1))
                    .encode(FE2OSP (curve.get_a()), OCTET_STRING, ASN1_Tag(2))
                    .encode(FE2OSP (curve.get_b()), OCTET_STRING, ASN1_Tag(3))
                    .encode(EC2OSP(dom_pars.get_base_point(),PointGFp::UNCOMPRESSED), OCTET_STRING, ASN1_Tag(4))
                    .encode(enc_order, OCTET_STRING, ASN1_Tag(5));
                  }
                enc.encode(EC2OSP(*key->mp_public_point , PointGFp::UNCOMPRESSED), OCTET_STRING, ASN1_Tag(6));
                if (key->m_param_enc == ENC_EXPLICIT)
                  {
                    enc.encode(enc_cof, OCTET_STRING, ASN1_Tag(7));
                  }
                enc.end_cons();
                SecureVector<byte> result = enc.get_contents();
                return result;
              }

            EC_Key_Encoder ( const EC_PublicKey* k ) : key ( k )
            {}
          private:
            const EC_PublicKey* key;
          };

        return std::auto_ptr<EAC1_1_CVC_Encoder> ( new EC_Key_Encoder ( this ) );
      }
    std::auto_ptr<EAC1_1_CVC_Decoder> EC_PublicKey::cvc_eac1_1_decoder()
    {
      class EC_Key_Decoder : public EAC1_1_CVC_Decoder
        {
        public:
          AlgorithmIdentifier const public_key ( MemoryRegion<byte> const& enc_pub_key )
          {
            AlgorithmIdentifier result;
            OID sig_alg_oid;
            SecureVector<byte> enc_mod;
            SecureVector<byte> enc_a;
            SecureVector<byte> enc_b;
            SecureVector<byte> enc_base_point;
            SecureVector<byte> enc_n;
            SecureVector<byte> enc_pub_point;
            SecureVector<byte> enc_cof;
            SecureVector<byte> const& sv_empty = SecureVector<byte>();
            MemoryRegion<byte> const& empty = sv_empty;
            SecureVector<byte> & ref_mod = enc_mod;
            MemoryRegion<byte> & reg_mod = ref_mod;
            SecureVector<byte> & ref_a = enc_a;
            MemoryRegion<byte> & reg_a = ref_a;
            SecureVector<byte> & ref_b = enc_b;
            MemoryRegion<byte> & reg_b = ref_b;
            SecureVector<byte> & ref_base_point = enc_base_point;
            MemoryRegion<byte> & reg_base_point = ref_base_point;
            SecureVector<byte> & ref_n = enc_n;
            MemoryRegion<byte> & reg_n = ref_n;
            SecureVector<byte> & ref_cof = enc_cof;
            MemoryRegion<byte> & reg_cof = ref_cof;
            BER_Decoder(enc_pub_key)
            .decode(sig_alg_oid)
            .decode_optional(reg_mod, OCTET_STRING, ASN1_Tag(1), CONTEXT_SPECIFIC, empty)
            .decode_optional(reg_a, OCTET_STRING, ASN1_Tag(2), CONTEXT_SPECIFIC, empty)
            .decode_optional(reg_b, OCTET_STRING, ASN1_Tag(3), CONTEXT_SPECIFIC, empty)
            .decode_optional(reg_base_point, OCTET_STRING, ASN1_Tag(4), CONTEXT_SPECIFIC, empty)
            .decode_optional(reg_n, OCTET_STRING, ASN1_Tag(5), CONTEXT_SPECIFIC, empty)
            .decode(enc_pub_point, OCTET_STRING, ASN1_Tag(6))
            .decode_optional(reg_cof, OCTET_STRING, ASN1_Tag(7), CONTEXT_SPECIFIC, empty)
            .verify_end();

            result = AlgorithmIdentifier(sig_alg_oid, AlgorithmIdentifier::USE_NULL_PARAM);

            if (enc_mod.size() == 0 && // either none are set...
                enc_a.size() == 0 &&
                enc_b.size() == 0 &&
                enc_base_point.size() == 0 &&
                enc_n.size() == 0 &&
                enc_cof.size() == 0)
              {
                // ok, this is impl_ca
                if (enc_pub_point.size() == 0)
                  {
                    // probably this cannot happen
                    throw Decoding_Error("EAC1_1_CVC_Decoder::public_key(): size of encoded public point is zero");
                  }
                key->m_param_enc = ENC_IMPLICITCA;
                key->m_enc_public_point.swap(enc_pub_point);
                return result;
              }
            // or all are set...
            if (enc_mod.size() == 0 ||
                enc_a.size() == 0 ||
                enc_b.size() == 0 ||
                enc_base_point.size() == 0 ||
                enc_n.size() == 0 ||
                enc_cof.size() == 0 ||
                enc_pub_point == 0) // don´t forget the non-optional
              {
                throw Decoding_Error("only a (non empty) subset of the domain parameter fields was found");
              }
            BigInt p(BigInt::decode(enc_mod, enc_mod.size()));
            BigInt cof(BigInt::decode(enc_cof, enc_cof.size()));
            BigInt order((BigInt::decode(enc_n, enc_n.size())));
            GFpElement a(p,BigInt::decode(enc_a, enc_a.size()));
            GFpElement b(p,BigInt::decode(enc_b, enc_b.size()));
            CurveGFp curve(a,b,p);
            PointGFp G = OS2ECP ( enc_base_point, curve );
            G.check_invariants();
            std::auto_ptr<EC_Domain_Params> p_tmp_dom_pars(new EC_Domain_Params(curve, G, order, cof));
            PointGFp public_point = OS2ECP(enc_pub_point, curve);
            key->mp_public_point.reset(new PointGFp(OS2ECP(enc_pub_point, curve)));
            key->mp_dom_pars = p_tmp_dom_pars;
            key->X509_load_hook();
            key->m_param_enc = ENC_EXPLICIT;
            return result;
          }
          EC_Key_Decoder (EC_PublicKey* k ) : key ( k )
          {}
        private:
          EC_PublicKey* key;
        };
      return std::auto_ptr<EAC1_1_CVC_Decoder> ( new EC_Key_Decoder ( this ) );
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

    /**
     * EC_PrivateKey generator
     **/
    void EC_PrivateKey::generate_private_key()
    {
      if (mp_dom_pars.get() == 0)
        {
          throw Invalid_State("cannot generate private key when domain parameters are not set");
        }
      BigInt tmp_private_value(0);
      tmp_private_value = random_integer ( 1, mp_dom_pars->get_order() );

      mp_public_point = std::auto_ptr<PointGFp>( new PointGFp (mp_dom_pars->get_base_point()));
      mp_public_point->mult_this_secure(tmp_private_value, mp_dom_pars->get_order(), mp_dom_pars->get_order()-1);
      assert(mp_public_point.get() != 0);
      tmp_private_value.swap(m_private_value);
    }

    /**
    * Return the PKCS #8 public key encoder
    **/
    std::auto_ptr<PKCS8_Encoder> EC_PrivateKey::pkcs8_encoder() const
      {
        class EC_Key_Encoder : public PKCS8_Encoder
          {
          public:
            AlgorithmIdentifier alg_id() const
              {
                key->affirm_init();
                SecureVector<byte> params = Botan::encode_der_ec_dompar ( * ( key->mp_dom_pars ), ENC_EXPLICIT );
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
        return std::auto_ptr<PKCS8_Encoder> ( new EC_Key_Encoder ( this ) );
      }

    /**
     * Return the PKCS #8 public key decoder
    */
    std::auto_ptr<PKCS8_Decoder> EC_PrivateKey::pkcs8_decoder()
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

      return std::auto_ptr<PKCS8_Decoder> ( new EC_Key_Decoder ( this ) );
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
        std::auto_ptr<ECDSA_Signature_Decoder> dec =  sig.x509_decoder();
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
    SecureVector<byte> ECDSA_PrivateKey::sign ( const byte message [], u32bit mess_len ) const
      {
        affirm_init();
        SecureVector<byte> sv_sig = m_ecdsa_core.sign ( message, mess_len );
        //code which der encodes the signature returned
        ECDSA_Signature sig = ecdsa::decode_concatenation( sv_sig );
        std::auto_ptr<ECDSA_Signature_Encoder> enc = sig.x509_encoder();
        return enc->signature_bits();

      }



    /*********************************
    * ECKAEG_PublicKey               *
    *********************************/

    void ECKAEG_PublicKey::affirm_init() const // virtual
      {
        EC_PublicKey::affirm_init();
      }

    void ECKAEG_PublicKey::set_all_values ( ECKAEG_PublicKey const& other )
    {
      m_param_enc = other.m_param_enc;
      m_eckaeg_core = other.m_eckaeg_core;
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
    ECKAEG_PublicKey::ECKAEG_PublicKey ( ECKAEG_PublicKey const& other )
        : Public_Key(),
        EC_PublicKey()
    {
      set_all_values ( other );
    }
    ECKAEG_PublicKey const& ECKAEG_PublicKey::operator= ( ECKAEG_PublicKey const& rhs )
    {
      set_all_values ( rhs );
      return *this;
    }

    void ECKAEG_PublicKey::X509_load_hook()
    {
      EC_PublicKey::X509_load_hook();
      EC_PublicKey::affirm_init();
      m_eckaeg_core = ECKAEG_Core ( *mp_dom_pars, BigInt ( 0 ), *mp_public_point );
    }
    ECKAEG_PublicKey::ECKAEG_PublicKey ( EC_Domain_Params const& dom_par, PointGFp const& public_point )
    {

      mp_dom_pars = std::auto_ptr<EC_Domain_Params> ( new EC_Domain_Params ( dom_par ) );
      mp_public_point = std::auto_ptr<PointGFp> ( new PointGFp ( public_point ) );
      if(mp_public_point->get_curve() != mp_dom_pars->get_curve())
      {
       throw Invalid_Argument("ECKAEG_PublicKey(): curve of arg. point and curve of arg. domain parameters are different");
      }
      EC_PublicKey::affirm_init();
      m_eckaeg_core = ECKAEG_Core ( *mp_dom_pars, BigInt ( 0 ), *mp_public_point );
    }


    /*********************************
      * ECKAEG_PrivateKey            *
    *********************************/
    void ECKAEG_PrivateKey::affirm_init() const // virtual
      {
        EC_PrivateKey::affirm_init();
      }
    void ECKAEG_PrivateKey::PKCS8_load_hook ( bool generated )
    {
      EC_PrivateKey::PKCS8_load_hook ( generated );
      EC_PrivateKey::affirm_init();
      m_eckaeg_core = ECKAEG_Core ( *mp_dom_pars, m_private_value, *mp_public_point );
    }
    void ECKAEG_PrivateKey::set_all_values ( ECKAEG_PrivateKey const& other )
    {
      m_private_value = other.m_private_value;
      m_param_enc = other.m_param_enc;
      m_eckaeg_core = other.m_eckaeg_core;
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

    ECKAEG_PrivateKey::ECKAEG_PrivateKey(ECKAEG_PrivateKey const& other)
        : Public_Key(),
        EC_PublicKey(),
        Private_Key(),
        ECKAEG_PublicKey(),
        EC_PrivateKey(),
        PK_Key_Agreement_Key()

    {
      set_all_values(other);
    }
    ECKAEG_PrivateKey const& ECKAEG_PrivateKey::operator= (ECKAEG_PrivateKey const& rhs)
    {
      set_all_values(rhs);
      return *this;
    }

    /**
    * Derive a key
    */
    SecureVector<byte> ECKAEG_PrivateKey::derive_key(const Public_Key& key) const
    {
        affirm_init();

        const EC_PublicKey * p_ec_pk = dynamic_cast<const EC_PublicKey*>(&key);
        if(!p_ec_pk)
        {
         throw Invalid_Argument("ECKAEG_PrivateKey::derive_key(): argument must be an EC_PublicKey");
        }
        p_ec_pk->affirm_init();
        return m_eckaeg_core.agree ( p_ec_pk->get_public_point() );
    }
  }
