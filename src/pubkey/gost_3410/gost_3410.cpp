/*
* GOST 34.10-2001 implemenation
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*          Manuel Hartl, FlexSecure GmbH
* (C) 2008-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/gost_3410.h>
#include <botan/numthry.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/secmem.h>
#include <botan/point_gfp.h>

namespace Botan {

GOST_3410_PrivateKey::GOST_3410_PrivateKey(RandomNumberGenerator& rng,
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
      throw Invalid_State("GOST_3410 key generation failed");
      }
   }

GOST_3410_PrivateKey::GOST_3410_PrivateKey(const EC_Domain_Params& domain,
                                           const BigInt& x)
   {
   mp_dom_pars = std::auto_ptr<EC_Domain_Params>(new EC_Domain_Params(domain));

   m_private_value = x;
   mp_public_point = std::auto_ptr<PointGFp>(new PointGFp (mp_dom_pars->get_base_point()));
   mp_public_point->mult_this_secure(m_private_value,
                                     mp_dom_pars->get_order(),
                                     mp_dom_pars->get_order()-1);

   try
      {
      mp_public_point->check_invariants();
      }
   catch(Illegal_Point)
      {
      throw Invalid_State("GOST_3410 key generation failed");
      }
   }

X509_Encoder* GOST_3410_PublicKey::x509_encoder() const
   {
   class GOST_3410_Key_Encoder : public X509_Encoder
      {
      public:
         AlgorithmIdentifier alg_id() const
            {
            key->affirm_init();

            SecureVector<byte> params =
               encode_der_ec_dompar(key->domain_parameters(), key->m_param_enc);

            return AlgorithmIdentifier(key->get_oid(), params);
            }

         MemoryVector<byte> key_bits() const
            {
            key->affirm_init();

            // Trust CryptoPro to come up with something obnoxious
            const BigInt x = key->mp_public_point->get_affine_x().get_value();
            const BigInt y = key->mp_public_point->get_affine_y().get_value();

            SecureVector<byte> bits(2*std::max(x.bytes(), y.bytes()));

            y.binary_encode(bits + (bits.size() / 2 - y.bytes()));
            x.binary_encode(bits + (bits.size() - y.bytes()));

            return DER_Encoder().encode(bits, OCTET_STRING).get_contents();
            }

         GOST_3410_Key_Encoder(const GOST_3410_PublicKey* k): key(k) {}
      private:
         const GOST_3410_PublicKey* key;
      };

   return new GOST_3410_Key_Encoder(this);
   }

X509_Decoder* GOST_3410_PublicKey::x509_decoder()
   {
   class GOST_3410_Key_Decoder : public X509_Decoder
      {
      public:
         void alg_id(const AlgorithmIdentifier& alg_id)
            {
            // Also includes hash and cipher OIDs... brilliant design guys
            OID ecc_param_id;

            BER_Decoder ber(alg_id.parameters);
            ber.start_cons(SEQUENCE).decode(ecc_param_id);

            EC_Domain_Params ecc_params = get_EC_Dom_Pars_by_oid(ecc_param_id.as_string());

            key->mp_dom_pars.reset(new EC_Domain_Params(ecc_params));
            }

         void key_bits(const MemoryRegion<byte>& bits)
            {

            SecureVector<byte> key_bits;
            BER_Decoder ber(bits);
            ber.decode(key_bits, OCTET_STRING);

            const u32bit part_size = key_bits.size() / 2;

            BigInt y(key_bits, part_size);
            BigInt x(key_bits + part_size, part_size);

            const BigInt p = key->domain_parameters().get_curve().get_p();

            key->mp_public_point.reset(
               new PointGFp(key->domain_parameters().get_curve(),
                            GFpElement(x, p),
                            GFpElement(y, p)));

            key->X509_load_hook();
            }

         GOST_3410_Key_Decoder(GOST_3410_PublicKey* k): key(k) {}
      private:
         GOST_3410_PublicKey* key;
      };

   return new GOST_3410_Key_Decoder(this);
   }

/*
* GOST_3410_PublicKey
*/
void GOST_3410_PublicKey::affirm_init() const // virtual
   {
   EC_PublicKey::affirm_init();
   }

void GOST_3410_PublicKey::set_domain_parameters(const EC_Domain_Params& dom_pars)
   {
   if(mp_dom_pars.get())
      {
      // they are already set, we must ensure that they are equal to the arg
      if(dom_pars != *mp_dom_pars.get())
         throw Invalid_Argument("EC_PublicKey::set_domain_parameters - cannot reset to a new value");

      return;
      }

   if(m_enc_public_point.size() == 0)
      throw Invalid_State("EC_PublicKey::set_domain_parameters(): encoded public point isn't set");

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
   mp_public_point.reset(new PointGFp(tmp_pp));
   mp_dom_pars = p_tmp_pars;
   }

void GOST_3410_PublicKey::set_all_values(const GOST_3410_PublicKey& other)
   {
   m_param_enc = other.m_param_enc;
   m_enc_public_point = other.m_enc_public_point;
   if(other.mp_dom_pars.get())
      mp_dom_pars.reset(new EC_Domain_Params(other.domain_parameters()));

   if(other.mp_public_point.get())
      mp_public_point.reset(new PointGFp(other.public_point()));
   }

GOST_3410_PublicKey::GOST_3410_PublicKey(const GOST_3410_PublicKey& other)
   : Public_Key(),
     EC_PublicKey(),
     PK_Verifying_wo_MR_Key()
   {
   set_all_values(other);
   }

const GOST_3410_PublicKey& GOST_3410_PublicKey::operator=(const GOST_3410_PublicKey& rhs)
   {
   set_all_values(rhs);
   return *this;
   }

bool GOST_3410_PublicKey::verify(const byte msg[], u32bit msg_len,
                                 const byte sig[], u32bit sig_len) const
   {
   affirm_init();

   const BigInt& n = mp_dom_pars->get_order();

   if(sig_len != n.bytes()*2)
      return false;

   // NOTE: it is not checked whether the public point is set
   if(mp_dom_pars->get_curve().get_p() == 0)
      throw Internal_Error("domain parameters not set");

   BigInt e(msg, msg_len);

   BigInt r(sig, sig_len / 2);
   BigInt s(sig + sig_len / 2, sig_len / 2);

   if(r < 0 || r >= n || s < 0 || s >= n)
      return false;

   e %= n;
   if(e == 0)
      e = 1;

   BigInt v = inverse_mod(e, n);

   BigInt z1 = (s*v) % n;
   BigInt z2 = (-r*v) % n;

   PointGFp R = (z1 * mp_dom_pars->get_base_point() + z2 * *mp_public_point);

   return (R.get_affine_x().get_value() == r);
   }

GOST_3410_PublicKey::GOST_3410_PublicKey(const EC_Domain_Params& dom_par,
                                 const PointGFp& public_point)
   {
   mp_dom_pars = std::auto_ptr<EC_Domain_Params>(new EC_Domain_Params(dom_par));
   mp_public_point = std::auto_ptr<PointGFp>(new PointGFp(public_point));
   m_param_enc = ENC_EXPLICIT;
   }

void GOST_3410_PublicKey::X509_load_hook()
   {
   EC_PublicKey::X509_load_hook();
   EC_PublicKey::affirm_init();
   }

u32bit GOST_3410_PublicKey::max_input_bits() const
   {
   if(!mp_dom_pars.get())
      {
      throw Invalid_State("GOST_3410_PublicKey::max_input_bits(): domain parameters not set");
      }
   return mp_dom_pars->get_order().bits();
   }

/*************************
* GOST_3410_PrivateKey
*************************/
void GOST_3410_PrivateKey::affirm_init() const // virtual
   {
   EC_PrivateKey::affirm_init();
   }

void GOST_3410_PrivateKey::PKCS8_load_hook(bool generated)
   {
   EC_PrivateKey::PKCS8_load_hook(generated);
   EC_PrivateKey::affirm_init();
   }

void GOST_3410_PrivateKey::set_all_values(const GOST_3410_PrivateKey& other)
   {
   m_private_value = other.m_private_value;
   m_param_enc = other.m_param_enc;
   m_enc_public_point = other.m_enc_public_point;

   if(other.mp_dom_pars.get())
      mp_dom_pars.reset(new EC_Domain_Params(other.domain_parameters()));

   if(other.mp_public_point.get())
      mp_public_point.reset(new PointGFp(other.public_point()));
   }

GOST_3410_PrivateKey::GOST_3410_PrivateKey(GOST_3410_PrivateKey const& other)
   : Public_Key(),
     EC_PublicKey(),
     Private_Key(),
     GOST_3410_PublicKey(),
     EC_PrivateKey(),
     PK_Signing_Key()
   {
   set_all_values(other);
   }

const GOST_3410_PrivateKey& GOST_3410_PrivateKey::operator=(const GOST_3410_PrivateKey& rhs)
   {
   set_all_values(rhs);
   return *this;
   }

SecureVector<byte>
GOST_3410_PrivateKey::sign(const byte msg[],
                           u32bit msg_len,
                           RandomNumberGenerator& rng) const
   {
   affirm_init();

   const BigInt& n = mp_dom_pars->get_order();

   BigInt k;
   do
      k.randomize(rng, n.bits()-1);
   while(k >= n);

   if(m_private_value == 0)
      throw Internal_Error("GOST_3410::sign(): no private key");

   if(n == 0)
      throw Internal_Error("GOST_3410::sign(): domain parameters not set");

   BigInt e(msg, msg_len);

   e %= n;
   if(e == 0)
      e = 1;

   PointGFp k_times_P(mp_dom_pars->get_base_point());
   k_times_P.mult_this_secure(k, n, n-1);
   k_times_P.check_invariants();
   BigInt r = k_times_P.get_affine_x().get_value() % n;

   if(r == 0)
      throw Internal_Error("GOST_3410::sign: r was zero");

   BigInt s = (r*m_private_value + k*e) % n;

   SecureVector<byte> output(2*n.bytes());
   r.binary_encode(output + (output.size() / 2 - r.bytes()));
   s.binary_encode(output + (output.size() - s.bytes()));
   return output;
   }

}
