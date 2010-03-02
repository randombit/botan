/*
* GOST 34.10-2001 implemenation
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*          Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
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

X509_Encoder* GOST_3410_PublicKey::x509_encoder() const
   {
   class GOST_3410_Key_Encoder : public X509_Encoder
      {
      public:
         AlgorithmIdentifier alg_id() const
            {
            return AlgorithmIdentifier(key->get_oid(),
                                       key->domain().DER_encode(key->domain_format()));
            }

         MemoryVector<byte> key_bits() const
            {
            // Trust CryptoPro to come up with something obnoxious
            const BigInt x = key->public_point().get_affine_x();
            const BigInt y = key->public_point().get_affine_y();

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

            key->domain_params = EC_Domain_Params(ecc_param_id);
            }

         void key_bits(const MemoryRegion<byte>& bits)
            {

            SecureVector<byte> key_bits;
            BER_Decoder ber(bits);
            ber.decode(key_bits, OCTET_STRING);

            const u32bit part_size = key_bits.size() / 2;

            BigInt y(key_bits, part_size);
            BigInt x(key_bits + part_size, part_size);

            const BigInt p = key->domain().get_curve().get_p();

            key->public_key = PointGFp(key->domain().get_curve(), x, y);

            key->X509_load_hook();
            }

         GOST_3410_Key_Decoder(GOST_3410_PublicKey* k): key(k) {}
      private:
         GOST_3410_PublicKey* key;
      };

   return new GOST_3410_Key_Decoder(this);
   }

bool GOST_3410_PublicKey::verify(const byte msg[], u32bit msg_len,
                                 const byte sig[], u32bit sig_len) const
   {
   const BigInt& n = domain().get_order();

   if(sig_len != n.bytes()*2)
      return false;

   // NOTE: it is not checked whether the public point is set
   if(domain().get_curve().get_p() == 0)
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

   PointGFp R = (z1 * domain().get_base_point() + z2 * public_point());

   return (R.get_affine_x() == r);
   }

GOST_3410_PublicKey::GOST_3410_PublicKey(const EC_Domain_Params& dom_par,
                                         const PointGFp& pub_point)
   {
   domain_params = dom_par;
   public_key = pub_point;
   domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
   }

SecureVector<byte>
GOST_3410_PrivateKey::sign(const byte msg[],
                           u32bit msg_len,
                           RandomNumberGenerator& rng) const
   {
   const BigInt& n = domain().get_order();

   BigInt k;
   do
      k.randomize(rng, n.bits()-1);
   while(k >= n);

   if(private_value() == 0)
      throw Internal_Error("GOST_3410::sign(): no private key");

   if(n == 0)
      throw Internal_Error("GOST_3410::sign(): domain parameters not set");

   BigInt e(msg, msg_len);

   e %= n;
   if(e == 0)
      e = 1;

   PointGFp k_times_P = domain().get_base_point() * k;
   k_times_P.check_invariants();

   BigInt r = k_times_P.get_affine_x() % n;

   if(r == 0)
      throw Internal_Error("GOST_3410::sign: r was zero");

   BigInt s = (r*private_value() + k*e) % n;

   SecureVector<byte> output(2*n.bytes());
   r.binary_encode(output + (output.size() / 2 - r.bytes()));
   s.binary_encode(output + (output.size() - s.bytes()));
   return output;
   }

}
