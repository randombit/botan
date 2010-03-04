/*
* GOST 34.10-2001 implemenation
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*          Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/gost_3410.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>

namespace Botan {

MemoryVector<byte> GOST_3410_PublicKey::x509_subject_public_key() const
   {
   // Trust CryptoPro to come up with something obnoxious
   const BigInt& x = public_point().get_affine_x();
   const BigInt& y = public_point().get_affine_y();

   MemoryVector<byte> bits(2*std::max(x.bytes(), y.bytes()));

   y.binary_encode(bits + (bits.size() / 2 - y.bytes()));
   x.binary_encode(bits + (bits.size() - x.bytes()));

   return DER_Encoder().encode(bits, OCTET_STRING).get_contents();
   }

AlgorithmIdentifier GOST_3410_PublicKey::algorithm_identifier() const
   {
   MemoryVector<byte> params =
      DER_Encoder().start_cons(SEQUENCE)
         .encode(OID(domain().get_oid()))
         .end_cons()
      .get_contents();

   return AlgorithmIdentifier(get_oid(), params);
   }

GOST_3410_PublicKey::GOST_3410_PublicKey(const AlgorithmIdentifier& alg_id,
                                         const MemoryRegion<byte>& key_bits)
   {
   OID ecc_param_id;

   // Also includes hash and cipher OIDs... brilliant design guys
   BER_Decoder(alg_id.parameters).start_cons(SEQUENCE).decode(ecc_param_id);

   domain_params = EC_Domain_Params(ecc_param_id);

   SecureVector<byte> bits;
   BER_Decoder(key_bits).decode(bits, OCTET_STRING);

   const u32bit part_size = bits.size() / 2;

   BigInt y(bits, part_size);
   BigInt x(bits + part_size, part_size);

   public_key = PointGFp(domain().get_curve(), x, y);

   try
      {
      public_key.check_invariants();
      }
   catch(Illegal_Point)
      {
      throw Internal_Error("Loaded ECC public key failed self test");
      }
   }

bool GOST_3410_PublicKey::verify(const byte msg[], u32bit msg_len,
                                 const byte sig[], u32bit sig_len) const
   {
   const BigInt& n = domain().get_order();

   if(n == 0)
      throw Invalid_State("domain parameters not set");

   if(sig_len != n.bytes()*2)
      return false;

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

SecureVector<byte>
GOST_3410_PrivateKey::sign(const byte msg[],
                           u32bit msg_len,
                           RandomNumberGenerator& rng) const
   {
   if(private_value() == 0)
      throw Invalid_State("GOST_3410::sign(): no private key");

   const BigInt& n = domain().get_order();

   if(n == 0)
      throw Invalid_State("GOST_3410::sign(): domain parameters not set");

   BigInt k;
   do
      k.randomize(rng, n.bits()-1);
   while(k >= n);

   BigInt e(msg, msg_len);

   e %= n;
   if(e == 0)
      e = 1;

   PointGFp k_times_P = domain().get_base_point() * k;
   k_times_P.check_invariants();

   BigInt r = k_times_P.get_affine_x() % n;

   if(r == 0)
      throw Invalid_State("GOST_3410::sign: r was zero");

   BigInt s = (r*private_value() + k*e) % n;

   SecureVector<byte> output(2*n.bytes());
   r.binary_encode(output + (output.size() / 2 - r.bytes()));
   s.binary_encode(output + (output.size() - s.bytes()));
   return output;
   }

}
