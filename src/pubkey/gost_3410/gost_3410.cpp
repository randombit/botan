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

   u32bit part_size = std::max(x.bytes(), y.bytes());

   MemoryVector<byte> bits(2*part_size);

   x.binary_encode(bits + (part_size - x.bytes()));
   y.binary_encode(bits + (2*part_size - y.bytes()));

   // Keys are stored in little endian format (WTF)
   for(u32bit i = 0; i != part_size / 2; ++i)
      {
      std::swap(bits[i], bits[part_size-1-i]);
      std::swap(bits[part_size+i], bits[2*part_size-1-i]);
      }

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

   // Keys are stored in little endian format (WTF)
   for(u32bit i = 0; i != part_size / 2; ++i)
      {
      std::swap(bits[i], bits[part_size-1-i]);
      std::swap(bits[part_size+i], bits[2*part_size-1-i]);
      }

   BigInt x(bits, part_size);
   BigInt y(bits + part_size, part_size);

   public_key = PointGFp(domain().get_curve(), x, y);

   try
      {
      public_key.check_invariants();
      }
   catch(Illegal_Point)
      {
      throw Internal_Error("Loaded GOST 34.10 public key failed self test");
      }
   }

GOST_3410_Signature_Operation::GOST_3410_Signature_Operation(
   const GOST_3410_PrivateKey& gost_3410) :

   base_point(gost_3410.domain().get_base_point()),
   order(gost_3410.domain().get_order()),
   x(gost_3410.private_value())
   {
   }

SecureVector<byte>
GOST_3410_Signature_Operation::sign(const byte msg[], u32bit msg_len,
                                    RandomNumberGenerator& rng)
   {
   BigInt k;
   do
      k.randomize(rng, order.bits()-1);
   while(k >= order);

   BigInt e(msg, msg_len);

   e %= order;
   if(e == 0)
      e = 1;

   PointGFp k_times_P = base_point * k;
   k_times_P.check_invariants();

   BigInt r = k_times_P.get_affine_x() % order;

   BigInt s = (r*x + k*e) % order;

   if(r == 0 || s == 0)
      throw Invalid_State("GOST 34.10: r == 0 || s == 0");

   SecureVector<byte> output(2*order.bytes());
   r.binary_encode(output + (output.size() / 2 - r.bytes()));
   s.binary_encode(output + (output.size() - s.bytes()));
   return output;
   }


GOST_3410_Verification_Operation::GOST_3410_Verification_Operation(const GOST_3410_PublicKey& gost) :
   base_point(gost.domain().get_base_point()),
   public_point(gost.public_point()),
   order(gost.domain().get_order())
   {
   }

bool GOST_3410_Verification_Operation::verify(const byte msg[], u32bit msg_len,
                                              const byte sig[], u32bit sig_len)
   {
   if(sig_len != order.bytes()*2)
      return false;

   BigInt e(msg, msg_len);

   BigInt r(sig, sig_len / 2);
   BigInt s(sig + sig_len / 2, sig_len / 2);

   if(r < 0 || r >= order || s < 0 || s >= order)
      return false;

   e %= order;
   if(e == 0)
      e = 1;

   BigInt v = inverse_mod(e, order);

   BigInt z1 = (s*v) % order;
   BigInt z2 = (-r*v) % order;

   PointGFp R = (z1 * base_point + z2 * public_point);

   return (R.get_affine_x() == r);
   }

}
