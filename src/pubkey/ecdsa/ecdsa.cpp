/*
* ECDSA implemenation
* (C) 2007 Manuel Hartl, FlexSecure GmbH
*     2007 Falko Strenzke, FlexSecure GmbH
*     2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ecdsa.h>

#include <assert.h>

namespace Botan {

ECDSA_PrivateKey::ECDSA_PrivateKey(RandomNumberGenerator& rng,
                                   const EC_Domain_Params& dom_pars)
   {
   domain_params = dom_pars;
   generate_private_key(rng);

   ecdsa_core = ECDSA_Core(domain(), private_value(), public_point());
   }

ECDSA_PrivateKey::ECDSA_PrivateKey(const EC_Domain_Params& dom_pars,
                                   const BigInt& x)
   {
   domain_params = dom_pars;

   private_key = x;
   public_key = domain().get_base_point() * x;

   try
      {
      public_key.check_invariants();
      }
   catch(Illegal_Point& e)
      {
      throw Invalid_State("ECDSA key generation failed");
      }

   ecdsa_core = ECDSA_Core(domain(), private_value(), public_point());
   }

bool ECDSA_PublicKey::verify(const byte msg[], u32bit msg_len,
                             const byte sig[], u32bit sig_len) const
   {
   return ecdsa_core.verify(msg, msg_len, sig, sig_len);
   }

ECDSA_PublicKey::ECDSA_PublicKey(const EC_Domain_Params& dom_par,
                                 const PointGFp& pub_point)
   {
   domain_encoding = EC_DOMPAR_ENC_EXPLICIT;
   domain_params = dom_par;
   public_key = pub_point;

   ecdsa_core = ECDSA_Core(domain(), 0, public_point());
   }

void ECDSA_PublicKey::X509_load_hook()
   {
   EC_PublicKey::X509_load_hook();
   ecdsa_core = ECDSA_Core(domain(), 0, public_point());
   }

void ECDSA_PrivateKey::PKCS8_load_hook(bool generated)
   {
   EC_PrivateKey::PKCS8_load_hook(generated);
   ecdsa_core = ECDSA_Core(domain(), private_value(), public_point());
   }

SecureVector<byte> ECDSA_PrivateKey::sign(const byte msg[],
                                          u32bit msg_len,
                                          RandomNumberGenerator& rng) const
   {
   const BigInt& n = domain().get_order();

   if(n == 0)
      throw Invalid_State("ECDSA_PrivateKey: Not initialized");

   assert(n.bits() >= 1);

   BigInt k;
   do
      k.randomize(rng, n.bits()-1);
   while(k >= n);

   return ecdsa_core.sign(msg, msg_len, k);
   }

}
