/*
* PK Operations
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/core_engine.h>

#if defined(BOTAN_HAS_RSA)
  #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_RW)
  #include <botan/rw.h>
#endif

#if defined(BOTAN_HAS_DSA)
  #include <botan/dsa.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_ELGAMAL)
  #include <botan/elgamal.h>
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
  #include <botan/gost_3410.h>
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
  #include <botan/nr.h>
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  #include <botan/dh.h>
#endif

#if defined(BOTAN_HAS_ECDH)
  #include <botan/ecdh.h>
#endif

namespace Botan {

PK_Ops::Encryption*
Core_Engine::get_encryption_op(const Public_Key& key) const
   {
#if defined(BOTAN_HAS_RSA)
   if(const RSA_PublicKey* s = dynamic_cast<const RSA_PublicKey*>(&key))
      return new RSA_Public_Operation(*s);
#endif

#if defined(BOTAN_HAS_ELGAMAL)
   if(const ElGamal_PublicKey* s = dynamic_cast<const ElGamal_PublicKey*>(&key))
      return new ElGamal_Encryption_Operation(*s);
#endif

   return 0;
   }

PK_Ops::Decryption*
Core_Engine::get_decryption_op(const Private_Key& key) const
   {
#if defined(BOTAN_HAS_RSA)
   if(const RSA_PrivateKey* s = dynamic_cast<const RSA_PrivateKey*>(&key))
      return new RSA_Private_Operation(*s);
#endif

#if defined(BOTAN_HAS_ELGAMAL)
   if(const ElGamal_PrivateKey* s = dynamic_cast<const ElGamal_PrivateKey*>(&key))
      return new ElGamal_Decryption_Operation(*s);
#endif

   return 0;
   }

PK_Ops::Key_Agreement*
Core_Engine::get_key_agreement_op(const Private_Key& key) const
   {
#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   if(const DH_PrivateKey* dh = dynamic_cast<const DH_PrivateKey*>(&key))
      return new DH_KA_Operation(*dh);
#endif

#if defined(BOTAN_HAS_ECDH)
   if(const ECDH_PrivateKey* ecdh = dynamic_cast<const ECDH_PrivateKey*>(&key))
      return new ECDH_KA_Operation(*ecdh);
#endif

   return 0;
   }

PK_Ops::Signature*
Core_Engine::get_signature_op(const Private_Key& key) const
   {
#if defined(BOTAN_HAS_RSA)
   if(const RSA_PrivateKey* s = dynamic_cast<const RSA_PrivateKey*>(&key))
      return new RSA_Private_Operation(*s);
#endif

#if defined(BOTAN_HAS_RW)
   if(const RW_PrivateKey* s = dynamic_cast<const RW_PrivateKey*>(&key))
      return new RW_Signature_Operation(*s);
#endif

#if defined(BOTAN_HAS_DSA)
   if(const DSA_PrivateKey* s = dynamic_cast<const DSA_PrivateKey*>(&key))
      return new DSA_Signature_Operation(*s);
#endif

#if defined(BOTAN_HAS_ECDSA)
   if(const ECDSA_PrivateKey* s = dynamic_cast<const ECDSA_PrivateKey*>(&key))
      return new ECDSA_Signature_Operation(*s);
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
   if(const GOST_3410_PrivateKey* s =
         dynamic_cast<const GOST_3410_PrivateKey*>(&key))
      return new GOST_3410_Signature_Operation(*s);
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
   if(const NR_PrivateKey* s = dynamic_cast<const NR_PrivateKey*>(&key))
      return new NR_Signature_Operation(*s);
#endif

   return 0;
   }

PK_Ops::Verification*
Core_Engine::get_verify_op(const Public_Key& key) const
   {
#if defined(BOTAN_HAS_RSA)
   if(const RSA_PublicKey* s = dynamic_cast<const RSA_PublicKey*>(&key))
      return new RSA_Public_Operation(*s);
#endif

#if defined(BOTAN_HAS_RW)
   if(const RW_PublicKey* s = dynamic_cast<const RW_PublicKey*>(&key))
      return new RW_Verification_Operation(*s);
#endif

#if defined(BOTAN_HAS_DSA)
   if(const DSA_PublicKey* s = dynamic_cast<const DSA_PublicKey*>(&key))
      return new DSA_Verification_Operation(*s);
#endif

#if defined(BOTAN_HAS_ECDSA)
   if(const ECDSA_PublicKey* s = dynamic_cast<const ECDSA_PublicKey*>(&key))
      return new ECDSA_Verification_Operation(*s);
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
   if(const GOST_3410_PublicKey* s =
         dynamic_cast<const GOST_3410_PublicKey*>(&key))
      return new GOST_3410_Verification_Operation(*s);
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
   if(const NR_PublicKey* s = dynamic_cast<const NR_PublicKey*>(&key))
      return new NR_Verification_Operation(*s);
#endif

   return 0;
   }

}
