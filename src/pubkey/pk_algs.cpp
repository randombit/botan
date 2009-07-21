/*
* PK Key
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/pk_algs.h>

#if defined(BOTAN_HAS_RSA)
  #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_DSA)
  #include <botan/dsa.h>
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  #include <botan/dh.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
  #include <botan/nr.h>
#endif

#if defined(BOTAN_HAS_RW)
  #include <botan/rw.h>
#endif

#if defined(BOTAN_HAS_ELGAMAL)
  #include <botan/elgamal.h>
#endif

namespace Botan {

/*
* Get an PK public key object
*/
Public_Key* get_public_key(const std::string& alg_name)
   {
#if defined(BOTAN_HAS_RSA)
   if(alg_name == "RSA") return new RSA_PublicKey;
#endif

#if defined(BOTAN_HAS_DSA)
   if(alg_name == "DSA") return new DSA_PublicKey;
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   if(alg_name == "DH")  return new DH_PublicKey;
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
   if(alg_name == "NR")  return new NR_PublicKey;
#endif

#if defined(BOTAN_HAS_RW)
   if(alg_name == "RW")  return new RW_PublicKey;
#endif

#if defined(BOTAN_HAS_ELG)
   if(alg_name == "ELG") return new ElGamal_PublicKey;
#endif

#if defined(BOTAN_HAS_ECDSA)
   if(alg_name == "ECDSA") return new ECDSA_PublicKey;
#endif

   return 0;
   }

/*
* Get an PK private key object
*/
Private_Key* get_private_key(const std::string& alg_name)
   {
#if defined(BOTAN_HAS_RSA)
   if(alg_name == "RSA") return new RSA_PrivateKey;
#endif

#if defined(BOTAN_HAS_DSA)
   if(alg_name == "DSA") return new DSA_PrivateKey;
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   if(alg_name == "DH")  return new DH_PrivateKey;
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
   if(alg_name == "NR")  return new NR_PrivateKey;
#endif

#if defined(BOTAN_HAS_RW)
   if(alg_name == "RW")  return new RW_PrivateKey;
#endif

#if defined(BOTAN_HAS_ELG)
   if(alg_name == "ELG") return new ElGamal_PrivateKey;
#endif

#if defined(BOTAN_HAS_ECDSA)
   if(alg_name == "ECDSA") return new ECDSA_PrivateKey;
#endif

   return 0;
   }

}
