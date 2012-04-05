/*
* PK Key
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/pk_algs.h>
#include <botan/oids.h>

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

#if defined(BOTAN_HAS_GOST_34_10_2001)
  #include <botan/gost_3410.h>
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

#if defined(BOTAN_HAS_ECDH)
  #include <botan/ecdh.h>
#endif

namespace Botan {

Public_Key* make_public_key(const AlgorithmIdentifier& alg_id,
                            const MemoryRegion<byte>& key_bits)
   {
   const std::string alg_name = OIDS::lookup(alg_id.oid);
   if(alg_name == "")
      throw Decoding_Error("Unknown algorithm OID: " + alg_id.oid.as_string());

#if defined(BOTAN_HAS_RSA)
   if(alg_name == "RSA")
      return new RSA_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_RW)
   if(alg_name == "RW")
      return new RW_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_DSA)
   if(alg_name == "DSA")
      return new DSA_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   if(alg_name == "DH")
      return new DH_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
   if(alg_name == "NR")
      return new NR_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_ELGAMAL)
   if(alg_name == "ElGamal")
      return new ElGamal_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_ECDSA)
   if(alg_name == "ECDSA")
      return new ECDSA_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
   if(alg_name == "GOST-34.10")
      return new GOST_3410_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_ECDH)
   if(alg_name == "ECDH")
      return new ECDH_PublicKey(alg_id, key_bits);
#endif

   return 0;
   }

Private_Key* make_private_key(const AlgorithmIdentifier& alg_id,
                              const MemoryRegion<byte>& key_bits,
                              RandomNumberGenerator& rng)
   {
   const std::string alg_name = OIDS::lookup(alg_id.oid);
   if(alg_name == "")
      throw Decoding_Error("Unknown algorithm OID: " + alg_id.oid.as_string());

#if defined(BOTAN_HAS_RSA)
   if(alg_name == "RSA")
      return new RSA_PrivateKey(alg_id, key_bits, rng);
#endif

#if defined(BOTAN_HAS_RW)
   if(alg_name == "RW")
      return new RW_PrivateKey(alg_id, key_bits, rng);
#endif

#if defined(BOTAN_HAS_DSA)
   if(alg_name == "DSA")
      return new DSA_PrivateKey(alg_id, key_bits, rng);
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   if(alg_name == "DH")
      return new DH_PrivateKey(alg_id, key_bits, rng);
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
   if(alg_name == "NR")
      return new NR_PrivateKey(alg_id, key_bits, rng);
#endif

#if defined(BOTAN_HAS_ELGAMAL)
   if(alg_name == "ElGamal")
      return new ElGamal_PrivateKey(alg_id, key_bits, rng);
#endif

#if defined(BOTAN_HAS_ECDSA)
   if(alg_name == "ECDSA")
      return new ECDSA_PrivateKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
   if(alg_name == "GOST-34.10")
      return new GOST_3410_PrivateKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_ECDH)
   if(alg_name == "ECDH")
      return new ECDH_PrivateKey(alg_id, key_bits);
#endif

   return 0;
   }

}
