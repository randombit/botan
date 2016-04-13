/*
* PK Key
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
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

#if defined(BOTAN_HAS_ECGDSA)
  #include <botan/ecgdsa.h>
#endif

#if defined(BOTAN_HAS_ECKCDSA)
  #include <botan/eckcdsa.h>
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

#if defined(BOTAN_HAS_CURVE_25519)
  #include <botan/curve25519.h>
#endif

#if defined(BOTAN_HAS_MCELIECE)
  #include <botan/mceliece.h>
#endif

namespace Botan {

Public_Key* make_public_key(const AlgorithmIdentifier& alg_id,
                            const secure_vector<byte>& key_bits)
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

#if defined(BOTAN_HAS_ECGDSA)
   if(alg_name == "ECGDSA")
      return new ECGDSA_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_ECKCDSA)
   if(alg_name == "ECKCDSA")
      return new ECKCDSA_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
   if(alg_name == "GOST-34.10")
      return new GOST_3410_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_ECDH)
   if(alg_name == "ECDH")
      return new ECDH_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_CURVE_25519)
   if(alg_name == "Curve25519")
      return new Curve25519_PublicKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_MCELIECE)
   if(alg_name == "McEliece")
      return new McEliece_PublicKey(unlock(key_bits));
#endif

   throw Decoding_Error("Unhandled PK algorithm " + alg_name);
   }

Private_Key* make_private_key(const AlgorithmIdentifier& alg_id,
                              const secure_vector<byte>& key_bits,
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

#if defined(BOTAN_HAS_ECGDSA)
   if(alg_name == "ECGDSA")
      return new ECGDSA_PrivateKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_ECKCDSA)
   if(alg_name == "ECKCDSA")
      return new ECKCDSA_PrivateKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
   if(alg_name == "GOST-34.10")
      return new GOST_3410_PrivateKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_ECDH)
   if(alg_name == "ECDH")
      return new ECDH_PrivateKey(alg_id, key_bits);
#endif

#if defined(BOTAN_HAS_CURVE_25519)
   if(alg_name == "Curve25519")
      return new Curve25519_PrivateKey(alg_id, key_bits, rng);
#endif

#if defined(BOTAN_HAS_MCELIECE)
   if(alg_name == "McEliece")
      return new McEliece_PrivateKey(key_bits);
#endif

   throw Decoding_Error("Unhandled PK algorithm " + alg_name);
   }

}
