/*
* PK Key
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/pk_algs.h>
#include <botan/oids.h>

#include <stdio.h>

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

namespace Botan {

BOTAN_DLL Public_Key* make_public_key(const AlgorithmIdentifier& alg_id,
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

#if defined(BOTAN_HAS_ELG)
   if(alg_name == "ELG")
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

   return 0;
   }

namespace {

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

#if defined(BOTAN_HAS_GOST_34_10_2001)
   if(alg_name == "GOST-34.10") return new GOST_3410_PrivateKey;
#endif

   return 0;
   }

}

BOTAN_DLL Private_Key* make_private_key(const AlgorithmIdentifier& alg_id,
                                        const MemoryRegion<byte>& key_bits,
                                        RandomNumberGenerator& rng)
   {
   const std::string alg_name = OIDS::lookup(alg_id.oid);
   if(alg_name == "")
      throw Decoding_Error("Unknown algorithm OID: " + alg_id.oid.as_string());

   std::auto_ptr<Private_Key> key(get_private_key(alg_name));

   if(!key.get())
      throw PKCS8_Exception("Unknown PK algorithm/OID: " + alg_name + ", " +
                           alg_id.oid.as_string());

   std::auto_ptr<PKCS8_Decoder> decoder(key->pkcs8_decoder(rng));

   if(!decoder.get())
      throw Decoding_Error("Key does not support PKCS #8 decoding");

   decoder->alg_id(alg_id);
   decoder->key_bits(key_bits);

   return key.release();
   }

}
