/*
* PK Key
* (C) 1999-2010,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pk_algs.h>
#include <botan/parsing.h>

#if defined(BOTAN_HAS_RSA)
  #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_DSA)
  #include <botan/dsa.h>
#endif

#if defined(BOTAN_HAS_DL_GROUP)
  #include <botan/dl_group.h>
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  #include <botan/dh.h>
#endif

#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)
  #include <botan/ecc_key.h>
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

#if defined(BOTAN_HAS_ED25519)
  #include <botan/ed25519.h>
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
  #include <botan/gost_3410.h>
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

#if defined(BOTAN_HAS_XMSS_RFC8391)
  #include <botan/xmss.h>
#endif

#if defined(BOTAN_HAS_SM2)
  #include <botan/sm2.h>
#endif

#if defined(BOTAN_HAS_OPENSSL)
  #include <botan/internal/openssl.h>
#endif

namespace Botan {

std::unique_ptr<Public_Key>
load_public_key(const AlgorithmIdentifier& alg_id,
                const std::vector<uint8_t>& key_bits)
   {
   const std::string oid_str = alg_id.get_oid().to_formatted_string();
   const std::vector<std::string> alg_info = split_on(oid_str, '/');
   const std::string alg_name = alg_info[0];

#if defined(BOTAN_HAS_RSA)
   if(alg_name == "RSA")
      return std::unique_ptr<Public_Key>(new RSA_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_CURVE_25519)
   if(alg_name == "Curve25519")
      return std::unique_ptr<Public_Key>(new Curve25519_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_MCELIECE)
   if(alg_name == "McEliece")
      return std::unique_ptr<Public_Key>(new McEliece_PublicKey(key_bits));
#endif

#if defined(BOTAN_HAS_ECDSA)
   if(alg_name == "ECDSA")
      return std::unique_ptr<Public_Key>(new ECDSA_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_ECDH)
   if(alg_name == "ECDH")
      return std::unique_ptr<Public_Key>(new ECDH_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   if(alg_name == "DH")
      return std::unique_ptr<Public_Key>(new DH_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_DSA)
   if(alg_name == "DSA")
      return std::unique_ptr<Public_Key>(new DSA_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_ELGAMAL)
   if(alg_name == "ElGamal")
      return std::unique_ptr<Public_Key>(new ElGamal_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_ECGDSA)
   if(alg_name == "ECGDSA")
      return std::unique_ptr<Public_Key>(new ECGDSA_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_ECKCDSA)
   if(alg_name == "ECKCDSA")
      return std::unique_ptr<Public_Key>(new ECKCDSA_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_ED25519)
   if(alg_name == "Ed25519")
      return std::unique_ptr<Public_Key>(new Ed25519_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
   if(alg_name == "GOST-34.10" || alg_name == "GOST-34.10-2012-256" || alg_name == "GOST-34.10-2012-512")
      return std::unique_ptr<Public_Key>(new GOST_3410_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_SM2)
   if(alg_name == "SM2" || alg_name == "SM2_Sig" || alg_name == "SM2_Enc")
      return std::unique_ptr<Public_Key>(new SM2_PublicKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_XMSS_RFC8391)
   if(alg_name == "XMSS")
      return std::unique_ptr<Public_Key>(new XMSS_PublicKey(key_bits));
#endif

   throw Decoding_Error("Unknown or unavailable public key algorithm " + alg_name);
   }

std::unique_ptr<Private_Key>
load_private_key(const AlgorithmIdentifier& alg_id,
                 const secure_vector<uint8_t>& key_bits)
   {
   const std::string alg_name = alg_id.get_oid().to_formatted_string();

#if defined(BOTAN_HAS_RSA)
   if(alg_name == "RSA")
      return std::unique_ptr<Private_Key>(new RSA_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_CURVE_25519)
   if(alg_name == "Curve25519")
      return std::unique_ptr<Private_Key>(new Curve25519_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_ECDSA)
   if(alg_name == "ECDSA")
      return std::unique_ptr<Private_Key>(new ECDSA_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_ECDH)
   if(alg_name == "ECDH")
      return std::unique_ptr<Private_Key>(new ECDH_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   if(alg_name == "DH")
      return std::unique_ptr<Private_Key>(new DH_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_DSA)
   if(alg_name == "DSA")
      return std::unique_ptr<Private_Key>(new DSA_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_MCELIECE)
   if(alg_name == "McEliece")
      return std::unique_ptr<Private_Key>(new McEliece_PrivateKey(key_bits));
#endif

#if defined(BOTAN_HAS_ECGDSA)
   if(alg_name == "ECGDSA")
      return std::unique_ptr<Private_Key>(new ECGDSA_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_ECKCDSA)
   if(alg_name == "ECKCDSA")
      return std::unique_ptr<Private_Key>(new ECKCDSA_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_ED25519)
   if(alg_name == "Ed25519")
      return std::unique_ptr<Private_Key>(new Ed25519_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
   if(alg_name == "GOST-34.10" || alg_name == "GOST-34.10-2012-256" || alg_name == "GOST-34.10-2012-512")
      return std::unique_ptr<Private_Key>(new GOST_3410_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_SM2)
   if(alg_name == "SM2" || alg_name == "SM2_Sig" || alg_name == "SM2_Enc")
      return std::unique_ptr<Private_Key>(new SM2_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_ELGAMAL)
   if(alg_name == "ElGamal")
      return std::unique_ptr<Private_Key>(new ElGamal_PrivateKey(alg_id, key_bits));
#endif

#if defined(BOTAN_HAS_XMSS_RFC8391)
   if(alg_name == "XMSS")
      return std::unique_ptr<Private_Key>(new XMSS_PrivateKey(key_bits));
#endif

   throw Decoding_Error("Unknown or unavailable public key algorithm " + alg_name);
   }

#if defined(BOTAN_HAS_ECC_GROUP)

namespace {

std::string default_ec_group_for(const std::string& alg_name)
   {
   if(alg_name == "SM2" || alg_name == "SM2_Enc" || alg_name == "SM2_Sig")
      return "sm2p256v1";
   if(alg_name == "GOST-34.10" || alg_name == "GOST-34.10-2012-256")
      return "gost_256A";
   if(alg_name == "GOST-34.10-2012-512")
      return "gost_512A";
   if(alg_name == "ECGDSA")
      return "brainpool256r1";
   return "secp256r1";

   }

}

#endif

std::unique_ptr<Private_Key>
create_private_key(const std::string& alg_name,
                   RandomNumberGenerator& rng,
                   const std::string& params,
                   const std::string& provider)
   {
   /*
   * Default paramaters are chosen for work factor > 2**128 where possible
   */

#if defined(BOTAN_HAS_CURVE_25519)
   if(alg_name == "Curve25519")
      return std::unique_ptr<Private_Key>(new Curve25519_PrivateKey(rng));
#endif

#if defined(BOTAN_HAS_RSA)
   if(alg_name == "RSA")
      {
      const size_t rsa_bits = (params.empty() ? 3072 : to_u32bit(params));
#if defined(BOTAN_HAS_OPENSSL)
      if(provider.empty() || provider == "openssl")
         {
         std::unique_ptr<Botan::Private_Key> pk;
         if((pk = make_openssl_rsa_private_key(rng, rsa_bits)))
            return pk;

         if(!provider.empty())
            return nullptr;
         }
#endif
      return std::unique_ptr<Private_Key>(new RSA_PrivateKey(rng, rsa_bits));
      }
#endif

#if defined(BOTAN_HAS_MCELIECE)
   if(alg_name == "McEliece")
      {
      std::vector<std::string> mce_param =
         Botan::split_on(params.empty() ? "2960,57" : params, ',');

      if(mce_param.size() != 2)
         throw Invalid_Argument("create_private_key bad McEliece parameters " + params);

      size_t mce_n = Botan::to_u32bit(mce_param[0]);
      size_t mce_t = Botan::to_u32bit(mce_param[1]);

      return std::unique_ptr<Botan::Private_Key>(new Botan::McEliece_PrivateKey(rng, mce_n, mce_t));
      }
#endif

#if defined(BOTAN_HAS_XMSS_RFC8391)
   if(alg_name == "XMSS")
      {
      return std::unique_ptr<Private_Key>(
         new XMSS_PrivateKey(XMSS_Parameters(params.empty() ? "XMSS-SHA2_10_512" : params).oid(), rng));
      }
#endif

#if defined(BOTAN_HAS_ED25519)
   if(alg_name == "Ed25519")
      {
      return std::unique_ptr<Private_Key>(new Ed25519_PrivateKey(rng));
      }
#endif

   // ECC crypto
#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)

   if(alg_name == "ECDSA" ||
      alg_name == "ECDH" ||
      alg_name == "ECKCDSA" ||
      alg_name == "ECGDSA" ||
      alg_name == "SM2" ||
      alg_name == "SM2_Sig" ||
      alg_name == "SM2_Enc" ||
      alg_name == "GOST-34.10" ||
      alg_name == "GOST-34.10-2012-256" ||
      alg_name == "GOST-34.10-2012-512")
      {
      const EC_Group ec_group(params.empty() ? default_ec_group_for(alg_name) : params);

#if defined(BOTAN_HAS_ECDSA)
      if(alg_name == "ECDSA")
         return std::unique_ptr<Private_Key>(new ECDSA_PrivateKey(rng, ec_group));
#endif

#if defined(BOTAN_HAS_ECDH)
      if(alg_name == "ECDH")
         return std::unique_ptr<Private_Key>(new ECDH_PrivateKey(rng, ec_group));
#endif

#if defined(BOTAN_HAS_ECKCDSA)
      if(alg_name == "ECKCDSA")
         return std::unique_ptr<Private_Key>(new ECKCDSA_PrivateKey(rng, ec_group));
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
      if(alg_name == "GOST-34.10" || alg_name == "GOST-34.10-2012-256" || alg_name == "GOST-34.10-2012-512")
         return std::unique_ptr<Private_Key>(new GOST_3410_PrivateKey(rng, ec_group));
#endif

#if defined(BOTAN_HAS_SM2)
      if(alg_name == "SM2" || alg_name == "SM2_Sig" || alg_name == "SM2_Enc")
         return std::unique_ptr<Private_Key>(new SM2_PrivateKey(rng, ec_group));
#endif

#if defined(BOTAN_HAS_ECGDSA)
      if(alg_name == "ECGDSA")
         return std::unique_ptr<Private_Key>(new ECGDSA_PrivateKey(rng, ec_group));
#endif
      }
#endif

   // DL crypto
#if defined(BOTAN_HAS_DL_GROUP)
   if(alg_name == "DH" || alg_name == "DSA" || alg_name == "ElGamal")
      {
      std::string default_group = (alg_name == "DSA") ? "dsa/botan/2048" : "modp/ietf/2048";
      DL_Group modp_group(params.empty() ? default_group : params);

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
      if(alg_name == "DH")
         return std::unique_ptr<Private_Key>(new DH_PrivateKey(rng, modp_group));
#endif

#if defined(BOTAN_HAS_DSA)
      if(alg_name == "DSA")
         return std::unique_ptr<Private_Key>(new DSA_PrivateKey(rng, modp_group));
#endif

#if defined(BOTAN_HAS_ELGAMAL)
      if(alg_name == "ElGamal")
         return std::unique_ptr<Private_Key>(new ElGamal_PrivateKey(rng, modp_group));
#endif
      }
#endif

   BOTAN_UNUSED(alg_name, rng, params, provider);

   return std::unique_ptr<Private_Key>();
   }

std::vector<std::string>
probe_provider_private_key(const std::string& alg_name,
                           const std::vector<std::string> possible)
   {
   std::vector<std::string> providers;
   for(auto&& prov : possible)
      {
      if(prov == "base" ||
#if defined(BOTAN_HAS_OPENSSL)
         (prov == "openssl" && alg_name == "RSA") ||
#endif
         0)
         {
         providers.push_back(prov); // available
         }
      }

   BOTAN_UNUSED(alg_name);

   return providers;
   }
}
