/*
* TLS Cipher Suites
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_suites.h>
#include <botan/tls_exceptn.h>

namespace Botan {

/**
* Convert an SSL/TLS ciphersuite to algorithm fields
*/
TLS_Ciphersuite_Algos CipherSuite::lookup_ciphersuite(u16bit suite)
   {
   if(suite == TLS_RSA_WITH_RC4_128_MD5)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_RSA |
                                   TLS_ALGO_KEYEXCH_NOKEX |
                                   TLS_ALGO_MAC_MD5 |
                                   TLS_ALGO_CIPHER_RC4_128);

   if(suite == TLS_RSA_WITH_RC4_128_SHA)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_RSA |
                                   TLS_ALGO_KEYEXCH_NOKEX |
                                   TLS_ALGO_MAC_SHA1 |
                                   TLS_ALGO_CIPHER_RC4_128);

   if(suite == TLS_RSA_WITH_3DES_EDE_CBC_SHA)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_RSA |
                                   TLS_ALGO_KEYEXCH_NOKEX |
                                   TLS_ALGO_MAC_SHA1 |
                                   TLS_ALGO_CIPHER_3DES_CBC);

   if(suite == TLS_RSA_WITH_AES_128_CBC_SHA)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_RSA |
                                   TLS_ALGO_KEYEXCH_NOKEX |
                                   TLS_ALGO_MAC_SHA1 |
                                   TLS_ALGO_CIPHER_AES128_CBC);

   if(suite == TLS_RSA_WITH_AES_256_CBC_SHA)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_RSA |
                                   TLS_ALGO_KEYEXCH_NOKEX |
                                   TLS_ALGO_MAC_SHA1 |
                                   TLS_ALGO_CIPHER_AES256_CBC);

   if(suite == TLS_RSA_WITH_SEED_CBC_SHA)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_RSA |
                                   TLS_ALGO_KEYEXCH_NOKEX |
                                   TLS_ALGO_MAC_SHA1 |
                                   TLS_ALGO_CIPHER_SEED_CBC);

   if(suite == TLS_RSA_WITH_AES_128_CBC_SHA256)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_RSA |
                                   TLS_ALGO_KEYEXCH_NOKEX |
                                   TLS_ALGO_MAC_SHA256 |
                                   TLS_ALGO_CIPHER_AES128_CBC);

   if(suite == TLS_RSA_WITH_AES_256_CBC_SHA256)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_RSA |
                                   TLS_ALGO_KEYEXCH_NOKEX |
                                   TLS_ALGO_MAC_SHA256 |
                                   TLS_ALGO_CIPHER_AES256_CBC);

   if(suite == TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_DSA |
                                   TLS_ALGO_KEYEXCH_DH |
                                   TLS_ALGO_MAC_SHA1 |
                                   TLS_ALGO_CIPHER_3DES_CBC);

   if(suite == TLS_DHE_DSS_WITH_AES_128_CBC_SHA)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_DSA |
                                   TLS_ALGO_KEYEXCH_DH |
                                   TLS_ALGO_MAC_SHA1 |
                                   TLS_ALGO_CIPHER_AES128_CBC);

   if(suite == TLS_DHE_DSS_WITH_SEED_CBC_SHA)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_DSA |
                                   TLS_ALGO_KEYEXCH_DH |
                                   TLS_ALGO_MAC_SHA1 |
                                   TLS_ALGO_CIPHER_SEED_CBC);

   if(suite == TLS_DHE_DSS_WITH_AES_256_CBC_SHA)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_DSA |
                                   TLS_ALGO_KEYEXCH_DH |
                                   TLS_ALGO_MAC_SHA1 |
                                   TLS_ALGO_CIPHER_AES256_CBC);

   if(suite == TLS_DHE_DSS_WITH_AES_128_CBC_SHA256)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_DSA |
                                   TLS_ALGO_KEYEXCH_DH |
                                   TLS_ALGO_MAC_SHA256 |
                                   TLS_ALGO_CIPHER_AES128_CBC);

   if(suite == TLS_DHE_DSS_WITH_AES_256_CBC_SHA256)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_DSA |
                                   TLS_ALGO_KEYEXCH_DH |
                                   TLS_ALGO_MAC_SHA256 |
                                   TLS_ALGO_CIPHER_AES256_CBC);

   if(suite == TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_RSA |
                                   TLS_ALGO_KEYEXCH_DH |
                                   TLS_ALGO_MAC_SHA1 |
                                   TLS_ALGO_CIPHER_3DES_CBC);

   if(suite == TLS_DHE_RSA_WITH_AES_128_CBC_SHA)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_RSA |
                                   TLS_ALGO_KEYEXCH_DH |
                                   TLS_ALGO_MAC_SHA1 |
                                   TLS_ALGO_CIPHER_AES128_CBC);

   if(suite == TLS_DHE_DSS_WITH_SEED_CBC_SHA)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_RSA |
                                   TLS_ALGO_KEYEXCH_DH |
                                   TLS_ALGO_MAC_SHA1 |
                                   TLS_ALGO_CIPHER_SEED_CBC);

   if(suite == TLS_DHE_RSA_WITH_AES_256_CBC_SHA)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_RSA |
                                   TLS_ALGO_KEYEXCH_DH |
                                   TLS_ALGO_MAC_SHA1 |
                                   TLS_ALGO_CIPHER_AES256_CBC);

   if(suite == TLS_DHE_RSA_WITH_AES_128_CBC_SHA256)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_RSA |
                                   TLS_ALGO_KEYEXCH_DH |
                                   TLS_ALGO_MAC_SHA256 |
                                   TLS_ALGO_CIPHER_AES128_CBC);

   if(suite == TLS_DHE_RSA_WITH_AES_256_CBC_SHA256)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_RSA |
                                   TLS_ALGO_KEYEXCH_DH |
                                   TLS_ALGO_MAC_SHA256 |
                                   TLS_ALGO_CIPHER_AES256_CBC);

   if(suite == TLS_ECDHE_ECDSA_WITH_RC4_128_SHA)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_ECDSA |
                                   TLS_ALGO_KEYEXCH_ECDH |
                                   TLS_ALGO_MAC_SHA1 |
                                   TLS_ALGO_CIPHER_RC4_128);

   if(suite == TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_ECDSA |
                                   TLS_ALGO_KEYEXCH_ECDH |
                                   TLS_ALGO_MAC_SHA1 |
                                   TLS_ALGO_CIPHER_3DES_CBC);

   if(suite == TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_ECDSA |
                                   TLS_ALGO_KEYEXCH_ECDH |
                                   TLS_ALGO_MAC_SHA1 |
                                   TLS_ALGO_CIPHER_AES128_CBC);

   if(suite == TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_ECDSA |
                                   TLS_ALGO_KEYEXCH_ECDH |
                                   TLS_ALGO_MAC_SHA1 |
                                   TLS_ALGO_CIPHER_AES256_CBC);

   if(suite == TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_ECDSA |
                                   TLS_ALGO_KEYEXCH_ECDH |
                                   TLS_ALGO_MAC_SHA256 |
                                   TLS_ALGO_CIPHER_AES128_CBC);

   if(suite == TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_ECDSA |
                                   TLS_ALGO_KEYEXCH_ECDH |
                                   TLS_ALGO_MAC_SHA384 |
                                   TLS_ALGO_CIPHER_AES256_CBC);

   if(suite == TLS_ECDHE_RSA_WITH_RC4_128_SHA)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_RSA |
                                   TLS_ALGO_KEYEXCH_ECDH |
                                   TLS_ALGO_MAC_SHA1 |
                                   TLS_ALGO_CIPHER_RC4_128);

   if(suite == TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_RSA |
                                   TLS_ALGO_KEYEXCH_ECDH |
                                   TLS_ALGO_MAC_SHA1 |
                                   TLS_ALGO_CIPHER_3DES_CBC);

   if(suite == TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_RSA |
                                   TLS_ALGO_KEYEXCH_ECDH |
                                   TLS_ALGO_MAC_SHA1 |
                                   TLS_ALGO_CIPHER_AES128_CBC);

   if(suite == TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_RSA |
                                   TLS_ALGO_KEYEXCH_ECDH |
                                   TLS_ALGO_MAC_SHA1 |
                                   TLS_ALGO_CIPHER_AES256_CBC);

   if(suite == TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_ECDSA |
                                   TLS_ALGO_KEYEXCH_ECDH |
                                   TLS_ALGO_MAC_SHA256 |
                                   TLS_ALGO_CIPHER_AES128_CBC);

   if(suite == TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384)
      return TLS_Ciphersuite_Algos(TLS_ALGO_SIGNER_ECDSA |
                                   TLS_ALGO_KEYEXCH_ECDH |
                                   TLS_ALGO_MAC_SHA384 |
                                   TLS_ALGO_CIPHER_AES256_CBC);

   return TLS_Ciphersuite_Algos(0);
   }

namespace {

std::pair<std::string, size_t> cipher_code_to_name(TLS_Ciphersuite_Algos algo)
   {
   if((algo & TLS_ALGO_CIPHER_MASK) == TLS_ALGO_CIPHER_RC4_128)
      return std::make_pair("ARC4", 16);

   if((algo & TLS_ALGO_CIPHER_MASK) == TLS_ALGO_CIPHER_3DES_CBC)
      return std::make_pair("3DES", 24);

   if((algo & TLS_ALGO_CIPHER_MASK) == TLS_ALGO_CIPHER_AES128_CBC)
      return std::make_pair("AES-128", 16);

   if((algo & TLS_ALGO_CIPHER_MASK) == TLS_ALGO_CIPHER_AES256_CBC)
      return std::make_pair("AES-256", 32);

   if((algo & TLS_ALGO_CIPHER_MASK) == TLS_ALGO_CIPHER_SEED_CBC)
      return std::make_pair("SEED", 16);

   throw TLS_Exception(INTERNAL_ERROR,
                       "CipherSuite: Unknown cipher type " + to_string(algo));
   }

std::string mac_code_to_name(TLS_Ciphersuite_Algos algo)
   {
   if((algo & TLS_ALGO_MAC_MASK) == TLS_ALGO_MAC_MD5)
      return "MD5";

   if((algo & TLS_ALGO_MAC_MASK) == TLS_ALGO_MAC_SHA1)
      return "SHA-1";

   if((algo & TLS_ALGO_MAC_MASK) == TLS_ALGO_MAC_SHA256)
      return "SHA-256";

   if((algo & TLS_ALGO_MAC_MASK) == TLS_ALGO_MAC_SHA384)
      return "SHA-384";

   throw TLS_Exception(INTERNAL_ERROR,
                       "CipherSuite: Unknown MAC type " + to_string(algo));
   }

}

/**
* CipherSuite Constructor
*/
CipherSuite::CipherSuite(u16bit suite_code)
   {
   if(suite_code == 0)
      return;

   TLS_Ciphersuite_Algos algos = lookup_ciphersuite(suite_code);

   if(algos == 0)
      throw Invalid_Argument("Unknown ciphersuite: " + to_string(suite_code));

   sig_algo = TLS_Ciphersuite_Algos(algos & TLS_ALGO_SIGNER_MASK);

   kex_algo = TLS_Ciphersuite_Algos(algos & TLS_ALGO_KEYEXCH_MASK);

   std::pair<std::string, size_t> cipher_info = cipher_code_to_name(algos);

   cipher = cipher_info.first;
   cipher_key_length = cipher_info.second;

   mac = mac_code_to_name(algos);
   }

}
