/**
* TLS Cipher Suites Source File
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_suites.h>
#include <botan/tls_exceptn.h>
#include <botan/parsing.h>
#include <vector>
#include <string>

namespace Botan {

namespace {

/**
* Convert an SSL/TLS ciphersuite to a string
*/
std::string lookup_ciphersuite(u16bit suite)
   {
   if(suite == RSA_RC4_MD5)        return "RSA/NONE/ARC4/16/MD5";
   if(suite == RSA_RC4_SHA)        return "RSA/NONE/ARC4/16/SHA1";
   if(suite == RSA_3DES_SHA)       return "RSA/NONE/3DES/24/SHA1";
   if(suite == RSA_AES128_SHA)     return "RSA/NONE/AES/16/SHA1";
   if(suite == RSA_AES256_SHA)     return "RSA/NONE/AES/32/SHA1";

   if(suite == DHE_RSA_3DES_SHA)   return "RSA/DH/3DES/24/SHA1";
   if(suite == DHE_RSA_AES128_SHA) return "RSA/DH/AES/16/SHA1";
   if(suite == DHE_RSA_AES256_SHA) return "RSA/DH/AES/32/SHA1";

   if(suite == DHE_DSS_3DES_SHA)   return "DSA/DH/3DES/24/SHA1";
   if(suite == DHE_DSS_AES128_SHA) return "DSA/DH/AES/16/SHA1";
   if(suite == DHE_DSS_AES256_SHA) return "DSA/DH/AES/32/SHA1";

   return "";
   }

}

/**
* CipherSuite Constructor
*/
CipherSuite::CipherSuite(u16bit suite_code)
   {
   if(suite_code == 0)
      return;

   std::string suite_string = lookup_ciphersuite(suite_code);

   if(suite_string == "")
      throw Invalid_Argument("Unknown ciphersuite: " +
                             to_string(suite_code));

   std::vector<std::string> suite_info = split_on(suite_string, '/');

   if(suite_info[0] == "RSA")       sig_algo = RSA_SIG;
   else if(suite_info[0] == "DSA")  sig_algo = DSA_SIG;
   else if(suite_info[0] == "NONE") sig_algo = NO_SIG;
   else
      throw TLS_Exception(INTERNAL_ERROR,
                          "CipherSuite: Unknown sig type " + suite_info[0]);

   if(suite_info[1] == "DH")        kex_algo = DH_KEX;
   else if(suite_info[1] == "RSA")  kex_algo = RSA_KEX;
   else if(suite_info[1] == "NONE") kex_algo = NO_KEX;
   else
      throw TLS_Exception(INTERNAL_ERROR,
                          "CipherSuite: Unknown kex type " + suite_info[1]);

   cipher = suite_info[2];
   cipher_key_length = to_u32bit(suite_info[3]);
   mac = suite_info[4];
   }

}
