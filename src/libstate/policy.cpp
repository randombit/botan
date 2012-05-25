/*
* Default Policy
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/libstate.h>

namespace Botan {

namespace {

/*
* OID loading helper function
*/
void add_oid(Library_State& config,
             const std::string& oid_str,
             const std::string& name)
   {
   if(!config.is_set("oid2str", oid_str))
      config.set("oid2str", oid_str, name);
   if(!config.is_set("str2oid", name))
      config.set("str2oid", name, oid_str);
   }

/*
* Load all of the default OIDs
*/
void set_default_oids(Library_State& config)
   {
   /* Public key types */
   add_oid(config, "1.2.840.113549.1.1.1", "RSA");
   add_oid(config, "2.5.8.1.1", "RSA"); // RSA alternate
   add_oid(config, "1.2.840.10040.4.1", "DSA");
   add_oid(config, "1.2.840.10046.2.1", "DH");
   add_oid(config, "1.3.6.1.4.1.3029.1.2.1", "ElGamal");
   add_oid(config, "1.3.6.1.4.1.25258.1.1", "RW");
   add_oid(config, "1.3.6.1.4.1.25258.1.2", "NR");

   // X9.62 ecPublicKey, valid for ECDSA and ECDH (RFC 3279 sec 2.3.5)
   add_oid(config, "1.2.840.10045.2.1", "ECDSA");

   /*
   * This is an OID defined for ECDH keys though rarely used for such.
   * In this configuration it is accepted on decoding, but not used for
   * encoding. You can enable it for encoding by calling
   *    global_state().set("str2oid", "ECDH", "1.3.132.1.12")
   * from your application code.
   */
   config.set("oid2str", "1.3.132.1.12", "ECDH");

   add_oid(config, "1.2.643.2.2.19", "GOST-34.10"); // RFC 4491

   /* Ciphers */
   add_oid(config, "1.3.14.3.2.7", "DES/CBC");
   add_oid(config, "1.2.840.113549.3.7", "TripleDES/CBC");
   add_oid(config, "1.2.840.113549.3.2", "RC2/CBC");
   add_oid(config, "1.2.840.113533.7.66.10", "CAST-128/CBC");
   add_oid(config, "2.16.840.1.101.3.4.1.2", "AES-128/CBC");
   add_oid(config, "2.16.840.1.101.3.4.1.22", "AES-192/CBC");
   add_oid(config, "2.16.840.1.101.3.4.1.42", "AES-256/CBC");
   add_oid(config, "1.2.410.200004.1.4", "SEED/CBC"); // RFC 4010
   add_oid(config, "1.3.6.1.4.1.25258.3.1", "Serpent/CBC");

   /* Hash Functions */
   add_oid(config, "1.2.840.113549.2.5", "MD5");
   add_oid(config, "1.3.6.1.4.1.11591.12.2", "Tiger(24,3)");

   add_oid(config, "1.3.14.3.2.26", "SHA-160");
   add_oid(config, "2.16.840.1.101.3.4.2.4", "SHA-224");
   add_oid(config, "2.16.840.1.101.3.4.2.1", "SHA-256");
   add_oid(config, "2.16.840.1.101.3.4.2.2", "SHA-384");
   add_oid(config, "2.16.840.1.101.3.4.2.3", "SHA-512");

   /* MACs */
   add_oid(config, "1.2.840.113549.2.7", "HMAC(SHA-1)");
   add_oid(config, "1.2.840.113549.2.8", "HMAC(SHA-224)");
   add_oid(config, "1.2.840.113549.2.9", "HMAC(SHA-256)");
   add_oid(config, "1.2.840.113549.2.10", "HMAC(SHA-384)");
   add_oid(config, "1.2.840.113549.2.11", "HMAC(SHA-512)");

   /* Key Wrap */
   add_oid(config, "1.2.840.113549.1.9.16.3.6", "KeyWrap.TripleDES");
   add_oid(config, "1.2.840.113549.1.9.16.3.7", "KeyWrap.RC2");
   add_oid(config, "1.2.840.113533.7.66.15", "KeyWrap.CAST-128");
   add_oid(config, "2.16.840.1.101.3.4.1.5", "KeyWrap.AES-128");
   add_oid(config, "2.16.840.1.101.3.4.1.25", "KeyWrap.AES-192");
   add_oid(config, "2.16.840.1.101.3.4.1.45", "KeyWrap.AES-256");

   /* Compression */
   add_oid(config, "1.2.840.113549.1.9.16.3.8", "Compression.Zlib");

   /* Public key signature schemes */
   add_oid(config, "1.2.840.113549.1.1.1", "RSA/EME-PKCS1-v1_5");
   add_oid(config, "1.2.840.113549.1.1.2", "RSA/EMSA3(MD2)");
   add_oid(config, "1.2.840.113549.1.1.4", "RSA/EMSA3(MD5)");
   add_oid(config, "1.2.840.113549.1.1.5", "RSA/EMSA3(SHA-160)");
   add_oid(config, "1.2.840.113549.1.1.11", "RSA/EMSA3(SHA-256)");
   add_oid(config, "1.2.840.113549.1.1.12", "RSA/EMSA3(SHA-384)");
   add_oid(config, "1.2.840.113549.1.1.13", "RSA/EMSA3(SHA-512)");
   add_oid(config, "1.3.36.3.3.1.2", "RSA/EMSA3(RIPEMD-160)");

   add_oid(config, "1.2.840.10040.4.3", "DSA/EMSA1(SHA-160)");
   add_oid(config, "2.16.840.1.101.3.4.3.1", "DSA/EMSA1(SHA-224)");
   add_oid(config, "2.16.840.1.101.3.4.3.2", "DSA/EMSA1(SHA-256)");

   add_oid(config, "0.4.0.127.0.7.1.1.4.1.1", "ECDSA/EMSA1_BSI(SHA-160)");
   add_oid(config, "0.4.0.127.0.7.1.1.4.1.2", "ECDSA/EMSA1_BSI(SHA-224)");
   add_oid(config, "0.4.0.127.0.7.1.1.4.1.3", "ECDSA/EMSA1_BSI(SHA-256)");
   add_oid(config, "0.4.0.127.0.7.1.1.4.1.4", "ECDSA/EMSA1_BSI(SHA-384)");
   add_oid(config, "0.4.0.127.0.7.1.1.4.1.5", "ECDSA/EMSA1_BSI(SHA-512)");
   add_oid(config, "0.4.0.127.0.7.1.1.4.1.6", "ECDSA/EMSA1_BSI(RIPEMD-160)");

   add_oid(config, "1.2.840.10045.4.1", "ECDSA/EMSA1(SHA-160)");
   add_oid(config, "1.2.840.10045.4.3.1", "ECDSA/EMSA1(SHA-224)");
   add_oid(config, "1.2.840.10045.4.3.2", "ECDSA/EMSA1(SHA-256)");
   add_oid(config, "1.2.840.10045.4.3.3", "ECDSA/EMSA1(SHA-384)");
   add_oid(config, "1.2.840.10045.4.3.4", "ECDSA/EMSA1(SHA-512)");

   add_oid(config, "1.2.643.2.2.3", "GOST-34.10/EMSA1(GOST-R-34.11-94)");

   add_oid(config, "1.3.6.1.4.1.25258.2.1.1.1", "RW/EMSA2(RIPEMD-160)");
   add_oid(config, "1.3.6.1.4.1.25258.2.1.1.2", "RW/EMSA2(SHA-160)");
   add_oid(config, "1.3.6.1.4.1.25258.2.1.1.3", "RW/EMSA2(SHA-224)");
   add_oid(config, "1.3.6.1.4.1.25258.2.1.1.4", "RW/EMSA2(SHA-256)");
   add_oid(config, "1.3.6.1.4.1.25258.2.1.1.5", "RW/EMSA2(SHA-384)");
   add_oid(config, "1.3.6.1.4.1.25258.2.1.1.6", "RW/EMSA2(SHA-512)");

   add_oid(config, "1.3.6.1.4.1.25258.2.1.2.1", "RW/EMSA4(RIPEMD-160)");
   add_oid(config, "1.3.6.1.4.1.25258.2.1.2.2", "RW/EMSA4(SHA-160)");
   add_oid(config, "1.3.6.1.4.1.25258.2.1.2.3", "RW/EMSA4(SHA-224)");
   add_oid(config, "1.3.6.1.4.1.25258.2.1.2.4", "RW/EMSA4(SHA-256)");
   add_oid(config, "1.3.6.1.4.1.25258.2.1.2.5", "RW/EMSA4(SHA-384)");
   add_oid(config, "1.3.6.1.4.1.25258.2.1.2.6", "RW/EMSA4(SHA-512)");

   add_oid(config, "1.3.6.1.4.1.25258.2.2.1.1", "NR/EMSA2(RIPEMD-160)");
   add_oid(config, "1.3.6.1.4.1.25258.2.2.1.2", "NR/EMSA2(SHA-160)");
   add_oid(config, "1.3.6.1.4.1.25258.2.2.1.3", "NR/EMSA2(SHA-224)");
   add_oid(config, "1.3.6.1.4.1.25258.2.2.1.4", "NR/EMSA2(SHA-256)");
   add_oid(config, "1.3.6.1.4.1.25258.2.2.1.5", "NR/EMSA2(SHA-384)");
   add_oid(config, "1.3.6.1.4.1.25258.2.2.1.6", "NR/EMSA2(SHA-512)");

   add_oid(config, "2.5.4.3",  "X520.CommonName");
   add_oid(config, "2.5.4.4",  "X520.Surname");
   add_oid(config, "2.5.4.5",  "X520.SerialNumber");
   add_oid(config, "2.5.4.6",  "X520.Country");
   add_oid(config, "2.5.4.7",  "X520.Locality");
   add_oid(config, "2.5.4.8",  "X520.State");
   add_oid(config, "2.5.4.10", "X520.Organization");
   add_oid(config, "2.5.4.11", "X520.OrganizationalUnit");
   add_oid(config, "2.5.4.12", "X520.Title");
   add_oid(config, "2.5.4.42", "X520.GivenName");
   add_oid(config, "2.5.4.43", "X520.Initials");
   add_oid(config, "2.5.4.44", "X520.GenerationalQualifier");
   add_oid(config, "2.5.4.46", "X520.DNQualifier");
   add_oid(config, "2.5.4.65", "X520.Pseudonym");

   add_oid(config, "1.2.840.113549.1.5.12", "PKCS5.PBKDF2");
   add_oid(config, "1.2.840.113549.1.5.1",  "PBE-PKCS5v15(MD2,DES/CBC)");
   add_oid(config, "1.2.840.113549.1.5.4",  "PBE-PKCS5v15(MD2,RC2/CBC)");
   add_oid(config, "1.2.840.113549.1.5.3",  "PBE-PKCS5v15(MD5,DES/CBC)");
   add_oid(config, "1.2.840.113549.1.5.6",  "PBE-PKCS5v15(MD5,RC2/CBC)");
   add_oid(config, "1.2.840.113549.1.5.10", "PBE-PKCS5v15(SHA-160,DES/CBC)");
   add_oid(config, "1.2.840.113549.1.5.11", "PBE-PKCS5v15(SHA-160,RC2/CBC)");
   add_oid(config, "1.2.840.113549.1.5.13", "PBE-PKCS5v20");

   add_oid(config, "1.2.840.113549.1.9.1", "PKCS9.EmailAddress");
   add_oid(config, "1.2.840.113549.1.9.2", "PKCS9.UnstructuredName");
   add_oid(config, "1.2.840.113549.1.9.3", "PKCS9.ContentType");
   add_oid(config, "1.2.840.113549.1.9.4", "PKCS9.MessageDigest");
   add_oid(config, "1.2.840.113549.1.9.7", "PKCS9.ChallengePassword");
   add_oid(config, "1.2.840.113549.1.9.14", "PKCS9.ExtensionRequest");

   add_oid(config, "1.2.840.113549.1.7.1",      "CMS.DataContent");
   add_oid(config, "1.2.840.113549.1.7.2",      "CMS.SignedData");
   add_oid(config, "1.2.840.113549.1.7.3",      "CMS.EnvelopedData");
   add_oid(config, "1.2.840.113549.1.7.5",      "CMS.DigestedData");
   add_oid(config, "1.2.840.113549.1.7.6",      "CMS.EncryptedData");
   add_oid(config, "1.2.840.113549.1.9.16.1.2", "CMS.AuthenticatedData");
   add_oid(config, "1.2.840.113549.1.9.16.1.9", "CMS.CompressedData");

   add_oid(config, "2.5.29.14", "X509v3.SubjectKeyIdentifier");
   add_oid(config, "2.5.29.15", "X509v3.KeyUsage");
   add_oid(config, "2.5.29.17", "X509v3.SubjectAlternativeName");
   add_oid(config, "2.5.29.18", "X509v3.IssuerAlternativeName");
   add_oid(config, "2.5.29.19", "X509v3.BasicConstraints");
   add_oid(config, "2.5.29.20", "X509v3.CRLNumber");
   add_oid(config, "2.5.29.21", "X509v3.ReasonCode");
   add_oid(config, "2.5.29.23", "X509v3.HoldInstructionCode");
   add_oid(config, "2.5.29.24", "X509v3.InvalidityDate");
   add_oid(config, "2.5.29.32", "X509v3.CertificatePolicies");
   add_oid(config, "2.5.29.35", "X509v3.AuthorityKeyIdentifier");
   add_oid(config, "2.5.29.36", "X509v3.PolicyConstraints");
   add_oid(config, "2.5.29.37", "X509v3.ExtendedKeyUsage");

   add_oid(config, "2.5.29.32.0", "X509v3.AnyPolicy");

   add_oid(config, "1.3.6.1.5.5.7.3.1", "PKIX.ServerAuth");
   add_oid(config, "1.3.6.1.5.5.7.3.2", "PKIX.ClientAuth");
   add_oid(config, "1.3.6.1.5.5.7.3.3", "PKIX.CodeSigning");
   add_oid(config, "1.3.6.1.5.5.7.3.4", "PKIX.EmailProtection");
   add_oid(config, "1.3.6.1.5.5.7.3.5", "PKIX.IPsecEndSystem");
   add_oid(config, "1.3.6.1.5.5.7.3.6", "PKIX.IPsecTunnel");
   add_oid(config, "1.3.6.1.5.5.7.3.7", "PKIX.IPsecUser");
   add_oid(config, "1.3.6.1.5.5.7.3.8", "PKIX.TimeStamping");
   add_oid(config, "1.3.6.1.5.5.7.3.9", "PKIX.OCSPSigning");

   add_oid(config, "1.3.6.1.5.5.7.8.5", "PKIX.XMPPAddr");

   /* ECC domain parameters */

   add_oid(config, "1.3.132.0.6",  "secp112r1");
   add_oid(config, "1.3.132.0.7",  "secp112r2");
   add_oid(config, "1.3.132.0.8",  "secp160r1");
   add_oid(config, "1.3.132.0.9",  "secp160k1");
   add_oid(config, "1.3.132.0.10", "secp256k1");
   add_oid(config, "1.3.132.0.28", "secp128r1");
   add_oid(config, "1.3.132.0.29", "secp128r2");
   add_oid(config, "1.3.132.0.30", "secp160r2");
   add_oid(config, "1.3.132.0.31", "secp192k1");
   add_oid(config, "1.3.132.0.32", "secp224k1");
   add_oid(config, "1.3.132.0.33", "secp224r1");
   add_oid(config, "1.3.132.0.34", "secp384r1");
   add_oid(config, "1.3.132.0.35", "secp521r1");

   add_oid(config, "1.2.840.10045.3.1.1", "secp192r1");
   add_oid(config, "1.2.840.10045.3.1.2", "x962_p192v2");
   add_oid(config, "1.2.840.10045.3.1.3", "x962_p192v3");
   add_oid(config, "1.2.840.10045.3.1.4", "x962_p239v1");
   add_oid(config, "1.2.840.10045.3.1.5", "x962_p239v2");
   add_oid(config, "1.2.840.10045.3.1.6", "x962_p239v3");
   add_oid(config, "1.2.840.10045.3.1.7", "secp256r1");

   add_oid(config, "1.3.36.3.3.2.8.1.1.1",  "brainpool160r1");
   add_oid(config, "1.3.36.3.3.2.8.1.1.3",  "brainpool192r1");
   add_oid(config, "1.3.36.3.3.2.8.1.1.5",  "brainpool224r1");
   add_oid(config, "1.3.36.3.3.2.8.1.1.7",  "brainpool256r1");
   add_oid(config, "1.3.36.3.3.2.8.1.1.9",  "brainpool320r1");
   add_oid(config, "1.3.36.3.3.2.8.1.1.11", "brainpool384r1");
   add_oid(config, "1.3.36.3.3.2.8.1.1.13", "brainpool512r1");

   add_oid(config, "1.2.643.2.2.35.1", "gost_256A");
   add_oid(config, "1.2.643.2.2.36.0", "gost_256A");

   /* CVC */
   add_oid(config, "0.4.0.127.0.7.3.1.2.1",
           "CertificateHolderAuthorizationTemplate");
   }

/*
* Set the default algorithm aliases
*/
void set_default_aliases(Library_State& config)
   {
   config.add_alias("OpenPGP.Cipher.1",  "IDEA");
   config.add_alias("OpenPGP.Cipher.2",  "TripleDES");
   config.add_alias("OpenPGP.Cipher.3",  "CAST-128");
   config.add_alias("OpenPGP.Cipher.4",  "Blowfish");
   config.add_alias("OpenPGP.Cipher.5",  "SAFER-SK(13)");
   config.add_alias("OpenPGP.Cipher.7",  "AES-128");
   config.add_alias("OpenPGP.Cipher.8",  "AES-192");
   config.add_alias("OpenPGP.Cipher.9",  "AES-256");
   config.add_alias("OpenPGP.Cipher.10", "Twofish");

   config.add_alias("OpenPGP.Digest.1", "MD5");
   config.add_alias("OpenPGP.Digest.2", "SHA-1");
   config.add_alias("OpenPGP.Digest.3", "RIPEMD-160");
   config.add_alias("OpenPGP.Digest.5", "MD2");
   config.add_alias("OpenPGP.Digest.6", "Tiger(24,3)");
   config.add_alias("OpenPGP.Digest.8", "SHA-256");

   config.add_alias("TLS.Digest.0",     "Parallel(MD5,SHA-160)");

   config.add_alias("EME-PKCS1-v1_5",  "PKCS1v15");
   config.add_alias("OAEP-MGF1",       "EME1");
   config.add_alias("EME-OAEP",        "EME1");
   config.add_alias("X9.31",           "EMSA2");
   config.add_alias("EMSA-PKCS1-v1_5", "EMSA3");
   config.add_alias("PSS-MGF1",        "EMSA4");
   config.add_alias("EMSA-PSS",        "EMSA4");

   config.add_alias("3DES",     "TripleDES");
   config.add_alias("DES-EDE",  "TripleDES");
   config.add_alias("CAST5",    "CAST-128");
   config.add_alias("SHA1",     "SHA-160");
   config.add_alias("SHA-1",    "SHA-160");
   config.add_alias("MARK-4",   "ARC4(256)");
   config.add_alias("OMAC",     "CMAC");
   config.add_alias("GOST",     "GOST-28147-89");
   }

/*
* Set the built-in discrete log groups
*/
void set_default_dl_groups(Library_State& config)
   {
   config.set("dl", "modp/ietf/768",
         "-----BEGIN X942 DH PARAMETERS-----"
         "MIHIAmEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxObIlFK"
         "CHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjo2IP//"
         "////////AgECAmB//////////+SH7VEQtGEaYmMxRcBuDmiUgScERTPmOgEF31Md"
         "ic2RKKUEPMcaAm73yozZ5p0hjZgVhTb5L4obp/Catrao4SLyQtq7MS8/Y3omIXTT"
         "HRsQf/////////8="
         "-----END X942 DH PARAMETERS-----");

   config.set("dl", "modp/ietf/1024",
         "-----BEGIN X942 DH PARAMETERS-----"
         "MIIBCgKBgQD//////////8kP2qIhaMI0xMZii4DcHNEpAk4IimfMdAILvqY7E5si"
         "UUoIeY40BN3vlRmzzTpDGzArCm3yXxQ3T+E1bW1RwkXkhbV2Yl5+xvRMQummN+1r"
         "C/9ctvQGt+3uOGv7Womfpa6fJBF8Sx/mSShmUezmU4H//////////wIBAgKBgH//"
         "////////5IftURC0YRpiYzFFwG4OaJSBJwRFM+Y6AQXfUx2JzZEopQQ8xxoCbvfK"
         "jNnmnSGNmBWFNvkvihun8Jq2tqjhIvJC2rsxLz9jeiYhdNMb9rWF/65begNb9vcc"
         "Nf2tRM/S10+SCL4lj/MklDMo9nMpwP//////////"
         "-----END X942 DH PARAMETERS-----");

   config.set("dl", "modp/srp/1024",
         "-----BEGIN X942 DH PARAMETERS-----"
         "MIIBCgKBgQDurwq5rbON1pwz+Ar6j8XoYHJhh3X/PAueojFMnCVldtZ033SW6oHT"
         "ODtIE9aSxuDg1djiULmL5I5JXB1gidrRXcfXtGFU1rbOjvStabFdSYJVmyl7zxiF"
         "xSn1ZmYOV+xo7bw8BXJswC/Uy/SXbqqa/VE4/oN2Q1ufxh0vwOsG4wIBAgKBgHdX"
         "hVzW2cbrThn8BX1H4vQwOTDDuv+eBc9RGKZOErK7azpvukt1QOmcHaQJ60ljcHBq"
         "7HEoXMXyRySuDrBE7Wiu4+vaMKprW2dHela02K6kwSrNlL3njELilPqzMwcr9jR2"
         "3h4CuTZgF+pl+ku3VU1+qJx/Qbshrc/jDpfgdYNx"
         "-----END X942 DH PARAMETERS-----");

   config.set("dl", "modp/ietf/1536",
         "-----BEGIN X942 DH PARAMETERS-----"
         "MIIBigKBwQD//////////8kP2qIhaMI0xMZii4DcHNEpAk4IimfMdAILvqY7E5si"
         "UUoIeY40BN3vlRmzzTpDGzArCm3yXxQ3T+E1bW1RwkXkhbV2Yl5+xvRMQummN+1r"
         "C/9ctvQGt+3uOGv7Womfpa6fJBF8Sx/mSShmUezkWz3CAHy4oWO/BZjaSDYcVdOa"
         "aRY/qP0kz1+DZV0j3KOtlhxi81YghVK7ntUpB3CWlm1nDDVOSryYBPF0bAjKI3Mn"
         "//////////8CAQICgcB//////////+SH7VEQtGEaYmMxRcBuDmiUgScERTPmOgEF"
         "31Mdic2RKKUEPMcaAm73yozZ5p0hjZgVhTb5L4obp/Catrao4SLyQtq7MS8/Y3om"
         "IXTTG/a1hf+uW3oDW/b3HDX9rUTP0tdPkgi+JY/zJJQzKPZyLZ7hAD5cULHfgsxt"
         "JBsOKunNNIsf1H6SZ6/Bsq6R7lHWyw4xeasQQqldz2qUg7hLSzazhhqnJV5MAni6"
         "NgRlEbmT//////////8="
         "-----END X942 DH PARAMETERS-----");

   config.set("dl", "modp/srp/1536",
         "-----BEGIN DH PARAMETERS-----"
         "MIHHAoHBAJ3vPK+5OSd6sfEqhheke7vbpR30maxMgL7uqWFLGcxNX09fVW4ny95R"
         "xqlL5GB6KRVYkDug0PhDgLZVu5oi6NzfAop87Gfw0IE0sci5eYkUm2CeC+O6tj1H"
         "VIOB28Wx/HZOP0tT3Z2hFYv9PiucjPVu3wGVOTSWJ9sv1T0kt8SGZXcuQ31sf4zk"
         "QnNK98y3roN8Jkrjqb64f4ov6bi1KS5aAh//XpFHnoznoowkQsbzFRgPk0maI03P"
         "duP+0TX5uwIBAg=="
         "-----END DH PARAMETERS-----");

   config.set("dl", "modp/ietf/2048",
         "-----BEGIN X942 DH PARAMETERS-----"
         "MIICDAKCAQEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
         "IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
         "awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
         "mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
         "fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
         "5RXSJhiY+gUQFXKOWoqsqmj//////////wIBAgKCAQB//////////+SH7VEQtGEa"
         "YmMxRcBuDmiUgScERTPmOgEF31Mdic2RKKUEPMcaAm73yozZ5p0hjZgVhTb5L4ob"
         "p/Catrao4SLyQtq7MS8/Y3omIXTTG/a1hf+uW3oDW/b3HDX9rUTP0tdPkgi+JY/z"
         "JJQzKPZyLZ7hAD5cULHfgsxtJBsOKunNNIsf1H6SZ6/Bsq6R7lHWyw4xeasQQqld"
         "z2qUg7hLSzazhhqnJV5MAni6NgRlDBC+GUgvIxcbZx3xzzuWDAdDAc2TwdF2A9FH"
         "2uKu+DemKWTvFeX7SqwLjBzKpL51SrVyiukTDEx9AogKuUctRVZVNH//////////"
         "-----END X942 DH PARAMETERS-----");

   config.set("dl", "modp/srp/2048",
         "-----BEGIN X942 DH PARAMETERS-----"
         "MIICDAKCAQEArGvbQTJKmpvxZt5eE4lYL69ytmUZh+4H/DGSlD21YFCjcynLtKCZ"
         "7YGT4HV3Z6E91SMSq0sDMQ3Nf0ip2gT9UOgIOWntt2ewz2CVF5oWOrNmGgX71fqq"
         "6CkYqZYvC5O4Vfl5k+yXXuqoDXQK2/T/dHNZ0EHVwz6nHSgeRGsUdzvKl7Q6I/uA"
         "Fna9IHpDbGSB8dK5B4cXRhpbnTLmiPh3SFRFI7UksNV9Xqd6J3XS7PoDLPvb9S+z"
         "eGFgJ5AE5Xrmr4dOcwPOUymczAQce8MI2CpWmPOo0MOCca41+Onb+7aUtcgD2J96"
         "5DXeI21SX1R1m2XjcvzWjvIPpxEfnkr/cwIBAgKCAQBWNe2gmSVNTfizby8JxKwX"
         "17lbMozD9wP+GMlKHtqwKFG5lOXaUEz2wMnwOruz0J7qkYlVpYGYhua/pFTtAn6o"
         "dAQctPbbs9hnsEqLzQsdWbMNAv3q/VV0FIxUyxeFydwq/LzJ9kuvdVQGugVt+n+6"
         "OazoIOrhn1OOlA8iNYo7neVL2h0R/cALO16QPSG2MkD46VyDw4ujDS3OmXNEfDuk"
         "KiKR2pJYar6vU70Tuul2fQGWfe36l9m8MLATyAJyvXNXw6c5gecplM5mAg494YRs"
         "FStMedRoYcE41xr8dO3920pa5AHsT71yGu8RtqkvqjrNsvG5fmtHeQfTiI/PJX+5"
         "-----END X942 DH PARAMETERS-----");

   config.set("dl", "modp/ietf/3072",
         "-----BEGIN X942 DH PARAMETERS-----"
         "MIIDDAKCAYEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
         "IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
         "awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
         "mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
         "fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
         "5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM"
         "fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq"
         "ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqTrS"
         "yv//////////AgECAoIBgH//////////5IftURC0YRpiYzFFwG4OaJSBJwRFM+Y6"
         "AQXfUx2JzZEopQQ8xxoCbvfKjNnmnSGNmBWFNvkvihun8Jq2tqjhIvJC2rsxLz9j"
         "eiYhdNMb9rWF/65begNb9vccNf2tRM/S10+SCL4lj/MklDMo9nItnuEAPlxQsd+C"
         "zG0kGw4q6c00ix/UfpJnr8GyrpHuUdbLDjF5qxBCqV3PapSDuEtLNrOGGqclXkwC"
         "eLo2BGUMEL4ZSC8jFxtnHfHPO5YMB0MBzZPB0XYD0Ufa4q74N6YpZO8V5ftKrAuM"
         "HMqkvnVKtXKK6RMMTH0CiAq5Ry1FVWIW1pmLhoIoPRnUKpDV745dMnZ9woIsbfeF"
         "RXU4q66DBj7Zy4fC03DyY9X610ZthJnrj0ZKcCUSsM7ncekTDWl3NfiX/QNsxQQy"
         "bDsBOZ9kNTIpD5WMC72QBl3wi6u9MK62O4TEYF1so3EEcSfQOnLVmKHtrf5wfohH"
         "JcFokFSdaWV//////////w=="
         "-----END X942 DH PARAMETERS-----");

   config.set("dl", "modp/srp/3072",
         "-----BEGIN DH PARAMETERS-----"
         "MIIBiAKCAYEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
         "IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
         "awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
         "mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
         "fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
         "5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM"
         "fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq"
         "ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqTrS"
         "yv//////////AgEF"
         "-----END DH PARAMETERS-----");

   config.set("dl", "modp/ietf/4096",
         "-----BEGIN X942 DH PARAMETERS-----"
         "MIIEDAKCAgEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
         "IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
         "awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
         "mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
         "fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
         "5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM"
         "fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq"
         "ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEI"
         "ARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O"
         "+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBI"
         "HNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0BjGZ//////////8CAQICggIA"
         "f//////////kh+1RELRhGmJjMUXAbg5olIEnBEUz5joBBd9THYnNkSilBDzHGgJu"
         "98qM2eadIY2YFYU2+S+KG6fwmra2qOEi8kLauzEvP2N6JiF00xv2tYX/rlt6A1v2"
         "9xw1/a1Ez9LXT5IIviWP8ySUMyj2ci2e4QA+XFCx34LMbSQbDirpzTSLH9R+kmev"
         "wbKuke5R1ssOMXmrEEKpXc9qlIO4S0s2s4YapyVeTAJ4ujYEZQwQvhlILyMXG2cd"
         "8c87lgwHQwHNk8HRdgPRR9rirvg3pilk7xXl+0qsC4wcyqS+dUq1corpEwxMfQKI"
         "CrlHLUVVYhbWmYuGgig9GdQqkNXvjl0ydn3Cgixt94VFdTirroMGPtnLh8LTcPJj"
         "1frXRm2EmeuPRkpwJRKwzudx6RMNaXc1+Jf9A2zFBDJsOwE5n2Q1MikPlYwLvZAG"
         "XfCLq70wrrY7hMRgXWyjcQRxJ9A6ctWYoe2t/nB+iEclwWiQVJCEAI05HglTw/Nr"
         "xDjNCF7dLZNM4ZOMNXpxHg1KNBpbCoXtEsH05RVqJnRt3eFtgm9HfJdHfgoP32VT"
         "FD4so6c14C7M2Usn0Ehh0RGd0MMorfP2j7CUuGdxa9fcDe67ELgkDmgDSJPq2C1U"
         "ydp1TEbH7uDDf9vuSFNgR6b6GuSaAxjM//////////8="
         "-----END X942 DH PARAMETERS-----");

   config.set("dl", "modp/srp/4096",
         "-----BEGIN DH PARAMETERS-----"
         "MIICCAKCAgEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
         "IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
         "awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
         "mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
         "fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
         "5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM"
         "fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq"
         "ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEI"
         "ARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O"
         "+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBI"
         "HNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0BjGZ//////////8CAQU="
         "-----END DH PARAMETERS-----");

   config.set("dl", "modp/ietf/6144",
         "-----BEGIN X942 DH PARAMETERS-----"
         "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"
         "jzbmIBJ//////////wIBAg=="
         "-----END X942 DH PARAMETERS-----");

   config.set("dl", "modp/srp/6144",
         "-----BEGIN DH PARAMETERS-----"
         "MIIDCAKCAwEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
         "IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
         "awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
         "mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
         "fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
         "5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM"
         "fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq"
         "ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEI"
         "ARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O"
         "+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBI"
         "HNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0AoSSNsP6tNJ8cCbB1NyyYCZG"
         "3sl1HnY9uje9+P+UBq2eUw7l2zgvQTABrrBqU+2QJ9gxF5cnsIZaiRjaPtvrz5sU"
         "7UTObLrO1Lsb238UR+bMJUszIFFRK9evQm+49AE3jNK/WYPKAcZLkuzwMuoV0XId"
         "A/SC185udP721V5wL0aYDIK1qEAxkAscnlnnyX++x+jzI6l6fjbMiL4PHUW3/1ha"
         "xUvUB7IrQVSqzI9tfr9I4dgUzF7SD4A34KeXFe7ym+MoBqHVi7fF2nb1UKo9ih+/"
         "8OsZzLGjE9Vc2lbJ7C7yljI4f+jXbjwEaAQ+j2Y/SGDuEr8tWwt0dNbmlPkebcxA"
         "JP//////////AgEF"
         "-----END DH PARAMETERS-----");

   config.set("dl", "modp/ietf/8192",
         "-----BEGIN X942 DH PARAMETERS-----"
         "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"
         "-----END X942 DH PARAMETERS-----");

   config.set("dl", "modp/srp/8192",
         "-----BEGIN DH PARAMETERS-----"
         "MIIECAKCBAEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb"
         "IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft"
         "awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT"
         "mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh"
         "fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq"
         "5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM"
         "fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq"
         "ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEI"
         "ARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O"
         "+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBI"
         "HNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0AoSSNsP6tNJ8cCbB1NyyYCZG"
         "3sl1HnY9uje9+P+UBq2eUw7l2zgvQTABrrBqU+2QJ9gxF5cnsIZaiRjaPtvrz5sU"
         "7UTObLrO1Lsb238UR+bMJUszIFFRK9evQm+49AE3jNK/WYPKAcZLkuzwMuoV0XId"
         "A/SC185udP721V5wL0aYDIK1qEAxkAscnlnnyX++x+jzI6l6fjbMiL4PHUW3/1ha"
         "xUvUB7IrQVSqzI9tfr9I4dgUzF7SD4A34KeXFe7ym+MoBqHVi7fF2nb1UKo9ih+/"
         "8OsZzLGjE9Vc2lbJ7C7yljI4f+jXbjwEaAQ+j2Y/SGDuEr8tWwt0dNbmlPkebb4R"
         "WXSjkm8S/uXkOHd8tqky34zYvsTQc7kxujvIMraNndMAdB+nv4r8R+0ldvaTa6Qk"
         "ZjqrY5xa5PVoNCO0dCvxyXgjjxbL451lLeP9uL78hIrZIiIuBKQDfAcT61eoGiPw"
         "xzRz/GRs6jBrS8vIhi+Dhd36nUt/osCH6HloMwPtW906Bis89bOieKZtKhP4P0T4"
         "Ld8xDuB0q2o2RZfomaAlXcFk8xzFCEaFHfmrSBld7X6hsdUQvX7nTXP682vDHs+i"
         "aDWQRvTrh5+SQAlDi0gcbNeImgAu1e44K8kZDab8Am5HlVjkR1Z36aqeMFDidlaU"
         "38gfVuiAuW5xYMmA3Zjt09///////////wIBEw=="
         "-----END DH PARAMETERS-----");

   config.set("dl", "dsa/jce/512",
         "-----BEGIN DSA PARAMETERS-----"
         "MIGdAkEA/KaCzo4Syrom78z3EQ5SbbB4sF7ey80etKII864WF64B81uRpH5t9jQT"
         "xeEu0ImbzRMqzVDZkVG9xD7nN1kuFwIVAJYu3cw2nLqOuyYO5rahJtk0bjjFAkEA"
         "3gtU76vylwh+5iPVylWIxkgo70/eT/uuHs0gBndrBbEbgeo83pvDlkwWh8UyW/Q9"
         "fM76DQqGvl3/3dDRFD3NdQ=="
         "-----END DSA PARAMETERS-----");

   config.set("dl", "dsa/jce/768",
         "-----BEGIN DSA PARAMETERS-----"
         "MIHdAmEA6eZCWZ01XzfJf/01ZxILjiXJzUPpJ7OpZw++xdiQFBki0sOzrSSACTeZ"
         "hp0ehGqrSfqwrSbSzmoiIZ1HC859d31KIfvpwnC1f2BwAvPO+Dk2lM9F7jaIwRqM"
         "VqsSej2vAhUAnNvYTJ8awvOND4D0KrlS5zOL9RECYQDe7p717RUWzn5pXmcrjO5F"
         "5s17NuDmOF+JS6hhY/bz5sbU6KgRRtQBfe/dccvZD6Akdlm4i3zByJT0gmn9Txqs"
         "CjBTjf9rP8ds+xMcnnlltYhYqwpDtVczWRKoqlR/lWg="
         "-----END DSA PARAMETERS-----");

   config.set("dl", "dsa/jce/1024",
         "-----BEGIN DSA PARAMETERS-----"
         "MIIBHgKBgQD9f1OBHXUSKVLfSpwu7OTn9hG3UjzvRADDHj+AtlEmaUVdQCJR+1k9"
         "jVj6v8X1ujD2y5tVbNeBO4AdNG/yZmC3a5lQpaSfn+gEexAiwk+7qdf+t8Yb+DtX"
         "58aophUPBPuD9tPFHsMCNVQTWhaRMvZ1864rYdcq7/IiAxmd0UgBxwIVAJdgUI8V"
         "IwvMspK5gqLrhAvwWBz1AoGARpYDUS4wJ4zTlHWV2yLuyYJqYyKtyXNE9B10DDJX"
         "JMj577qn1NgD/4xgnc0QDrxb38+tfGpCX66nhuogUOvpg1HqH9of3yTWlHqmuaoj"
         "dmlTgC9NfUqOy6BtGXaKJJH/sW0O+cQ6mbX3FnL/bwoktETQc20E04oaEyLa9s3Y"
         "jJ0="
         "-----END DSA PARAMETERS-----");

   config.set("dl", "dsa/botan/2048",
         "-----BEGIN DSA PARAMETERS-----"
         "MIICLAKCAQEAkcSKT9+898Aq6V59oSYSK13Shk9Vm4fo50oobVL1m9HeaN/WRdDg"
         "DGDAgAMYkZgDdO61lKUyv9Z7mgnqxLhmOgeRDmjzlGX7cEDSXfE5MuusQ0elMOy6"
         "YchU+biA08DDZgCAWHxFVm2t4mvVo5S+CTtMDyS1r/747GxbPlf7iQJam8FnaZMh"
         "MeFtPJTvyrGNDfBhIDzFPmEDvHLVWUv9QMplOA9EqahR3LB1SV/AM6ilgHGhvXj+"
         "BS9mVVZI60txnSr+i0iA+NrW8VgYuhePiSdMhwvpuW6wjEbEAEDMLv4d+xsYaN0x"
         "nePDSjKmOrbrEiQgmkGWgMx5AtFyjU354QIhAIzX1FD4bwrZTu5M5GmodW0evRBY"
         "JBlD6v+ws1RYXpJNAoIBAA2fXgdhtNvRgz1qsalhoJlsXyIwP3LYTBQPZ8Qx2Uq1"
         "cVvqgaDJjTnOS8941rnryJXTT+idlAkdWEhhXvFfXobxHZb2yWniA936WDVkIKSc"
         "tES1lbkBqTPP4HZ7WU8YoHt/kd7NukRriJkPePL/kfL+fNQ/0uRtGOraH3u2YCxh"
         "f27zpLKE8v2boQo2BC3o+oeiyjZZf+yBFXoUheRAQd8CgwERy4gLvm7UlIFIhvll"
         "zcMTX1zPE4Nyi/ZbgG+WksCxDWxMCcdabKO0ATyxarLBBfa+I66pAA6rIXiYX5cs"
         "mAV+HIbkTnIYaI6krg82NtzKdFydzU5q/7Z8y8E9YTE="
         "-----END DSA PARAMETERS-----");

   config.set("dl", "dsa/botan/3072",
         "-----BEGIN DSA PARAMETERS-----"
         "MIIDLAKCAYEA5LUIgHWWY1heFCRgyi2d/xMviuTIQN2jomZoiRJP5WOLhOiim3rz"
         "+hIJvmv8S1By7Tsrc4e68/hX9HioAijvNgC3az3Pth0g00RlslBtLK+H3259wM6R"
         "vS0Wekb2rcwxxTHk+cervbkq3fNbCoBsZikqX14X6WTdCZkDczrEKKs12A6m9oW/"
         "uovkBo5UGK5eytno/wc94rY+Tn6tNciptwtb1Hz7iNNztm83kxk5sKtxvVWVgJCG"
         "2gFVM30YWg5Ps2pRmxtiArhZHmACRJzxzTpmOE9tIHOxzXO+ypO68eGmEX0COPIi"
         "rh7X/tGFqJDn9n+rj+uXU8wTSlGD3+h64llfe1wtn7tCJJ/dWVE+HTOWs+sv2GaE"
         "8oWoRI/nV6ApiBxAdguU75Gb35dAw4OJWZ7FGm6btRmo4GhJHpzgovz+PLYNZs8N"
         "+tIKjsaEBIaEphREV1vRck1zUrRKdgB3s71r04XOWwpyUMwL92jagpI4Buuc+7E4"
         "hDcxthggjHWbAiEAs+vTZOxp74zzuvZDt1c0sWM5suSeXN4bWcHp+0DuDFsCggGA"
         "K+0h7vg5ZKIwrom7px2ffDnFL8gim047x+WUTTKdoQ8BDqyee69sAJ/E6ylgcj4r"
         "Vt9GY+TDrIAOkljeL3ZJ0gZ4KJP4Ze/KSY0u7zAHTqXop6smJxKk2UovOwuaku5A"
         "D7OKPMWaXcfkNtXABLIuNQKDgbUck0B+sy1K4P1Cy0XhLQ7O6KJiOO3iCCp7FSIR"
         "PGbO+NdFxs88uUX4TS9N4W1Epx3hmCcOE/A1U8iLjTI60LlIob8hA6lJl5tu0W+1"
         "88lT2Vt8jojKZ9z1pjb7nKOdkkIV96iE7Wx+48ltjZcVQnl0t8Q1EoLhPTdz99KL"
         "RS8QiSoTx1hzKN6kgntrNpsqjcFyrcWD9R8qZZjFSD5bxGewL5HQWcQC0Y4sJoD3"
         "dqoG9JKAoscsF8xC1bbnQMXEsas8UcLtCSviotiwU65Xc9FCXtKwjwbi3VBZLfGk"
         "eMFVkc39EVZP+I/zi3IdQjkv2kcyEtz9jS2IqXagCv/m//tDCjWeZMorNRyiQSOU"
         "-----END DSA PARAMETERS-----");

   config.set("ec", "secp112r1",
         "-----BEGIN EC PARAMETERS-----"
         "MHQCAQEwGgYHKoZIzj0BAQIPANt8Kr9i415mgHa+rSCLMCAEDtt8Kr9i415mgHa+"
         "rSCIBA5lnvi6BDkW7t6JEXArIgQdBAlIcjmZWl7na1X5wvCYqJzlr4ckwKI+Dg/3"
         "dQACDwDbfCq/YuNedijfrGVhxQIBAQ=="
         "-----END EC PARAMETERS-----");

   config.set("ec", "secp112r2",
         "-----BEGIN EC PARAMETERS-----"
         "MHMCAQEwGgYHKoZIzj0BAQIPANt8Kr9i415mgHa+rSCLMCAEDmEnwkwF84oKqvZc"
         "DvAsBA5R3vGBXbXtdPzDTIXXCQQdBEujCrXokrThZJ3QkoZDrc1G9YguN0fe826V"
         "bpcCDjbfCq/YuNdZfKEFINBLAgEB"
         "-----END EC PARAMETERS-----");

   config.set("ec", "secp128r1",
         "-----BEGIN EC PARAMETERS-----"
         "MIGAAgEBMBwGByqGSM49AQECEQD////9////////////////MCQEEP////3/////"
         "//////////wEEOh1ecEQefQ92CSZPCzuXtMEIQQWH/dSi4mbLQwoYHylLFuGz1rI"
         "OVuv6xPALaKS3e16gwIRAP////4AAAAAdaMNG5A4oRUCAQE="
         "-----END EC PARAMETERS-----");

   config.set("ec", "secp128r2",
         "-----BEGIN EC PARAMETERS-----"
         "MH8CAQEwHAYHKoZIzj0BAQIRAP////3///////////////8wJAQQ1gMZmNGzu/6/"
         "Wcybv/mu4QQQXu78o4DQKRncLGVYu22KXQQhBHtqpdheVymD5vsyp83rwUAntpFq"
         "iU067nEG/oBfw0tEAhA/////f////74AJHIGE7WjAgEE"
         "-----END EC PARAMETERS-----");

   config.set("ec", "secp160k1",
         "-----BEGIN EC PARAMETERS-----"
         "MIGYAgEBMCAGByqGSM49AQECFQD////////////////////+//+sczAsBBQAAAAA"
         "AAAAAAAAAAAAAAAAAAAAAAQUAAAAAAAAAAAAAAAAAAAAAAAAAAcEKQQ7TDgs43qh"
         "kqQBnnYwNvT13U1+u5OM+TUxj9zta8KChlMXM8PwPE/uAhUBAAAAAAAAAAAAAbj6"
         "Ft+rmsoWtrMCAQE="
         "-----END EC PARAMETERS-----");

   config.set("ec", "secp160r1",
         "-----BEGIN EC PARAMETERS-----"
         "MIGYAgEBMCAGByqGSM49AQECFQD/////////////////////f////zAsBBT/////"
         "////////////////f////AQUHJe+/FS9eotlrPifgdTUrcVl+kUEKQRKlrVojvVz"
         "KEZkaYlow4u5E8v8giOmKFUxaJR9WdzJEgQjUTd6xfsyAhUBAAAAAAAAAAAAAfTI"
         "+Seu08p1IlcCAQE="
         "-----END EC PARAMETERS-----");

   config.set("ec", "secp160r2",
         "-----BEGIN EC PARAMETERS-----"
         "MIGYAgEBMCAGByqGSM49AQECFQD////////////////////+//+sczAsBBT/////"
         "///////////////+//+scAQUtOE00/tZ64urVydJBGZNWvUDiLoEKQRS3LA0KToR"
         "fh9P8Rsw9xmdMUTObf6v/vLjMfKW4HH6DfmYLP6n1D8uAhUBAAAAAAAAAAAAADUe"
         "54aoGPOhoWsCAQE="
         "-----END EC PARAMETERS-----");

   config.set("ec", "secp192k1",
         "-----BEGIN EC PARAMETERS-----"
         "MIGwAgEBMCQGByqGSM49AQECGQD//////////////////////////v//7jcwNAQY"
         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBgAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
         "AAMEMQTbT/EOwFfpriawfQKAt/Q0HaXRsergbH2bLy9tnFYop4RBY9AVvoY0QIKq"
         "iNleL50CGQD///////////////4m8vwXD2lGanTe/Y0CAQE="
         "-----END EC PARAMETERS-----");

   config.set("ec", "secp192r1",
         "-----BEGIN EC PARAMETERS-----"
         "MIGwAgEBMCQGByqGSM49AQECGQD////////////////////+//////////8wNAQY"
         "/////////////////////v/////////8BBhkIQUZ5ZyA5w+n6atyJDBJ/rje7MFG"
         "ubEEMQQYjagOsDCQ9ny/IOtDoYgA9P8K/YL/EBIHGSuV/8jaeGMQEe1rJM3Vc/l3"
         "oR55SBECGQD///////////////+Z3vg2FGvJsbTSKDECAQE="
         "-----END EC PARAMETERS-----");

   config.set("ec", "secp224k1",
         "-----BEGIN EC PARAMETERS-----"
         "MIHIAgEBMCgGByqGSM49AQECHQD///////////////////////////////7//+Vt"
         "MDwEHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEHAAAAAAAAAAAAAAAAAAA"
         "AAAAAAAAAAAAAAAAAAUEOQShRVszTfCZ3zD8KKFppGfp5HB1qQ9+ZQ62t6Rcfgif"
         "7X+6NEKCyvvW9+MZ98CwvVniykvbVW1hpQIdAQAAAAAAAAAAAAAAAAAB3OjS7GGE"
         "yvCpcXafsfcCAQE="
         "-----END EC PARAMETERS-----");

   config.set("ec", "secp224r1",
         "-----BEGIN EC PARAMETERS-----"
         "MIHIAgEBMCgGByqGSM49AQECHQD/////////////////////AAAAAAAAAAAAAAAB"
         "MDwEHP////////////////////7///////////////4EHLQFCoUMBLOr9UEyVlBE"
         "sLfXv9i6Jws5QyNV/7QEOQS3Dgy9a7S/fzITkLlKA8HTVsIRIjQygNYRXB0hvTdj"
         "iLX3I/tMIt/mzUN1oFoHR2RE1YGZhQB+NAIdAP//////////////////FqLguPA+"
         "E90pRVxcKj0CAQE="
         "-----END EC PARAMETERS-----");

   config.set("ec", "secp256k1",
         "-----BEGIN EC PARAMETERS-----"
         "MIHgAgEBMCwGByqGSM49AQECIQD////////////////////////////////////+"
         "///8LzBEBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQgAAAAAAAA"
         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcEQQR5vmZ++dy7rFWgYpXOhwsHApv8"
         "2y3OKNlZ8oFbFvgXmEg62ncmo8RlXaT7/A4RCKj9F7RIpoVUGZxH0I/7ENS4AiEA"
         "/////////////////////rqu3OavSKA7v9JejNA2QUECAQE="
         "-----END EC PARAMETERS-----");

   config.set("ec", "secp256r1",
         "-----BEGIN EC PARAMETERS-----"
         "MIHgAgEBMCwGByqGSM49AQECIQD/////AAAAAQAAAAAAAAAAAAAAAP//////////"
         "/////zBEBCD/////AAAAAQAAAAAAAAAAAAAAAP///////////////AQgWsY12Ko6"
         "k+ez671VdpiGvGUdBrDMU7D2O848PifSYEsEQQRrF9Hy4SxCR/i85uVjpEDydwN9"
         "gS3rM6D0oTlF2JjClk/jQuL+Gn+bjufrSnwPnhYrzjNXazFezsu2QGg3v1H1AiEA"
         "/////wAAAAD//////////7zm+q2nF56E87nKwvxjJVECAQE="
         "-----END EC PARAMETERS-----");

   config.set("ec", "secp384r1",
         "-----BEGIN EC PARAMETERS-----"
         "MIIBQAIBATA8BgcqhkjOPQEBAjEA////////////////////////////////////"
         "//////7/////AAAAAAAAAAD/////MGQEMP//////////////////////////////"
         "///////////+/////wAAAAAAAAAA/////AQwszEvp+I+5+SYjgVr4/gtGRgdnG7+"
         "gUESAxQIj1ATh1rGVjmNii7RnSqFyO3T7CrvBGEEqofKIr6LBTeOscce8yCtdG4d"
         "O2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3NhfeSpYmLG9dnpi/kpLcKfj0"
         "Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5fAjEA////////////////////"
         "////////////x2NNgfQ3Ld9YGg2ySLCneuzsGWrMxSlzAgEB"
         "-----END EC PARAMETERS-----");

   config.set("ec", "secp521r1",
         "-----BEGIN EC PARAMETERS-----"
         "MIIBrAIBATBNBgcqhkjOPQEBAkIB////////////////////////////////////"
         "//////////////////////////////////////////////////8wgYgEQgH/////"
         "////////////////////////////////////////////////////////////////"
         "/////////////////ARCAFGVPrlhjhyaH5KaIaC2hUDuotpyW5mzFfO4tImRjvEJ"
         "4VYZOVHsfpN7FlLAvTuxvwc1c9+IPSw08e9FH9RrUD8ABIGFBADGhY4GtwQE6c2e"
         "PstmI5W0QpxkgTkFP7Uh+CivYGtNPbqhS1537+dZKP4dwSei/6jeM0izwYVqQpv5"
         "fn4xwuW9ZgEYOSlqeJo7wARcil+0LH0b2Zj1RElXm0RoF6+9Fyc+ZiyX7nKZXvQm"
         "QMVQuQE/rQdhNTxwhqJywkCIvpR2n9FmUAJCAf//////////////////////////"
         "////////////////+lGGh4O/L5Zrf8wBSPcJpdA7tcm4iZxHrrtvtx6ROGQJAgEB"
         "-----END EC PARAMETERS-----");

   config.set("ec", "1.3.6.1.4.1.8301.3.1.2.9.0.38",
         "-----BEGIN EC PARAMETERS-----"
         "MIIBrAIBATBNBgcqhkjOPQEBAkIB////////////////////////////////////"
         "//////////////////////////////////////////////////8wgYgEQgH/////"
         "////////////////////////////////////////////////////////////////"
         "/////////////////ARCAFGVPrlhjhyaH5KaIaC2hUDuotpyW5mzFfO4tImRjvEJ"
         "4VYZOVHsfpN7FlLAvTuxvwc1c9+IPSw08e9FH9RrUD8ABIGFBADGhY4GtwQE6c2e"
         "PstmI5W0QpxkgTkFP7Uh+CivYGtNPbqhS1537+dZKP4dwSei/6jeM0izwYVqQpv5"
         "fn4xwuW9ZgEYOSlqeJo7wARcil+0LH0b2Zj1RElXm0RoF6+9Fyc+ZiyX7nKZXvQm"
         "QMVQuQE/rQdhNTxwhqJywkCIvpR2n9FmUAJCAf//////////////////////////"
         "////////////////+lGGh4O/L5Zrf8wBSPcJpdA7tcm4iZxHrrtvtx6ROGQJAgEB"
         "-----END EC PARAMETERS-----");

   config.set("ec", "brainpool160r1",
         "-----BEGIN EC PARAMETERS-----"
         "MIGYAgEBMCAGByqGSM49AQECFQDpXkpfc3BZ3GDfx62Vs9gTlRViDzAsBBQ0Dnvi"
         "ooDrdOK+YbradF2X6PfDAAQUHliahZVCNBITT6otveyVyNhnXlgEKQS+1a8W6j9q"
         "T2KTjEYx61r3vbzbwxZny0d6Go7DOPlHQWacl2MW2mMhAhUA6V5KX3NwWdxg31mR"
         "1FApQJ5g/AkCAQE="
         "-----END EC PARAMETERS-----");

   config.set("ec", "brainpool192r1",
         "-----BEGIN EC PARAMETERS-----"
         "MIGwAgEBMCQGByqGSM49AQECGQDDAvQdkyo2zaejRjCT0Y23j85HbeGoYpcwNAQY"
         "apEXQHax4OGcOcAx/oaFwcrgQOXGmijvBBhGmijvfCjMo9xyHQRPRJa8yn70FG+/"
         "JckEMQTAoGR+qrakh1OwM8VssPCQCi9cSFM3X9YUtpCGar1buItfSCjBSQAC5nc/"
         "ovopm48CGQDDAvQdkyo2zaejRi+enpFrW+jxAprErMECAQE="
         "-----END EC PARAMETERS-----");

   config.set("ec", "brainpool224r1",
         "-----BEGIN EC PARAMETERS-----"
         "MIHIAgEBMCgGByqGSM49AQECHQDXwTSqJkNmhioYMCV10deHsJ8HV5faifV+yMD/"
         "MDwEHGil5iypzmwcKZgDpsFTC1FOGCrYsAQqWcrSn0MEHCWA9jzP5EE4hwcTsakj"
         "aeM+ITXSZtuzcjhsQAsEOQQNkCmtLH5c9DQII7KofcaMnkzjF0webv3uEsB9WKpW"
         "93LAcm8kxrieTs2sJDVLnpnKo/bTdhQCzQIdANfBNKomQ2aGKhgwJXXQ+5jRFrxL"
         "bd68o6Wnk58CAQE="
         "-----END EC PARAMETERS-----");

   config.set("ec", "brainpool256r1",
         "-----BEGIN EC PARAMETERS-----"
         "MIHgAgEBMCwGByqGSM49AQECIQCp+1fboe6pvD5mCpCdg41ybjv2I9UmICggE0gd"
         "H25TdzBEBCB9Wgl1/CwwV+72dTBBev/n+4BVwSbcXGzpSktE8zC12QQgJtxcbOlK"
         "S0TzMLXZu9d8v5WEFilc9+HOa8zcGP+MB7YEQQSL0q65y35XyyxLSC/8gbevud4n"
         "4eO9I8I6RFO9ms4yYlR++DXD2sT9l/hGGhRhHcnCd0UTLe2OVFwdVMcvBGmXAiEA"
         "qftX26Huqbw+ZgqQnYONcYw5eqO1Yab3kB4OgpdIVqcCAQE="
         "-----END EC PARAMETERS-----");

   config.set("ec", "brainpool320r1",
         "-----BEGIN EC PARAMETERS-----"
         "MIIBEAIBATA0BgcqhkjOPQEBAikA015HIDa8T7fhPHhe0gHgZfmPz6b29A3vT5K5"
         "7HiT7Cj81BKx8bMuJzBUBCg+4wtWj7qw+IPM69RtPzu4oqc1E/XredpmGQ6whf+p"
         "9JLzdal9hg60BChSCIOUnf28QtOtGYZAaIpv4T9BNJVUtJrMMdzNiEU5gW9etKyP"
         "sfGmBFEEQ71+mvtT2LhSibzEjuW/5vIBN9EKCH6254ceKhClmccQr40NOeIGERT9"
         "0FVF7BzIq0CTJH93J14HQ//tEXGC6qnHeHeqrGrH01JF0WkujuECKQDTXkcgNrxP"
         "t+E8eF7SAeBl+Y/PpbaPEqMtSC7H7oZY6YaRVVtExZMRAgEB"
         "-----END EC PARAMETERS-----");

   config.set("ec", "brainpool384r1",
         "-----BEGIN EC PARAMETERS-----"
         "MIIBQAIBATA8BgcqhkjOPQEBAjEAjLkegqM4bSgPXW9+UOZB3xUvcQntVFa0ErHa"
         "GX+3ESOs06cpkB0acYdHABMxB+xTMGQEMHvDgsY9jBUMPHIICs4Fr6DCvqKOT7In"
         "hxORZe+6kfkPiqWBSlA61OsEqMfdIs4oJgQwBKjH3SLOKCaLObVUFvBEfC+3feEH"
         "3NKmLogOpT7rYtV8tDkCldvJlDq3hpb6UEwRBGEEHRxk8GjPRf+ipjqBt8E/a4hH"
         "o+d+8U/j23/K/gy9EOjoJuA0NtZGqu+HsuJH1K8eir4ddSD5wqRcseuOlc/VUmK3"
         "Cyn+7Fhk4ZwFT/mRKSgORkYhd5GBEUKCA0EmPFMVAjEAjLkegqM4bSgPXW9+UOZB"
         "3xUvcQntVFazHxZubKwEJafPOrava3/DEDuIMgLpBGVlAgEB"
         "-----END EC PARAMETERS-----");

   config.set("ec", "brainpool512r1",
         "-----BEGIN EC PARAMETERS-----"
         "MIIBogIBATBMBgcqhkjOPQEBAkEAqt2duNvpxIs/1OauM8n8B8swjbOzydIO1mOc"
         "ynAzCHF9TZsAm8ZoQq7NoSrmo4DmKIH/Ly2CxoUoqmBWWDpI8zCBhARAeDCjMYtg"
         "O4niMnFFrCNMxZTL3Y09+RYQqDRByuqYY7wt7V1aqCU6oQou8cmLmsi1fxEXpyvy"
         "x7nnwaxNd/yUygRAPfkWEKg0QcrqmGO8Le1dWqglOqEKLvHJi5rItX8RF6cr8se5"
         "58GsTXf8lMrcCD5nmEBQt1665d0oCb1jgBb3IwSBgQSBruS92C7ZZFohMi6cTGqT"
         "he2fcLXZFsG0O2Lu9NAJjv87H3ji0NSNUNFoe5O5fV98bVBHQGpeaIs1Igm8ufgi"
         "fd44XVZjMuzA6r+pz3gi/fIJ9wAkpXsaoADFW4gfgRGy3N5JSl9IXlvKS9iKJ2Ou"
         "0corL6jwVAZ4zR4POtgIkgJBAKrdnbjb6cSLP9TmrjPJ/AfLMI2zs8nSDtZjnMpw"
         "MwhwVT5cQUypJhlBhmEZf6wQRx2x04EIXdrdtYeWgpypAGkCAQE="
         "-----END EC PARAMETERS-----");

   config.set("ec", "x962_p192v2",
         "-----BEGIN EC PARAMETERS-----"
         "MIGwAgEBMCQGByqGSM49AQECGQD////////////////////+//////////8wNAQY"
         "/////////////////////v/////////8BBjMItbfuVxrJeScDWNkpOWYDDk6ohZo"
         "2VMEMQTuorrn4Ul4QvLed2nP6cmJwHKtaW9IA0pldNEdabbsemcruCoIPfLysIR9"
         "6XCy3hUCGQD///////////////5fsack3IBBhkjY3TECAQE="
         "-----END EC PARAMETERS-----");

   config.set("ec", "x962_p192v3",
         "-----BEGIN EC PARAMETERS-----"
         "MIGwAgEBMCQGByqGSM49AQECGQD////////////////////+//////////8wNAQY"
         "/////////////////////v/////////8BBgiEj3COVoFyqdCPa7MyUdgp9RiJWvV"
         "aRYEMQR9KXeBAMZaHaF4NxZYjc4ri0rujiKPGJY4qQ8iY3M3M0tJ3LZqbcj5l4rK"
         "dkipQ7ACGQD///////////////96YtAxyD9ClPZA7BMCAQE="
         "-----END EC PARAMETERS-----");

   config.set("ec", "x962_p239v1",
         "-----BEGIN EC PARAMETERS-----"
         "MIHSAgEBMCkGByqGSM49AQECHn///////////////3///////4AAAAAAAH//////"
         "/zBABB5///////////////9///////+AAAAAAAB///////wEHmsBbDvc8YlB0NZU"
         "khR1ynGp2y+yfR03eWGFwpQsCgQ9BA/6ljzcqIFszDO4ZCvt+QXD01hXPT8n+707"
         "PLmqr33r6OTpCl2ubkBUylMLoEZUs2gYziJrOfzLewLxrgIef///////////////"
         "f///nl6an12QcfvRUiaIkJ0LAgEB"
         "-----END EC PARAMETERS-----");

   config.set("ec", "x962_p239v2",
         "-----BEGIN EC PARAMETERS-----"
         "MIHSAgEBMCkGByqGSM49AQECHn///////////////3///////4AAAAAAAH//////"
         "/zBABB5///////////////9///////+AAAAAAAB///////wEHmF/q2gyV2y7/tUN"
         "mfAknD/uWLlLoAOMeuhMjIMvLAQ9BDivCdmHJ3BRIMkhu16eJilqPNzy81dXoOr9"
         "h7gw51sBJeTb6g7HIG2g/AHZsIEyn7VV3m70YCN9/4vkugIef///////////////"
         "gAAAz6foWUN31BTAOCG8WCBjAgEB"
         "-----END EC PARAMETERS-----");

   config.set("ec", "x962_p239v3",
         "-----BEGIN EC PARAMETERS-----"
         "MIHSAgEBMCkGByqGSM49AQECHn///////////////3///////4AAAAAAAH//////"
         "/zBABB5///////////////9///////+AAAAAAAB///////wEHiVXBfoqMGZUsfTL"
         "A9anUKMMJQEC1JiHF9m6FattPgQ9BGdoro4Yu5LPzwBclJqixtlIU9DmYLv4VLHJ"
         "UF/pWhYH5omPOQwGvB1VK60ibztvz+SLboGEma8Y4+1s8wIef///////////////"
         "f///l13rQbOmBXw8QyFGUmVRAgEB"
         "-----END EC PARAMETERS-----");

   config.set("ec", "gost_256A",
         "-----BEGIN EC PARAMETERS-----"
         "MIHgAgEBMCwGByqGSM49AQECIQD/////////////////////////////////////"
         "///9lzBEBCD////////////////////////////////////////9lAQgAAAAAAAA"
         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKYEQQQAAAAAAAAAAAAAAAAAAAAAAAAA"
         "AAAAAAAAAAAAAAAAAY2R5HHgmJzaJ99QWkU/K3Y1KU8t3yPjsSKsyZyenx4UAiEA"
         "/////////////////////2xhEHCZWtEARYQbCbdhuJMCAQE="
         "-----END EC PARAMETERS-----");
   }
}

/*
* Set the default policy
*/
void Library_State::load_default_config()
   {
   set_default_aliases(*this);
   set_default_oids(*this);
   set_default_dl_groups(*this);
   }

}
