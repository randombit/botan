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
   add_oid(config, "1.2.840.113549.2.7", "HMAC(SHA-160)");
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
   add_oid(config, "2.5.29.31", "X509v3.CRLDistributionPoints");
   add_oid(config, "2.5.29.32", "X509v3.CertificatePolicies");
   add_oid(config, "2.5.29.35", "X509v3.AuthorityKeyIdentifier");
   add_oid(config, "2.5.29.36", "X509v3.PolicyConstraints");
   add_oid(config, "2.5.29.37", "X509v3.ExtendedKeyUsage");
   add_oid(config, "1.3.6.1.5.5.7.1.1", "PKIX.AuthorityInformationAccess");

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

   add_oid(config, "1.3.6.1.5.5.7.48.1", "PKIX.OCSP");
   add_oid(config, "1.3.6.1.5.5.7.48.1.1", "PKIX.OCSP.BasicResponse");

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
   config.add_alias("MARK-4",   "RC4(256)");
   config.add_alias("ARC4",     "RC4");
   config.add_alias("OMAC",     "CMAC");
   config.add_alias("GOST",     "GOST-28147-89");
   config.add_alias("GOST-34.11", "GOST-R-34.11-94");
   }

/*
* Set the built-in discrete log groups
*/
void set_default_dl_groups(Library_State& config)
   {
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
