/*
* Default Policy
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/libstate.h>
#include <botan/scan_name.h>

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
   add_oid(config, "0.4.0.127.0.7.3.1.2.1", "CertificateHolderAuthorizationTemplate");
   }

/*
* Set the default algorithm aliases
*/
void set_default_aliases(Library_State& )
   {
   // common variations worth supporting
   // SHA-1 alone requires supporting something
   SCAN_Name::add_alias("EME-PKCS1-v1_5",  "PKCS1v15");
   SCAN_Name::add_alias("3DES",     "TripleDES");
   SCAN_Name::add_alias("DES-EDE",  "TripleDES");
   SCAN_Name::add_alias("CAST5",    "CAST-128");
   SCAN_Name::add_alias("SHA1",     "SHA-160");
   SCAN_Name::add_alias("SHA-1",    "SHA-160");
   SCAN_Name::add_alias("MARK-4",   "RC4(256)");
   SCAN_Name::add_alias("ARC4",     "RC4");
   SCAN_Name::add_alias("OMAC",     "CMAC");

   // should be renamed in sources
   SCAN_Name::add_alias("OAEP-MGF1",       "EME1");
   SCAN_Name::add_alias("EME-OAEP",        "EME1");
   SCAN_Name::add_alias("X9.31",           "EMSA2");
   SCAN_Name::add_alias("EMSA-PKCS1-v1_5", "EMSA3");
   SCAN_Name::add_alias("PSS-MGF1",        "EMSA4");
   SCAN_Name::add_alias("EMSA-PSS",        "EMSA4");

   // probably can be removed
   SCAN_Name::add_alias("GOST",     "GOST-28147-89");
   SCAN_Name::add_alias("GOST-34.11", "GOST-R-34.11-94");
   }

}

/*
* Set the default policy
*/
void Library_State::load_default_config()
   {
   set_default_aliases(*this);
   set_default_oids(*this);
   }

}
