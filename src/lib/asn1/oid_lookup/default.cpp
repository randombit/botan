/*
* OID Registry
* (C) 1999-2010,2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/oids.h>

namespace Botan {

namespace OIDS {

/*
* Load all of the default OIDs
*/
void set_defaults()
   {
   /* Public key types */
   OIDS::add_oidstr("1.2.840.113549.1.1.1", "RSA");
   OIDS::add_oidstr("2.5.8.1.1", "RSA"); // RSA alternate
   OIDS::add_oidstr("1.2.840.10040.4.1", "DSA");
   OIDS::add_oidstr("1.2.840.10046.2.1", "DH");
   OIDS::add_oidstr("1.3.6.1.4.1.3029.1.2.1", "ElGamal");
   OIDS::add_oidstr("1.3.6.1.4.1.25258.1.1", "RW");
   OIDS::add_oidstr("1.3.6.1.4.1.25258.1.2", "NR");

   // X9.62 ecPublicKey, valid for ECDSA and ECDH (RFC 3279 sec 2.3.5)
   OIDS::add_oidstr("1.2.840.10045.2.1", "ECDSA");

   /*
   * This is an OID defined for ECDH keys though rarely used for such.
   * In this configuration it is accepted on decoding, but not used for
   * encoding. You can enable it for encoding by calling
   *    OIDS::add_str2oid("ECDH", "1.3.132.1.12")
   * from your application code.
   */
   OIDS::add_oid2str(OID("1.3.132.1.12"), "ECDH");

   OIDS::add_oidstr("1.2.643.2.2.19", "GOST-34.10"); // RFC 4491

   /* Ciphers */
   OIDS::add_oidstr("1.3.14.3.2.7", "DES/CBC");
   OIDS::add_oidstr("1.2.840.113549.3.7", "TripleDES/CBC");
   OIDS::add_oidstr("1.2.840.113549.3.2", "RC2/CBC");
   OIDS::add_oidstr("1.2.840.113533.7.66.10", "CAST-128/CBC");
   OIDS::add_oidstr("2.16.840.1.101.3.4.1.2", "AES-128/CBC");
   OIDS::add_oidstr("2.16.840.1.101.3.4.1.22", "AES-192/CBC");
   OIDS::add_oidstr("2.16.840.1.101.3.4.1.42", "AES-256/CBC");
   OIDS::add_oidstr("1.2.410.200004.1.4", "SEED/CBC"); // RFC 4010
   OIDS::add_oidstr("1.3.6.1.4.1.25258.3.1", "Serpent/CBC");
   OIDS::add_oidstr("1.3.6.1.4.1.25258.3.2", "Threefish-512/CBC");

   OIDS::add_oidstr("2.16.840.1.101.3.4.1.6", "AES-128/GCM");
   OIDS::add_oidstr("2.16.840.1.101.3.4.1.26", "AES-192/GCM");
   OIDS::add_oidstr("2.16.840.1.101.3.4.1.46", "AES-256/GCM");

   /* Hash Functions */
   OIDS::add_oidstr("1.2.840.113549.2.5", "MD5");
   OIDS::add_oidstr("1.3.6.1.4.1.11591.12.2", "Tiger(24,3)");

   OIDS::add_oidstr("1.3.14.3.2.26", "SHA-160");
   OIDS::add_oidstr("2.16.840.1.101.3.4.2.4", "SHA-224");
   OIDS::add_oidstr("2.16.840.1.101.3.4.2.1", "SHA-256");
   OIDS::add_oidstr("2.16.840.1.101.3.4.2.2", "SHA-384");
   OIDS::add_oidstr("2.16.840.1.101.3.4.2.3", "SHA-512");

   /* MACs */
   OIDS::add_oidstr("1.2.840.113549.2.7", "HMAC(SHA-160)");
   OIDS::add_oidstr("1.2.840.113549.2.8", "HMAC(SHA-224)");
   OIDS::add_oidstr("1.2.840.113549.2.9", "HMAC(SHA-256)");
   OIDS::add_oidstr("1.2.840.113549.2.10", "HMAC(SHA-384)");
   OIDS::add_oidstr("1.2.840.113549.2.11", "HMAC(SHA-512)");

   /* Key Wrap */
   OIDS::add_oidstr("1.2.840.113549.1.9.16.3.6", "KeyWrap.TripleDES");
   OIDS::add_oidstr("1.2.840.113549.1.9.16.3.7", "KeyWrap.RC2");
   OIDS::add_oidstr("1.2.840.113533.7.66.15", "KeyWrap.CAST-128");
   OIDS::add_oidstr("2.16.840.1.101.3.4.1.5", "KeyWrap.AES-128");
   OIDS::add_oidstr("2.16.840.1.101.3.4.1.25", "KeyWrap.AES-192");
   OIDS::add_oidstr("2.16.840.1.101.3.4.1.45", "KeyWrap.AES-256");

   /* Compression */
   OIDS::add_oidstr("1.2.840.113549.1.9.16.3.8", "Compression.Zlib");

   /* Public key signature schemes */
   OIDS::add_oidstr("1.2.840.113549.1.1.1", "RSA/EME-PKCS1-v1_5");
   OIDS::add_oidstr("1.2.840.113549.1.1.2", "RSA/EMSA3(MD2)");
   OIDS::add_oidstr("1.2.840.113549.1.1.4", "RSA/EMSA3(MD5)");
   OIDS::add_oidstr("1.2.840.113549.1.1.5", "RSA/EMSA3(SHA-160)");
   OIDS::add_oidstr("1.2.840.113549.1.1.11", "RSA/EMSA3(SHA-256)");
   OIDS::add_oidstr("1.2.840.113549.1.1.12", "RSA/EMSA3(SHA-384)");
   OIDS::add_oidstr("1.2.840.113549.1.1.13", "RSA/EMSA3(SHA-512)");
   OIDS::add_oidstr("1.3.36.3.3.1.2", "RSA/EMSA3(RIPEMD-160)");

   OIDS::add_oidstr("1.2.840.10040.4.3", "DSA/EMSA1(SHA-160)");
   OIDS::add_oidstr("2.16.840.1.101.3.4.3.1", "DSA/EMSA1(SHA-224)");
   OIDS::add_oidstr("2.16.840.1.101.3.4.3.2", "DSA/EMSA1(SHA-256)");

   OIDS::add_oidstr("0.4.0.127.0.7.1.1.4.1.1", "ECDSA/EMSA1_BSI(SHA-160)");
   OIDS::add_oidstr("0.4.0.127.0.7.1.1.4.1.2", "ECDSA/EMSA1_BSI(SHA-224)");
   OIDS::add_oidstr("0.4.0.127.0.7.1.1.4.1.3", "ECDSA/EMSA1_BSI(SHA-256)");
   OIDS::add_oidstr("0.4.0.127.0.7.1.1.4.1.4", "ECDSA/EMSA1_BSI(SHA-384)");
   OIDS::add_oidstr("0.4.0.127.0.7.1.1.4.1.5", "ECDSA/EMSA1_BSI(SHA-512)");
   OIDS::add_oidstr("0.4.0.127.0.7.1.1.4.1.6", "ECDSA/EMSA1_BSI(RIPEMD-160)");

   OIDS::add_oidstr("1.2.840.10045.4.1", "ECDSA/EMSA1(SHA-160)");
   OIDS::add_oidstr("1.2.840.10045.4.3.1", "ECDSA/EMSA1(SHA-224)");
   OIDS::add_oidstr("1.2.840.10045.4.3.2", "ECDSA/EMSA1(SHA-256)");
   OIDS::add_oidstr("1.2.840.10045.4.3.3", "ECDSA/EMSA1(SHA-384)");
   OIDS::add_oidstr("1.2.840.10045.4.3.4", "ECDSA/EMSA1(SHA-512)");

   OIDS::add_oidstr("1.2.643.2.2.3", "GOST-34.10/EMSA1(GOST-R-34.11-94)");

   OIDS::add_oidstr("1.3.6.1.4.1.25258.2.1.1.1", "RW/EMSA2(RIPEMD-160)");
   OIDS::add_oidstr("1.3.6.1.4.1.25258.2.1.1.2", "RW/EMSA2(SHA-160)");
   OIDS::add_oidstr("1.3.6.1.4.1.25258.2.1.1.3", "RW/EMSA2(SHA-224)");
   OIDS::add_oidstr("1.3.6.1.4.1.25258.2.1.1.4", "RW/EMSA2(SHA-256)");
   OIDS::add_oidstr("1.3.6.1.4.1.25258.2.1.1.5", "RW/EMSA2(SHA-384)");
   OIDS::add_oidstr("1.3.6.1.4.1.25258.2.1.1.6", "RW/EMSA2(SHA-512)");

   OIDS::add_oidstr("1.3.6.1.4.1.25258.2.1.2.1", "RW/EMSA4(RIPEMD-160)");
   OIDS::add_oidstr("1.3.6.1.4.1.25258.2.1.2.2", "RW/EMSA4(SHA-160)");
   OIDS::add_oidstr("1.3.6.1.4.1.25258.2.1.2.3", "RW/EMSA4(SHA-224)");
   OIDS::add_oidstr("1.3.6.1.4.1.25258.2.1.2.4", "RW/EMSA4(SHA-256)");
   OIDS::add_oidstr("1.3.6.1.4.1.25258.2.1.2.5", "RW/EMSA4(SHA-384)");
   OIDS::add_oidstr("1.3.6.1.4.1.25258.2.1.2.6", "RW/EMSA4(SHA-512)");

   OIDS::add_oidstr("1.3.6.1.4.1.25258.2.2.1.1", "NR/EMSA2(RIPEMD-160)");
   OIDS::add_oidstr("1.3.6.1.4.1.25258.2.2.1.2", "NR/EMSA2(SHA-160)");
   OIDS::add_oidstr("1.3.6.1.4.1.25258.2.2.1.3", "NR/EMSA2(SHA-224)");
   OIDS::add_oidstr("1.3.6.1.4.1.25258.2.2.1.4", "NR/EMSA2(SHA-256)");
   OIDS::add_oidstr("1.3.6.1.4.1.25258.2.2.1.5", "NR/EMSA2(SHA-384)");
   OIDS::add_oidstr("1.3.6.1.4.1.25258.2.2.1.6", "NR/EMSA2(SHA-512)");

   OIDS::add_oidstr("2.5.4.3",  "X520.CommonName");
   OIDS::add_oidstr("2.5.4.4",  "X520.Surname");
   OIDS::add_oidstr("2.5.4.5",  "X520.SerialNumber");
   OIDS::add_oidstr("2.5.4.6",  "X520.Country");
   OIDS::add_oidstr("2.5.4.7",  "X520.Locality");
   OIDS::add_oidstr("2.5.4.8",  "X520.State");
   OIDS::add_oidstr("2.5.4.10", "X520.Organization");
   OIDS::add_oidstr("2.5.4.11", "X520.OrganizationalUnit");
   OIDS::add_oidstr("2.5.4.12", "X520.Title");
   OIDS::add_oidstr("2.5.4.42", "X520.GivenName");
   OIDS::add_oidstr("2.5.4.43", "X520.Initials");
   OIDS::add_oidstr("2.5.4.44", "X520.GenerationalQualifier");
   OIDS::add_oidstr("2.5.4.46", "X520.DNQualifier");
   OIDS::add_oidstr("2.5.4.65", "X520.Pseudonym");

   OIDS::add_oidstr("1.2.840.113549.1.5.12", "PKCS5.PBKDF2");
   OIDS::add_oidstr("1.2.840.113549.1.5.13", "PBE-PKCS5v20");

   OIDS::add_oidstr("1.2.840.113549.1.9.1", "PKCS9.EmailAddress");
   OIDS::add_oidstr("1.2.840.113549.1.9.2", "PKCS9.UnstructuredName");
   OIDS::add_oidstr("1.2.840.113549.1.9.3", "PKCS9.ContentType");
   OIDS::add_oidstr("1.2.840.113549.1.9.4", "PKCS9.MessageDigest");
   OIDS::add_oidstr("1.2.840.113549.1.9.7", "PKCS9.ChallengePassword");
   OIDS::add_oidstr("1.2.840.113549.1.9.14", "PKCS9.ExtensionRequest");

   OIDS::add_oidstr("1.2.840.113549.1.7.1",      "CMS.DataContent");
   OIDS::add_oidstr("1.2.840.113549.1.7.2",      "CMS.SignedData");
   OIDS::add_oidstr("1.2.840.113549.1.7.3",      "CMS.EnvelopedData");
   OIDS::add_oidstr("1.2.840.113549.1.7.5",      "CMS.DigestedData");
   OIDS::add_oidstr("1.2.840.113549.1.7.6",      "CMS.EncryptedData");
   OIDS::add_oidstr("1.2.840.113549.1.9.16.1.2", "CMS.AuthenticatedData");
   OIDS::add_oidstr("1.2.840.113549.1.9.16.1.9", "CMS.CompressedData");

   OIDS::add_oidstr("2.5.29.14", "X509v3.SubjectKeyIdentifier");
   OIDS::add_oidstr("2.5.29.15", "X509v3.KeyUsage");
   OIDS::add_oidstr("2.5.29.17", "X509v3.SubjectAlternativeName");
   OIDS::add_oidstr("2.5.29.18", "X509v3.IssuerAlternativeName");
   OIDS::add_oidstr("2.5.29.19", "X509v3.BasicConstraints");
   OIDS::add_oidstr("2.5.29.20", "X509v3.CRLNumber");
   OIDS::add_oidstr("2.5.29.21", "X509v3.ReasonCode");
   OIDS::add_oidstr("2.5.29.23", "X509v3.HoldInstructionCode");
   OIDS::add_oidstr("2.5.29.24", "X509v3.InvalidityDate");
   OIDS::add_oidstr("2.5.29.31", "X509v3.CRLDistributionPoints");
   OIDS::add_oidstr("2.5.29.32", "X509v3.CertificatePolicies");
   OIDS::add_oidstr("2.5.29.35", "X509v3.AuthorityKeyIdentifier");
   OIDS::add_oidstr("2.5.29.36", "X509v3.PolicyConstraints");
   OIDS::add_oidstr("2.5.29.37", "X509v3.ExtendedKeyUsage");
   OIDS::add_oidstr("1.3.6.1.5.5.7.1.1", "PKIX.AuthorityInformationAccess");

   OIDS::add_oidstr("2.5.29.32.0", "X509v3.AnyPolicy");

   OIDS::add_oidstr("1.3.6.1.5.5.7.3.1", "PKIX.ServerAuth");
   OIDS::add_oidstr("1.3.6.1.5.5.7.3.2", "PKIX.ClientAuth");
   OIDS::add_oidstr("1.3.6.1.5.5.7.3.3", "PKIX.CodeSigning");
   OIDS::add_oidstr("1.3.6.1.5.5.7.3.4", "PKIX.EmailProtection");
   OIDS::add_oidstr("1.3.6.1.5.5.7.3.5", "PKIX.IPsecEndSystem");
   OIDS::add_oidstr("1.3.6.1.5.5.7.3.6", "PKIX.IPsecTunnel");
   OIDS::add_oidstr("1.3.6.1.5.5.7.3.7", "PKIX.IPsecUser");
   OIDS::add_oidstr("1.3.6.1.5.5.7.3.8", "PKIX.TimeStamping");
   OIDS::add_oidstr("1.3.6.1.5.5.7.3.9", "PKIX.OCSPSigning");

   OIDS::add_oidstr("1.3.6.1.5.5.7.8.5", "PKIX.XMPPAddr");

   OIDS::add_oidstr("1.3.6.1.5.5.7.48.1", "PKIX.OCSP");
   OIDS::add_oidstr("1.3.6.1.5.5.7.48.1.1", "PKIX.OCSP.BasicResponse");

   /* ECC domain parameters */
   OIDS::add_oidstr("1.3.132.0.6",  "secp112r1");
   OIDS::add_oidstr("1.3.132.0.7",  "secp112r2");
   OIDS::add_oidstr("1.3.132.0.8",  "secp160r1");
   OIDS::add_oidstr("1.3.132.0.9",  "secp160k1");
   OIDS::add_oidstr("1.3.132.0.10", "secp256k1");
   OIDS::add_oidstr("1.3.132.0.28", "secp128r1");
   OIDS::add_oidstr("1.3.132.0.29", "secp128r2");
   OIDS::add_oidstr("1.3.132.0.30", "secp160r2");
   OIDS::add_oidstr("1.3.132.0.31", "secp192k1");
   OIDS::add_oidstr("1.3.132.0.32", "secp224k1");
   OIDS::add_oidstr("1.3.132.0.33", "secp224r1");
   OIDS::add_oidstr("1.3.132.0.34", "secp384r1");
   OIDS::add_oidstr("1.3.132.0.35", "secp521r1");

   OIDS::add_oidstr("1.2.840.10045.3.1.1", "secp192r1");
   OIDS::add_oidstr("1.2.840.10045.3.1.2", "x962_p192v2");
   OIDS::add_oidstr("1.2.840.10045.3.1.3", "x962_p192v3");
   OIDS::add_oidstr("1.2.840.10045.3.1.4", "x962_p239v1");
   OIDS::add_oidstr("1.2.840.10045.3.1.5", "x962_p239v2");
   OIDS::add_oidstr("1.2.840.10045.3.1.6", "x962_p239v3");
   OIDS::add_oidstr("1.2.840.10045.3.1.7", "secp256r1");

   OIDS::add_oidstr("1.3.36.3.3.2.8.1.1.1",  "brainpool160r1");
   OIDS::add_oidstr("1.3.36.3.3.2.8.1.1.3",  "brainpool192r1");
   OIDS::add_oidstr("1.3.36.3.3.2.8.1.1.5",  "brainpool224r1");
   OIDS::add_oidstr("1.3.36.3.3.2.8.1.1.7",  "brainpool256r1");
   OIDS::add_oidstr("1.3.36.3.3.2.8.1.1.9",  "brainpool320r1");
   OIDS::add_oidstr("1.3.36.3.3.2.8.1.1.11", "brainpool384r1");
   OIDS::add_oidstr("1.3.36.3.3.2.8.1.1.13", "brainpool512r1");

   OIDS::add_oidstr("1.2.643.2.2.35.1", "gost_256A");
   OIDS::add_oidstr("1.2.643.2.2.36.0", "gost_256A");

   /* CVC */
   OIDS::add_oidstr("0.4.0.127.0.7.3.1.2.1", "CertificateHolderAuthorizationTemplate");
   }

}

}
