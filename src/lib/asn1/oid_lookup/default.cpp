/*
* OID Registry
* (C) 1999-2010,2013,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/oids.h>

namespace Botan {

namespace OIDS {

const char* default_oid_list()
   {
   return

      // Public key types
      "1.2.840.113549.1.1.1 = RSA" "\n"
      "2.5.8.1.1 = RSA" "\n"
      "1.2.840.10040.4.1 = DSA" "\n"
      "1.2.840.10046.2.1 = DH" "\n"
      "1.3.6.1.4.1.3029.1.2.1 = ElGamal" "\n"
      "1.3.6.1.4.1.25258.1.1 = RW" "\n"
      "1.3.6.1.4.1.25258.1.2 = NR" "\n"
      "1.3.6.1.4.1.25258.1.3 = McEliece" "\n"
      "1.3.6.1.4.1.25258.1.4 = Curve25519" "\n"

      // X9.62 ecPublicKey, valid for ECDSA and ECDH (RFC 3279 sec 2.3.5)
      "1.2.840.10045.2.1 = ECDSA" "\n"
      "1.3.132.1.12 = ECDH" "\n"

      "1.2.643.2.2.19 = GOST-34.10" "\n"

      // Block ciphers
      "1.3.14.3.2.7 = DES/CBC" "\n"
      "1.2.840.113549.3.7 = TripleDES/CBC" "\n"
      "1.2.840.113549.3.2 = RC2/CBC" "\n"
      "1.2.840.113533.7.66.10 = CAST-128/CBC" "\n"
      "2.16.840.1.101.3.4.1.2 = AES-128/CBC" "\n"
      "2.16.840.1.101.3.4.1.22 = AES-192/CBC" "\n"
      "2.16.840.1.101.3.4.1.42 = AES-256/CBC" "\n"
      "1.2.410.200004.1.4 = SEED/CBC" "\n"
      "1.3.6.1.4.1.25258.3.1 = Serpent/CBC" "\n"
      "1.3.6.1.4.1.25258.3.2 = Threefish-512/CBC" "\n"
      "1.3.6.1.4.1.25258.3.3 = Twofish/CBC" "\n"

      "2.16.840.1.101.3.4.1.6 = AES-128/GCM" "\n"
      "2.16.840.1.101.3.4.1.26 = AES-192/GCM" "\n"
      "2.16.840.1.101.3.4.1.46 = AES-256/GCM" "\n"

      "1.3.6.1.4.1.25258.3.101 = Serpent/GCM" "\n"
      "1.3.6.1.4.1.25258.3.102 = Twofish/GCM" "\n"

      "1.3.6.1.4.1.25258.3.2.1 = AES-128/OCB" "\n"
      "1.3.6.1.4.1.25258.3.2.2 = AES-192/OCB" "\n"
      "1.3.6.1.4.1.25258.3.2.3 = AES-256/OCB" "\n"
      "1.3.6.1.4.1.25258.3.2.4 = Serpent/OCB" "\n"
      "1.3.6.1.4.1.25258.3.2.5 = Twofish/OCB" "\n"

      // Hashes
      "1.2.840.113549.2.5 = MD5" "\n"
      "1.3.6.1.4.1.11591.12.2 = Tiger(24,3)" "\n"

      "1.3.14.3.2.26 = SHA-160" "\n"
      "2.16.840.1.101.3.4.2.4 = SHA-224" "\n"
      "2.16.840.1.101.3.4.2.1 = SHA-256" "\n"
      "2.16.840.1.101.3.4.2.2 = SHA-384" "\n"
      "2.16.840.1.101.3.4.2.3 = SHA-512" "\n"
      "2.16.840.1.101.3.4.2.6 = SHA-512-256" "\n"

      // MACs
      "1.2.840.113549.2.7 = HMAC(SHA-160)" "\n"
      "1.2.840.113549.2.8 = HMAC(SHA-224)" "\n"
      "1.2.840.113549.2.9 = HMAC(SHA-256)" "\n"
      "1.2.840.113549.2.10 = HMAC(SHA-384)" "\n"
      "1.2.840.113549.2.11 = HMAC(SHA-512)" "\n"

      // Keywrap
      "1.2.840.113549.1.9.16.3.6 = KeyWrap.TripleDES" "\n"
      "1.2.840.113549.1.9.16.3.7 = KeyWrap.RC2" "\n"
      "1.2.840.113533.7.66.15 = KeyWrap.CAST-128" "\n"
      "2.16.840.1.101.3.4.1.5 = KeyWrap.AES-128" "\n"
      "2.16.840.1.101.3.4.1.25 = KeyWrap.AES-192" "\n"
      "2.16.840.1.101.3.4.1.45 = KeyWrap.AES-256" "\n"

      "1.2.840.113549.1.9.16.3.8 = Compression.Zlib" "\n"

      "1.2.840.113549.1.1.1 = RSA/EME-PKCS1-v1_5" "\n"
      "1.2.840.113549.1.1.2 = RSA/EMSA3(MD2)" "\n"
      "1.2.840.113549.1.1.4 = RSA/EMSA3(MD5)" "\n"
      "1.2.840.113549.1.1.5 = RSA/EMSA3(SHA-160)" "\n"
      "1.2.840.113549.1.1.11 = RSA/EMSA3(SHA-256)" "\n"
      "1.2.840.113549.1.1.12 = RSA/EMSA3(SHA-384)" "\n"
      "1.2.840.113549.1.1.13 = RSA/EMSA3(SHA-512)" "\n"
      "1.3.36.3.3.1.2 = RSA/EMSA3(RIPEMD-160)" "\n"

      "1.2.840.10040.4.3 = DSA/EMSA1(SHA-160)" "\n"
      "2.16.840.1.101.3.4.3.1 = DSA/EMSA1(SHA-224)" "\n"
      "2.16.840.1.101.3.4.3.2 = DSA/EMSA1(SHA-256)" "\n"

      "0.4.0.127.0.7.1.1.4.1.1 = ECDSA/EMSA1_BSI(SHA-160)" "\n"
      "0.4.0.127.0.7.1.1.4.1.2 = ECDSA/EMSA1_BSI(SHA-224)" "\n"
      "0.4.0.127.0.7.1.1.4.1.3 = ECDSA/EMSA1_BSI(SHA-256)" "\n"
      "0.4.0.127.0.7.1.1.4.1.4 = ECDSA/EMSA1_BSI(SHA-384)" "\n"
      "0.4.0.127.0.7.1.1.4.1.5 = ECDSA/EMSA1_BSI(SHA-512)" "\n"
      "0.4.0.127.0.7.1.1.4.1.6 = ECDSA/EMSA1_BSI(RIPEMD-160)" "\n"

      "1.2.840.10045.4.1 = ECDSA/EMSA1(SHA-160)" "\n"
      "1.2.840.10045.4.3.1 = ECDSA/EMSA1(SHA-224)" "\n"
      "1.2.840.10045.4.3.2 = ECDSA/EMSA1(SHA-256)" "\n"
      "1.2.840.10045.4.3.3 = ECDSA/EMSA1(SHA-384)" "\n"
      "1.2.840.10045.4.3.4 = ECDSA/EMSA1(SHA-512)" "\n"

      "1.2.643.2.2.3 = GOST-34.10/EMSA1(GOST-R-34.11-94)" "\n"

      "1.3.6.1.4.1.25258.2.1.1.1 = RW/EMSA2(RIPEMD-160)" "\n"
      "1.3.6.1.4.1.25258.2.1.1.2 = RW/EMSA2(SHA-160)" "\n"
      "1.3.6.1.4.1.25258.2.1.1.3 = RW/EMSA2(SHA-224)" "\n"
      "1.3.6.1.4.1.25258.2.1.1.4 = RW/EMSA2(SHA-256)" "\n"
      "1.3.6.1.4.1.25258.2.1.1.5 = RW/EMSA2(SHA-384)" "\n"
      "1.3.6.1.4.1.25258.2.1.1.6 = RW/EMSA2(SHA-512)" "\n"

      "1.3.6.1.4.1.25258.2.1.2.1 = RW/EMSA4(RIPEMD-160)" "\n"
      "1.3.6.1.4.1.25258.2.1.2.2 = RW/EMSA4(SHA-160)" "\n"
      "1.3.6.1.4.1.25258.2.1.2.3 = RW/EMSA4(SHA-224)" "\n"
      "1.3.6.1.4.1.25258.2.1.2.4 = RW/EMSA4(SHA-256)" "\n"
      "1.3.6.1.4.1.25258.2.1.2.5 = RW/EMSA4(SHA-384)" "\n"
      "1.3.6.1.4.1.25258.2.1.2.6 = RW/EMSA4(SHA-512)" "\n"

      "1.3.6.1.4.1.25258.2.2.1.1 = NR/EMSA2(RIPEMD-160)" "\n"
      "1.3.6.1.4.1.25258.2.2.1.2 = NR/EMSA2(SHA-160)" "\n"
      "1.3.6.1.4.1.25258.2.2.1.3 = NR/EMSA2(SHA-224)" "\n"
      "1.3.6.1.4.1.25258.2.2.1.4 = NR/EMSA2(SHA-256)" "\n"
      "1.3.6.1.4.1.25258.2.2.1.5 = NR/EMSA2(SHA-384)" "\n"
      "1.3.6.1.4.1.25258.2.2.1.6 = NR/EMSA2(SHA-512)" "\n"

      "2.5.4.3 = X520.CommonName" "\n"
      "2.5.4.4 = X520.Surname" "\n"
      "2.5.4.5 = X520.SerialNumber" "\n"
      "2.5.4.6 = X520.Country" "\n"
      "2.5.4.7 = X520.Locality" "\n"
      "2.5.4.8 = X520.State" "\n"
      "2.5.4.10 = X520.Organization" "\n"
      "2.5.4.11 = X520.OrganizationalUnit" "\n"
      "2.5.4.12 = X520.Title" "\n"
      "2.5.4.42 = X520.GivenName" "\n"
      "2.5.4.43 = X520.Initials" "\n"
      "2.5.4.44 = X520.GenerationalQualifier" "\n"
      "2.5.4.46 = X520.DNQualifier" "\n"
      "2.5.4.65 = X520.Pseudonym" "\n"

      "1.2.840.113549.1.5.12 = PKCS5.PBKDF2" "\n"
      "1.2.840.113549.1.5.13 = PBE-PKCS5v20" "\n"

      "1.2.840.113549.1.9.1 = PKCS9.EmailAddress" "\n"
      "1.2.840.113549.1.9.2 = PKCS9.UnstructuredName" "\n"
      "1.2.840.113549.1.9.3 = PKCS9.ContentType" "\n"
      "1.2.840.113549.1.9.4 = PKCS9.MessageDigest" "\n"
      "1.2.840.113549.1.9.7 = PKCS9.ChallengePassword" "\n"
      "1.2.840.113549.1.9.14 = PKCS9.ExtensionRequest" "\n"

      "1.2.840.113549.1.7.1 = CMS.DataContent" "\n"
      "1.2.840.113549.1.7.2 = CMS.SignedData" "\n"
      "1.2.840.113549.1.7.3 = CMS.EnvelopedData" "\n"
      "1.2.840.113549.1.7.5 = CMS.DigestedData" "\n"
      "1.2.840.113549.1.7.6 = CMS.EncryptedData" "\n"
      "1.2.840.113549.1.9.16.1.2 = CMS.AuthenticatedData" "\n"
      "1.2.840.113549.1.9.16.1.9 = CMS.CompressedData" "\n"

      "2.5.29.14 = X509v3.SubjectKeyIdentifier" "\n"
      "2.5.29.15 = X509v3.KeyUsage" "\n"
      "2.5.29.17 = X509v3.SubjectAlternativeName" "\n"
      "2.5.29.18 = X509v3.IssuerAlternativeName" "\n"
      "2.5.29.19 = X509v3.BasicConstraints" "\n"
      "2.5.29.20 = X509v3.CRLNumber" "\n"
      "2.5.29.21 = X509v3.ReasonCode" "\n"
      "2.5.29.23 = X509v3.HoldInstructionCode" "\n"
      "2.5.29.24 = X509v3.InvalidityDate" "\n"
      "2.5.29.30 = X509v3.NameConstraints" "\n"
      "2.5.29.31 = X509v3.CRLDistributionPoints" "\n"
      "2.5.29.32 = X509v3.CertificatePolicies" "\n"
      "2.5.29.35 = X509v3.AuthorityKeyIdentifier" "\n"
      "2.5.29.36 = X509v3.PolicyConstraints" "\n"
      "2.5.29.37 = X509v3.ExtendedKeyUsage" "\n"
      "1.3.6.1.5.5.7.1.1 = PKIX.AuthorityInformationAccess" "\n"

      "2.5.29.32.0 = X509v3.AnyPolicy" "\n"

      "1.3.6.1.5.5.7.3.1 = PKIX.ServerAuth" "\n"
      "1.3.6.1.5.5.7.3.2 = PKIX.ClientAuth" "\n"
      "1.3.6.1.5.5.7.3.3 = PKIX.CodeSigning" "\n"
      "1.3.6.1.5.5.7.3.4 = PKIX.EmailProtection" "\n"
      "1.3.6.1.5.5.7.3.5 = PKIX.IPsecEndSystem" "\n"
      "1.3.6.1.5.5.7.3.6 = PKIX.IPsecTunnel" "\n"
      "1.3.6.1.5.5.7.3.7 = PKIX.IPsecUser" "\n"
      "1.3.6.1.5.5.7.3.8 = PKIX.TimeStamping" "\n"
      "1.3.6.1.5.5.7.3.9 = PKIX.OCSPSigning" "\n"

      "1.3.6.1.5.5.7.8.5 = PKIX.XMPPAddr" "\n"

      "1.3.6.1.5.5.7.48.1 = PKIX.OCSP" "\n"
      "1.3.6.1.5.5.7.48.1.1 = PKIX.OCSP.BasicResponse" "\n"

      "1.3.6.1.4.1.311.20.2.2 = Microsoft SmartcardLogon" "\n"

      // ECC param sets
      "1.3.132.0.8 = secp160r1" "\n"
      "1.3.132.0.9 = secp160k1" "\n"
      "1.3.132.0.10 = secp256k1" "\n"
      "1.3.132.0.30 = secp160r2" "\n"
      "1.3.132.0.31 = secp192k1" "\n"
      "1.3.132.0.32 = secp224k1" "\n"
      "1.3.132.0.33 = secp224r1" "\n"
      "1.3.132.0.34 = secp384r1" "\n"
      "1.3.132.0.35 = secp521r1" "\n"

      "1.2.840.10045.3.1.1 = secp192r1" "\n"
      "1.2.840.10045.3.1.2 = x962_p192v2" "\n"
      "1.2.840.10045.3.1.3 = x962_p192v3" "\n"
      "1.2.840.10045.3.1.4 = x962_p239v1" "\n"
      "1.2.840.10045.3.1.5 = x962_p239v2" "\n"
      "1.2.840.10045.3.1.6 = x962_p239v3" "\n"
      "1.2.840.10045.3.1.7 = secp256r1" "\n"

      "1.3.36.3.3.2.8.1.1.1 = brainpool160r1" "\n"
      "1.3.36.3.3.2.8.1.1.3 = brainpool192r1" "\n"
      "1.3.36.3.3.2.8.1.1.5 = brainpool224r1" "\n"
      "1.3.36.3.3.2.8.1.1.7 = brainpool256r1" "\n"
      "1.3.36.3.3.2.8.1.1.9 = brainpool320r1" "\n"
      "1.3.36.3.3.2.8.1.1.11 = brainpool384r1" "\n"
      "1.3.36.3.3.2.8.1.1.13 = brainpool512r1" "\n"

      "1.3.6.1.4.1.8301.3.1.2.9.0.38 = secp521r1" "\n"

      "1.2.643.2.2.35.1 = gost_256A" "\n"
      "1.2.643.2.2.36.0 = gost_256A" "\n"

      "0.4.0.127.0.7.3.1.2.1 = CertificateHolderAuthorizationTemplate" "\n"
      ;
   }

}

}
