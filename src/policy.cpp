/*************************************************
* Default Policy Source File                     *
* (C) 1999-2007 The Botan Project                *
* (C) 2008  Falko Strenzke                       *
*           strenzke@flexsecure.de               *
*************************************************/

#include <botan/config.h>

namespace Botan {

namespace {

/*************************************************
* OID loading helper functions                   *
*************************************************/
void add_oid_to_section(const std::string& section_oid2str, const std::string section_str2oid, Config& config,
             const std::string& oid_str,
             const std::string& name)
{
    if(!config.is_set(section_oid2str, oid_str))
        config.set(section_oid2str, oid_str, name);
    if(!config.is_set(section_str2oid, name))
        config.set(section_str2oid, name, oid_str);
}
    void add_oid(Config& config,
                 const std::string& oid_str,
                 const std::string& name)
    {
        add_oid_to_section("oid2str", "str2oid", config, oid_str, name);
    }
    void add_oid_bsi(Config& config,
                     const std::string& oid_str,
                     const std::string& name)
    {
        add_oid_to_section("oid2str", "str2oid_bsi", config, oid_str, name);
        //NOTE: lookup of oid is generally applicable in all cases
        // whereas for the lookup of oid´s the domain ("normal"/bsi) has to be specified
    }

/*************************************************
* Load all of the default OIDs                   *
*************************************************/
void set_default_oids(Config& config)
   {
   add_oid(config, "0.4.0.127.0.7.3.1.2.1", "CertificateHolderAuthorizationTemplate");

   add_oid(config, "1.2.840.113549.1.1.1", "RSA");
   add_oid(config, "2.5.8.1.1", "RSA");

   /*
   add_oid(config, "1.2.840.10040.4.1", "DSA");
   */
   add_oid(config, "1.2.840.10046.2.1", "DH");

   add_oid(config, "1.2.840.10045.2.1", "ECDSA");
   add_oid(config, "1.2.840.10045.4.1", "ECDSA/EMSA1_BSI(SHA-1)");
   add_oid(config, "1.2.840.10045.4.3.1", "ECDSA/EMSA1_BSI(SHA-224)");
   add_oid(config, "1.2.840.10045.4.3.2", "ECDSA/EMSA1_BSI(SHA-256)");
   add_oid(config, "1.2.840.10045.4.3.3", "ECDSA/EMSA1_BSI(SHA-384)");
   add_oid(config, "1.2.840.10045.4.3.4", "ECDSA/EMSA1_BSI(SHA-512)");

   add_oid_bsi(config, "0.4.0.127.0.7.2.2.2.2.1", "ECDSA/EMSA1_BSI(SHA-1)");
   add_oid_bsi(config, "0.4.0.127.0.7.2.2.2.2.2", "ECDSA/EMSA1_BSI(SHA-224)");
   add_oid_bsi(config, "0.4.0.127.0.7.2.2.2.2.3", "ECDSA/EMSA1_BSI(SHA-256)");


   add_oid(config, "0.4.0.127.0.7.1.1.5.1", "ECKAEG"); // in the normal domain use the bsi oid as well
   add_oid_bsi(config, "0.4.0.127.0.7.1.1.5.1", "ECKAEG");
   /*
   add_oid(config, "1.3.6.1.4.1.3029.1.2.1", "ELG");
   add_oid(config, "1.3.6.1.4.1.25258.1.1", "RW");
   add_oid(config, "1.3.6.1.4.1.25258.1.2", "NR");
   */

   add_oid(config, "1.3.14.3.2.7", "DES/CBC");
   add_oid(config, "1.2.840.113549.3.7", "TripleDES/CBC");
   /*
   add_oid(config, "1.2.840.113549.3.2", "RC2/CBC");
   add_oid(config, "1.2.840.113533.7.66.10", "CAST-128/CBC");
   */
   add_oid(config, "2.16.840.1.101.3.4.1.2", "AES-128/CBC");
   add_oid(config, "2.16.840.1.101.3.4.1.22", "AES-192/CBC");
   add_oid(config, "2.16.840.1.101.3.4.1.42", "AES-256/CBC");

	/*
   add_oid(config, "1.2.840.113549.2.5", "MD5");
   */
   add_oid(config, "1.3.14.3.2.26", "SHA-160");
   add_oid(config, "2.16.840.1.101.3.4.2.4", "SHA-224");
   add_oid(config, "2.16.840.1.101.3.4.2.1", "SHA-256");
   add_oid(config, "2.16.840.1.101.3.4.2.2", "SHA-384");
   add_oid(config, "2.16.840.1.101.3.4.2.3", "SHA-512");


   /*
   add_oid(config, "1.3.6.1.4.1.11591.12.2", "Tiger(24,3)");
   */

   add_oid(config, "1.2.840.113549.1.9.16.3.6", "KeyWrap.TripleDES");
   /*
   add_oid(config, "1.2.840.113549.1.9.16.3.7", "KeyWrap.RC2");
   add_oid(config, "1.2.840.113533.7.66.15", "KeyWrap.CAST-128");
   */
   add_oid(config, "2.16.840.1.101.3.4.1.5", "KeyWrap.AES-128");
   add_oid(config, "2.16.840.1.101.3.4.1.25", "KeyWrap.AES-192");
   add_oid(config, "2.16.840.1.101.3.4.1.45", "KeyWrap.AES-256");

   add_oid(config, "1.2.840.113549.1.9.16.3.8", "Compression.Zlib");

   add_oid(config, "1.2.840.113549.1.1.1", "RSA/EME-PKCS1-v1_5");
   /*
   add_oid(config, "1.2.840.113549.1.1.2", "RSA/EMSA3(MD2)");
   add_oid(config, "1.2.840.113549.1.1.4", "RSA/EMSA3(MD5)");
   */
   add_oid(config, "1.2.840.113549.1.1.5", "RSA/EMSA3(SHA-160)");
   add_oid(config, "1.2.840.113549.1.1.11", "RSA/EMSA3(SHA-256)");
   add_oid(config, "1.2.840.113549.1.1.12", "RSA/EMSA3(SHA-384)");
   add_oid(config, "1.2.840.113549.1.1.13", "RSA/EMSA3(SHA-512)");
   add_oid(config, "1.3.36.3.3.1.2", "RSA/EMSA3(RIPEMD-160)");
   add_oid(config, "1.2.840.10040.4.3", "DSA/EMSA1(SHA-160)");
   add_oid(config, "2.16.840.1.101.3.4.3.1", "DSA/EMSA1(SHA-224)");
   add_oid(config, "2.16.840.1.101.3.4.3.2", "DSA/EMSA1(SHA-256)");


	/*
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
	*/
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
	/*
   add_oid(config, "1.2.840.113549.1.5.1",  "PBE-PKCS5v15(MD2,DES/CBC)");
   add_oid(config, "1.2.840.113549.1.5.4",  "PBE-PKCS5v15(MD2,RC2/CBC)");
   add_oid(config, "1.2.840.113549.1.5.3",  "PBE-PKCS5v15(MD5,DES/CBC)");
   add_oid(config, "1.2.840.113549.1.5.6",  "PBE-PKCS5v15(MD5,RC2/CBC)");
   */
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
   }

/*************************************************
* Set the default algorithm aliases              *
*************************************************/
void set_default_aliases(Config& config)
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
   config.add_alias("OpenPGP.Digest.7", "HAVAL(20,5)");
   config.add_alias("OpenPGP.Digest.8", "SHA-256");

   config.add_alias("TLS.Digest.0",     "Parallel(MD5,SHA-160)");

   config.add_alias("EME-PKCS1-v1_5",  "PKCS1v15");
   config.add_alias("OAEP-MGF1",       "EME1");
   config.add_alias("EME-OAEP",        "EME1");
   config.add_alias("X9.31",           "EMSA2");
   config.add_alias("EMSA-PKCS1-v1_5", "EMSA3");
   config.add_alias("PSS-MGF1",        "EMSA4");
   config.add_alias("EMSA-PSS",        "EMSA4");

   config.add_alias("Rijndael", "AES");
   config.add_alias("3DES",     "TripleDES");
   config.add_alias("DES-EDE",  "TripleDES");
   config.add_alias("CAST5",    "CAST-128");
   config.add_alias("SHA1",     "SHA-160");
   config.add_alias("SHA-1",    "SHA-160");
   config.add_alias("SEAL",     "SEAL-3.0-BE");
   config.add_alias("MARK-4",   "ARC4(256)");
   config.add_alias("OMAC",     "CMAC");
   }

/*************************************************
* Set the default configuration toggles          *
*************************************************/
void set_default_config(Config& config)
   {
   config.set_option("base/memory_chunk", "64*1024");
   config.set_option("base/pkcs8_tries", "3");
   config.set_option("base/default_pbe",
                     "PBE-PKCS5v20(SHA-1,TripleDES/CBC)");
   config.set_option("base/default_allocator", "malloc");

   config.set_option("pk/blinder_size", "64");
   config.set_option("pk/test/public", "basic");
   config.set_option("pk/test/private", "basic");
   config.set_option("pk/test/private_gen", "all");

   config.set_option("pem/search", "4*1024");
   config.set_option("pem/forgive", "8");
   config.set_option("pem/width", "64");

   config.set_option("rng/ms_capi_prov_type", "INTEL_SEC:RSA_FULL");
   config.set_option("rng/unix_path", "/usr/ucb:/usr/etc:/etc");
   config.set_option("rng/es_files", "/dev/urandom:/dev/random");
   config.set_option("rng/egd_path",
                     "/var/run/egd-pool:/dev/egd-pool");
   config.set_option("rng/slow_poll_request", "256");
   config.set_option("rng/fast_poll_request", "64");

   config.set_option("x509/validity_slack", "24h");
   config.set_option("x509/v1_assume_ca", "false");
   config.set_option("x509/cache_verify_results", "30m");

   config.set_option("x509/ca/allow_ca", "false");
   config.set_option("x509/ca/basic_constraints", "always");
   config.set_option("x509/ca/default_expire", "1y");
   config.set_option("x509/ca/signing_offset", "30s");
   config.set_option("x509/ca/rsa_hash", "SHA-1");
   config.set_option("x509/ca/ecdsa_hash", "SHA-224");
   config.set_option("x509/ca/str_type", "latin1");

   config.set_option("x509/crl/unknown_critical", "ignore");
   config.set_option("x509/crl/next_update", "7d");

   config.set_option("x509/exts/basic_constraints", "critical");
   config.set_option("x509/exts/subject_key_id", "yes");
   config.set_option("x509/exts/authority_key_id", "yes");
   config.set_option("x509/exts/subject_alternative_name", "yes");
   config.set_option("x509/exts/issuer_alternative_name", "no");
   config.set_option("x509/exts/key_usage", "critical");
   config.set_option("x509/exts/extended_key_usage", "yes");
   config.set_option("x509/exts/crl_number", "yes");

   config.set_option("eac/ca/cvca_validity_months", "12");
   config.set_option("eac/ca/dvca_validity_months", "3");
   config.set_option("eac/ca/is_validity_months", "1");
   }

/*************************************************
* Set the built-in discrete log groups           *
*************************************************/
void set_default_dl_groups(Config& config)
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
   }


	/*************************************************
	* Set the built-in EC domain parameters          *
	*************************************************/

	void set_default_ec_dompar(Config& config)
	{
		{
		    /* secp160r1; source:
		    GEC 2: Test Vectors for SEC 1
		    Certicom Research
		            Working Draft
		            September, 1999
		            Version 0.3;
		            section 2.1.2*/
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xffffffffffffffffffffffffffffffff7fffffff"); //p
		    dom_par.push_back("0xffffffffffffffffffffffffffffffff7ffffffc"); // a
		    dom_par.push_back("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45"); // b
		    dom_par.push_back("024a96b5688ef573284664698968c38bb913cbfc82"); // G
		    dom_par.push_back("0x0100000000000000000001f4c8f927aed3ca752257"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.3.132.0.8", dom_par);
		}

		{
		    /* prime192v1; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xfffffffffffffffffffffffffffffffeffffffffffffffff"); //p
		    dom_par.push_back("0xfffffffffffffffffffffffffffffffefffffffffffffffc"); // a
		    dom_par.push_back("0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1"); // b
		    dom_par.push_back("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012"); // G
		    dom_par.push_back("0xffffffffffffffffffffffff99def836146bc9b1b4d22831"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.2.840.10045.3.1.1", dom_par);
		}

		{
		    /* prime192v2; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xfffffffffffffffffffffffffffffffeffffffffffffffff"); //p
		    dom_par.push_back("0xffffffffffffffffffffffffffffffFeffffffffffffffFC"); // a
		    dom_par.push_back("0xcc22d6dfb95c6b25e49c0d6364a4e5980c393aa21668d953"); // b
		    dom_par.push_back("03eea2bae7e1497842f2de7769cfe9c989c072ad696f48034a"); // G
		    dom_par.push_back("0xfffffffffffffffffffffffe5fb1a724dc80418648d8dd31"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.2.840.10045.3.1.2", dom_par);
		}

		{
		    /* prime192v3; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xfffffffffffffffffffffffffffffffeffffffffffffffff"); //p
		    dom_par.push_back("0xfffffffffffffffffffffffffffffffefffffffffffffffc"); // a
		    dom_par.push_back("0x22123dc2395a05caa7423daeccc94760a7d462256bd56916"); // b
		    dom_par.push_back("027d29778100c65a1da1783716588dce2b8b4aee8e228f1896"); // G
		    dom_par.push_back("0xffffffffffffffffffffffff7a62d031c83f4294f640ec13"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.2.840.10045.3.1.3", dom_par);
		}

		{
		    /* prime239v1; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0x7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff"); //p
		    dom_par.push_back("0x7ffFffffffffffffffffffff7fffffffffff8000000000007ffffffffffc"); // a
		    dom_par.push_back("0x6B016C3BDCF18941D0D654921475CA71A9DB2FB27D1D37796185C2942C0A"); // b
		    dom_par.push_back("020ffA963CDCA8816CCC33B8642BEDF905C3D358573D3F27FBBD3B3CB9AAAF"); // G
		    dom_par.push_back("0x7fffffffffffffffffffffff7fffff9e5e9a9f5d9071fbd1522688909d0b"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.2.840.10045.3.1.4", dom_par);
		}

		{
		    /* prime239v2; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0x7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff"); //p
		    dom_par.push_back("0x7ffFffffffffffffffffffff7ffFffffffff8000000000007ffFffffffFC"); // a
		    dom_par.push_back("0x617FAB6832576CBBFED50D99F0249C3FEE58B94BA0038C7AE84C8C832F2C"); // b
		    dom_par.push_back("0238AF09D98727705120C921BB5E9E26296A3CDCF2F35757A0EAFD87B830E7"); // G
		    dom_par.push_back("0x7fffffffffffffffffffffff800000CFA7E8594377D414C03821BC582063"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.2.840.10045.3.1.5", dom_par);
		}

		{
		    /* prime239v3; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0x7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff"); //p
		    dom_par.push_back("0x7ffFffffffffffffffffffff7ffFffffffff8000000000007ffFffffffFC"); // a
		    dom_par.push_back("0x255705FA2A306654B1F4CB03D6A750A30C250102D4988717D9BA15AB6D3E"); // b
		    dom_par.push_back("036768AE8E18BB92CFCF005C949AA2C6D94853D0E660BBF854B1C9505FE95A"); // G
		    dom_par.push_back("0x7fffffffffffffffffffffff7fffff975DEB41B3A6057C3C432146526551"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.2.840.10045.3.1.6", dom_par);
		}

		{
		    /* prime256v1; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"); //p
		    dom_par.push_back("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffFC"); // a
		    dom_par.push_back("0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"); // b
		    dom_par.push_back("036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"); // G
		    dom_par.push_back("0xffffffff00000000ffffffffffffffffBCE6FAADA7179E84F3B9CAC2FC632551"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.2.840.10045.3.1.7", dom_par);
		}

	    /* SEC2 */

		{
		    /* secp112r1; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xdb7c2abf62e35e668076bead208b"); //p
		    dom_par.push_back("0xDB7C2ABF62E35E668076BEAD2088"); // a
		    dom_par.push_back("0x659EF8BA043916EEDE8911702B22"); // b
		    dom_par.push_back("0409487239995A5EE76B55F9C2F098A89CE5AF8724C0A23E0E0ff77500"); // G
		    dom_par.push_back("0xDB7C2ABF62E35E7628DFAC6561C5"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.3.132.0.6", dom_par);
		}

		{
		    /* secp112r2; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xdb7c2abf62e35e668076bead208b"); //p
		    dom_par.push_back("0x6127C24C05F38A0AAAF65C0EF02C"); // a
		    dom_par.push_back("0x51DEF1815DB5ED74FCC34C85D709"); // b
		    dom_par.push_back("044BA30AB5E892B4E1649DD0928643ADCD46F5882E3747DEF36E956E97"); // G
		    dom_par.push_back("0x36DF0AAFD8B8D7597CA10520D04B"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.3.132.0.7", dom_par);
		}

		{
		    /* secp128r1; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xfffffffdffffffffffffffffffffffff"); //p
		    dom_par.push_back("0xffffffFDffffffffffffffffffffffFC"); // a
		    dom_par.push_back("0xE87579C11079F43DD824993C2CEE5ED3"); // b
		    dom_par.push_back("04161ff7528B899B2D0C28607CA52C5B86CF5AC8395BAFEB13C02DA292DDED7A83"); // G
		    dom_par.push_back("0xffffffFE0000000075A30D1B9038A115"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.3.132.0.28", dom_par);
		}

		{
		    /* secp128r2; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xfffffffdffffffffffffffffffffffff"); //p
		    dom_par.push_back("0xD6031998D1B3BBFEBF59CC9BBff9AEE1"); // a
		    dom_par.push_back("0x5EEEFCA380D02919DC2C6558BB6D8A5D"); // b
		    dom_par.push_back("047B6AA5D85E572983E6FB32A7CDEBC14027B6916A894D3AEE7106FE805FC34B44"); // G
		    dom_par.push_back("0x3ffffffF7ffffffFBE0024720613B5A3"); // order
		    dom_par.push_back("4");                                         // cofactor

		    config.set_ec_dompar("1.3.132.0.29", dom_par);
		}

		{
		    /* secp160k1; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xfffffffffffffffffffffffffffffffeffffac73"); //p
		    dom_par.push_back("0x0000000000000000000000000000000000000000"); // a
		    dom_par.push_back("0x0000000000000000000000000000000000000007"); // b
		    dom_par.push_back("043B4C382CE37AA192A4019E763036F4F5DD4D7EBB938CF935318FDCED6BC28286531733C3F03C4FEE"); // G
		    dom_par.push_back("0x0100000000000000000001B8FA16DFAB9ACA16B6B3"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.3.132.0.9", dom_par);
		}

		{
		    /* secp160r2; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xfffffffffffffffffffffffffffffffeffffac73"); //p
		    dom_par.push_back("0xffffffffffffffffffffffffffffffFEffffAC70"); // a
		    dom_par.push_back("0xB4E134D3FB59EB8BAB57274904664D5AF50388BA"); // b
		    dom_par.push_back("0452DCB034293A117E1F4ff11B30F7199D3144CE6DFEAffEF2E331F296E071FA0DF9982CFEA7D43F2E"); // G
		    dom_par.push_back("0x0100000000000000000000351EE786A818F3A1A16B"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.3.132.0.30", dom_par);
		}

		{
		    /* secp192k1; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xfffffffffffffffffffffffffffffffffffffffeffffee37"); //p
		    dom_par.push_back("0x000000000000000000000000000000000000000000000000"); // a
		    dom_par.push_back("0x000000000000000000000000000000000000000000000003"); // b
		    dom_par.push_back("04DB4ff10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D"); // G
		    dom_par.push_back("0xffffffffffffffffffffffFE26F2FC170F69466A74DEFD8D"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.3.132.0.31", dom_par);
		}

		{
		    /* secp224k1; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xfffffffffffffffffffffffffffffffffffffffffffffffeffffe56d"); //p
		    dom_par.push_back("0x00000000000000000000000000000000000000000000000000000000"); // a
		    dom_par.push_back("0x00000000000000000000000000000000000000000000000000000005"); // b
		    dom_par.push_back("04A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5"); // G
		    dom_par.push_back("0x010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.3.132.0.32", dom_par);
		}

		{
		    /* secp224r1; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xffffffffffffffffffffffffffffffff000000000000000000000001"); //p
		    dom_par.push_back("0xffffffffffffffffffffffffffffffFEffffffffffffffffffffffFE"); // a
		    dom_par.push_back("0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355ffB4"); // b
		    dom_par.push_back("04B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34"); // G
		    dom_par.push_back("0xffffffffffffffffffffffffffff16A2E0B8F03E13DD29455C5C2A3D"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.3.132.0.33", dom_par);
		}

		{
		    /* secp256k1; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"); //p
		    dom_par.push_back("0x0000000000000000000000000000000000000000000000000000000000000000"); // a
		    dom_par.push_back("0x0000000000000000000000000000000000000000000000000000000000000007"); // b
		    dom_par.push_back("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"); // G
		    dom_par.push_back("0xffffffffffffffffffffffffffffffFEBAAEDCE6AF48A03BBFD25E8CD0364141"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.3.132.0.10", dom_par);
		}

		{
		    /* secp384r1; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"); //p
		    dom_par.push_back("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFEffffffff0000000000000000ffffffFC"); // a
		    dom_par.push_back("0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF"); // b
		    dom_par.push_back("04AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB73617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"); // G
		    dom_par.push_back("0xffffffffffffffffffffffffffffffffffffffffffffffffC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.3.132.0.34", dom_par);
		}

		{
		    /* secp521r1; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); //p
		    dom_par.push_back("0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFC"); // a
		    dom_par.push_back("0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00"); // b
		    dom_par.push_back("0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2ffA8DE3348B3C1856A429BF97E7E31C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"); // G
		    dom_par.push_back("0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.3.132.0.35", dom_par);
		}

		/* NIS */

		{
		    /* NIST curve P-521; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); //p
		    dom_par.push_back("0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFC"); // a
		    dom_par.push_back("0x051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00"); // b
		    dom_par.push_back("0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2ffA8DE3348B3C1856A429BF97E7E31C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"); // G
		    dom_par.push_back("0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.3.6.1.4.1.8301.3.1.2.9.0.38", dom_par);
		}

		/* BrainPool */

		{
		    /* brainpoolP160r1; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xE95E4A5F737059DC60DFC7AD95B3D8139515620F"); //p
		    dom_par.push_back("0x340E7BE2A280EB74E2BE61BADA745D97E8F7C300"); // a
		    dom_par.push_back("0x1E589A8595423412134FAA2DBDEC95C8D8675E58"); // b
		    dom_par.push_back("04BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC31667CB477A1A8EC338F94741669C976316DA6321"); // G
		    dom_par.push_back("0xE95E4A5F737059DC60DF5991D45029409E60FC09"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.3.36.3.3.2.8.1.1.1", dom_par);
		}

		{
		    /* brainpoolP192r1; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xC302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297"); //p
		    dom_par.push_back("0x6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF"); // a
		    dom_par.push_back("0x469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9"); // b
		    dom_par.push_back("04C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD614B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F"); // G
		    dom_par.push_back("0xC302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.3.36.3.3.2.8.1.1.3", dom_par);
		}

		{
		    /* brainpoolP224r1; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xD7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF"); //p
		    dom_par.push_back("0x68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43"); // a
		    dom_par.push_back("0x2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B"); // b
		    dom_par.push_back("040D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD"); // G
		    dom_par.push_back("0xD7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.3.36.3.3.2.8.1.1.5", dom_par);
		}

		{
		    /* brainpoolP256r1; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377"); //p
		    dom_par.push_back("0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9"); // a
		    dom_par.push_back("0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6"); // b
		    dom_par.push_back("048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997"); // G
		    dom_par.push_back("0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.3.36.3.3.2.8.1.1.7", dom_par);
		}

		{
		    /* brainpoolP320r1; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xD35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27"); //p
		    dom_par.push_back("0x3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4"); // a
		    dom_par.push_back("0x520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6"); // b
		    dom_par.push_back("0443BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E2061114FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1"); // G
		    dom_par.push_back("0xD35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.3.36.3.3.2.8.1.1.9", dom_par);
		}

		{
		    /* brainpoolP384r1; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53"); //p
		    dom_par.push_back("0x7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826"); // a
		    dom_par.push_back("0x4A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11"); // b
		    dom_par.push_back("041D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315"); // G
		    dom_par.push_back("0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.3.36.3.3.2.8.1.1.11", dom_par);
		}

		{
		    /* brainpoolP512r1; source:
		       Flexiprovider */
			std::vector<std::string> dom_par;
		    dom_par.push_back("0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3"); //p
		    dom_par.push_back("0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA"); // a
		    dom_par.push_back("0x3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723"); // b
		    dom_par.push_back("0481AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F8227DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892"); // G
		    dom_par.push_back("0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069"); // order
		    dom_par.push_back("1");                                         // cofactor

		    config.set_ec_dompar("1.3.36.3.3.2.8.1.1.13", dom_par);
		}
	}
}
/*************************************************
* Set the default policy                         *
*************************************************/
void Config::load_defaults()
   {
   set_default_config(*this);
   set_default_aliases(*this);
   set_default_oids(*this);
   set_default_dl_groups(*this);
   set_default_ec_dompar(*this);

   }

}
