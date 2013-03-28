/*
* List of TLS cipher suites
*
* This file was automatically generated from the IANA assignments
* by ./src/build-data/scripts/tls_suite_info.py
*
* Released under the terms of the Botan license
*/

#include <botan/tls_ciphersuite.h>

namespace Botan {

namespace TLS {

Ciphersuite Ciphersuite::by_id(u16bit suite)
   {

   switch(suite)
      {

      case 0x0013: // DHE_DSS_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0x0013, "DSA", "DH", "SHA-1", "3DES", 24);

      case 0x0032: // DHE_DSS_WITH_AES_128_CBC_SHA
         return Ciphersuite(0x0032, "DSA", "DH", "SHA-1", "AES-128", 16);

      case 0x0040: // DHE_DSS_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0x0040, "DSA", "DH", "SHA-256", "AES-128", 16);

      case 0x0038: // DHE_DSS_WITH_AES_256_CBC_SHA
         return Ciphersuite(0x0038, "DSA", "DH", "SHA-1", "AES-256", 32);

      case 0x006A: // DHE_DSS_WITH_AES_256_CBC_SHA256
         return Ciphersuite(0x006A, "DSA", "DH", "SHA-256", "AES-256", 32);

      case 0x0044: // DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
         return Ciphersuite(0x0044, "DSA", "DH", "SHA-1", "Camellia-128", 16);

      case 0x00BD: // DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0x00BD, "DSA", "DH", "SHA-256", "Camellia-128", 16);

      case 0x0087: // DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
         return Ciphersuite(0x0087, "DSA", "DH", "SHA-1", "Camellia-256", 32);

      case 0x00C3: // DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256
         return Ciphersuite(0x00C3, "DSA", "DH", "SHA-256", "Camellia-256", 32);

      case 0x0066: // DHE_DSS_WITH_RC4_128_SHA
         return Ciphersuite(0x0066, "DSA", "DH", "SHA-1", "ARC4", 16);

      case 0x0099: // DHE_DSS_WITH_SEED_CBC_SHA
         return Ciphersuite(0x0099, "DSA", "DH", "SHA-1", "SEED", 16);

      case 0x008F: // DHE_PSK_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0x008F, "", "DHE_PSK", "SHA-1", "3DES", 24);

      case 0x0090: // DHE_PSK_WITH_AES_128_CBC_SHA
         return Ciphersuite(0x0090, "", "DHE_PSK", "SHA-1", "AES-128", 16);

      case 0x00B2: // DHE_PSK_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0x00B2, "", "DHE_PSK", "SHA-256", "AES-128", 16);

      case 0x0091: // DHE_PSK_WITH_AES_256_CBC_SHA
         return Ciphersuite(0x0091, "", "DHE_PSK", "SHA-1", "AES-256", 32);

      case 0x00B3: // DHE_PSK_WITH_AES_256_CBC_SHA384
         return Ciphersuite(0x00B3, "", "DHE_PSK", "SHA-384", "AES-256", 32);

      case 0xC096: // DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0xC096, "", "DHE_PSK", "SHA-256", "Camellia-128", 16);

      case 0xC097: // DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
         return Ciphersuite(0xC097, "", "DHE_PSK", "SHA-384", "Camellia-256", 32);

      case 0x008E: // DHE_PSK_WITH_RC4_128_SHA
         return Ciphersuite(0x008E, "", "DHE_PSK", "SHA-1", "ARC4", 16);

      case 0x0016: // DHE_RSA_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0x0016, "RSA", "DH", "SHA-1", "3DES", 24);

      case 0x0033: // DHE_RSA_WITH_AES_128_CBC_SHA
         return Ciphersuite(0x0033, "RSA", "DH", "SHA-1", "AES-128", 16);

      case 0x0067: // DHE_RSA_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0x0067, "RSA", "DH", "SHA-256", "AES-128", 16);

      case 0x0039: // DHE_RSA_WITH_AES_256_CBC_SHA
         return Ciphersuite(0x0039, "RSA", "DH", "SHA-1", "AES-256", 32);

      case 0x006B: // DHE_RSA_WITH_AES_256_CBC_SHA256
         return Ciphersuite(0x006B, "RSA", "DH", "SHA-256", "AES-256", 32);

      case 0x0045: // DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
         return Ciphersuite(0x0045, "RSA", "DH", "SHA-1", "Camellia-128", 16);

      case 0x00BE: // DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0x00BE, "RSA", "DH", "SHA-256", "Camellia-128", 16);

      case 0x0088: // DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
         return Ciphersuite(0x0088, "RSA", "DH", "SHA-1", "Camellia-256", 32);

      case 0x00C4: // DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
         return Ciphersuite(0x00C4, "RSA", "DH", "SHA-256", "Camellia-256", 32);

      case 0x009A: // DHE_RSA_WITH_SEED_CBC_SHA
         return Ciphersuite(0x009A, "RSA", "DH", "SHA-1", "SEED", 16);

      case 0x001B: // DH_anon_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0x001B, "", "DH", "SHA-1", "3DES", 24);

      case 0x0034: // DH_anon_WITH_AES_128_CBC_SHA
         return Ciphersuite(0x0034, "", "DH", "SHA-1", "AES-128", 16);

      case 0x006C: // DH_anon_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0x006C, "", "DH", "SHA-256", "AES-128", 16);

      case 0x003A: // DH_anon_WITH_AES_256_CBC_SHA
         return Ciphersuite(0x003A, "", "DH", "SHA-1", "AES-256", 32);

      case 0x006D: // DH_anon_WITH_AES_256_CBC_SHA256
         return Ciphersuite(0x006D, "", "DH", "SHA-256", "AES-256", 32);

      case 0x0046: // DH_anon_WITH_CAMELLIA_128_CBC_SHA
         return Ciphersuite(0x0046, "", "DH", "SHA-1", "Camellia-128", 16);

      case 0x00BF: // DH_anon_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0x00BF, "", "DH", "SHA-256", "Camellia-128", 16);

      case 0x0089: // DH_anon_WITH_CAMELLIA_256_CBC_SHA
         return Ciphersuite(0x0089, "", "DH", "SHA-1", "Camellia-256", 32);

      case 0x00C5: // DH_anon_WITH_CAMELLIA_256_CBC_SHA256
         return Ciphersuite(0x00C5, "", "DH", "SHA-256", "Camellia-256", 32);

      case 0x0018: // DH_anon_WITH_RC4_128_MD5
         return Ciphersuite(0x0018, "", "DH", "MD5", "ARC4", 16);

      case 0x009B: // DH_anon_WITH_SEED_CBC_SHA
         return Ciphersuite(0x009B, "", "DH", "SHA-1", "SEED", 16);

      case 0xC008: // ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0xC008, "ECDSA", "ECDH", "SHA-1", "3DES", 24);

      case 0xC009: // ECDHE_ECDSA_WITH_AES_128_CBC_SHA
         return Ciphersuite(0xC009, "ECDSA", "ECDH", "SHA-1", "AES-128", 16);

      case 0xC023: // ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0xC023, "ECDSA", "ECDH", "SHA-256", "AES-128", 16);

      case 0xC00A: // ECDHE_ECDSA_WITH_AES_256_CBC_SHA
         return Ciphersuite(0xC00A, "ECDSA", "ECDH", "SHA-1", "AES-256", 32);

      case 0xC024: // ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
         return Ciphersuite(0xC024, "ECDSA", "ECDH", "SHA-384", "AES-256", 32);

      case 0xC072: // ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0xC072, "ECDSA", "ECDH", "SHA-256", "Camellia-128", 16);

      case 0xC073: // ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
         return Ciphersuite(0xC073, "ECDSA", "ECDH", "SHA-384", "Camellia-256", 32);

      case 0xC007: // ECDHE_ECDSA_WITH_RC4_128_SHA
         return Ciphersuite(0xC007, "ECDSA", "ECDH", "SHA-1", "ARC4", 16);

      case 0xC034: // ECDHE_PSK_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0xC034, "", "ECDHE_PSK", "SHA-1", "3DES", 24);

      case 0xC035: // ECDHE_PSK_WITH_AES_128_CBC_SHA
         return Ciphersuite(0xC035, "", "ECDHE_PSK", "SHA-1", "AES-128", 16);

      case 0xC037: // ECDHE_PSK_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0xC037, "", "ECDHE_PSK", "SHA-256", "AES-128", 16);

      case 0xC036: // ECDHE_PSK_WITH_AES_256_CBC_SHA
         return Ciphersuite(0xC036, "", "ECDHE_PSK", "SHA-1", "AES-256", 32);

      case 0xC038: // ECDHE_PSK_WITH_AES_256_CBC_SHA384
         return Ciphersuite(0xC038, "", "ECDHE_PSK", "SHA-384", "AES-256", 32);

      case 0xC09A: // ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0xC09A, "", "ECDHE_PSK", "SHA-256", "Camellia-128", 16);

      case 0xC09B: // ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
         return Ciphersuite(0xC09B, "", "ECDHE_PSK", "SHA-384", "Camellia-256", 32);

      case 0xC033: // ECDHE_PSK_WITH_RC4_128_SHA
         return Ciphersuite(0xC033, "", "ECDHE_PSK", "SHA-1", "ARC4", 16);

      case 0xC012: // ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0xC012, "RSA", "ECDH", "SHA-1", "3DES", 24);

      case 0xC013: // ECDHE_RSA_WITH_AES_128_CBC_SHA
         return Ciphersuite(0xC013, "RSA", "ECDH", "SHA-1", "AES-128", 16);

      case 0xC027: // ECDHE_RSA_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0xC027, "RSA", "ECDH", "SHA-256", "AES-128", 16);

      case 0xC014: // ECDHE_RSA_WITH_AES_256_CBC_SHA
         return Ciphersuite(0xC014, "RSA", "ECDH", "SHA-1", "AES-256", 32);

      case 0xC028: // ECDHE_RSA_WITH_AES_256_CBC_SHA384
         return Ciphersuite(0xC028, "RSA", "ECDH", "SHA-384", "AES-256", 32);

      case 0xC076: // ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0xC076, "RSA", "ECDH", "SHA-256", "Camellia-128", 16);

      case 0xC077: // ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
         return Ciphersuite(0xC077, "RSA", "ECDH", "SHA-384", "Camellia-256", 32);

      case 0xC011: // ECDHE_RSA_WITH_RC4_128_SHA
         return Ciphersuite(0xC011, "RSA", "ECDH", "SHA-1", "ARC4", 16);

      case 0xC017: // ECDH_anon_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0xC017, "", "ECDH", "SHA-1", "3DES", 24);

      case 0xC018: // ECDH_anon_WITH_AES_128_CBC_SHA
         return Ciphersuite(0xC018, "", "ECDH", "SHA-1", "AES-128", 16);

      case 0xC019: // ECDH_anon_WITH_AES_256_CBC_SHA
         return Ciphersuite(0xC019, "", "ECDH", "SHA-1", "AES-256", 32);

      case 0xC016: // ECDH_anon_WITH_RC4_128_SHA
         return Ciphersuite(0xC016, "", "ECDH", "SHA-1", "ARC4", 16);

      case 0x008B: // PSK_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0x008B, "", "PSK", "SHA-1", "3DES", 24);

      case 0x008C: // PSK_WITH_AES_128_CBC_SHA
         return Ciphersuite(0x008C, "", "PSK", "SHA-1", "AES-128", 16);

      case 0x00AE: // PSK_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0x00AE, "", "PSK", "SHA-256", "AES-128", 16);

      case 0x008D: // PSK_WITH_AES_256_CBC_SHA
         return Ciphersuite(0x008D, "", "PSK", "SHA-1", "AES-256", 32);

      case 0x00AF: // PSK_WITH_AES_256_CBC_SHA384
         return Ciphersuite(0x00AF, "", "PSK", "SHA-384", "AES-256", 32);

      case 0xC094: // PSK_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0xC094, "", "PSK", "SHA-256", "Camellia-128", 16);

      case 0xC095: // PSK_WITH_CAMELLIA_256_CBC_SHA384
         return Ciphersuite(0xC095, "", "PSK", "SHA-384", "Camellia-256", 32);

      case 0x008A: // PSK_WITH_RC4_128_SHA
         return Ciphersuite(0x008A, "", "PSK", "SHA-1", "ARC4", 16);

      case 0x000A: // RSA_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0x000A, "RSA", "RSA", "SHA-1", "3DES", 24);

      case 0x002F: // RSA_WITH_AES_128_CBC_SHA
         return Ciphersuite(0x002F, "RSA", "RSA", "SHA-1", "AES-128", 16);

      case 0x003C: // RSA_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0x003C, "RSA", "RSA", "SHA-256", "AES-128", 16);

      case 0x0035: // RSA_WITH_AES_256_CBC_SHA
         return Ciphersuite(0x0035, "RSA", "RSA", "SHA-1", "AES-256", 32);

      case 0x003D: // RSA_WITH_AES_256_CBC_SHA256
         return Ciphersuite(0x003D, "RSA", "RSA", "SHA-256", "AES-256", 32);

      case 0x0041: // RSA_WITH_CAMELLIA_128_CBC_SHA
         return Ciphersuite(0x0041, "RSA", "RSA", "SHA-1", "Camellia-128", 16);

      case 0x00BA: // RSA_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0x00BA, "RSA", "RSA", "SHA-256", "Camellia-128", 16);

      case 0x0084: // RSA_WITH_CAMELLIA_256_CBC_SHA
         return Ciphersuite(0x0084, "RSA", "RSA", "SHA-1", "Camellia-256", 32);

      case 0x00C0: // RSA_WITH_CAMELLIA_256_CBC_SHA256
         return Ciphersuite(0x00C0, "RSA", "RSA", "SHA-256", "Camellia-256", 32);

      case 0x0004: // RSA_WITH_RC4_128_MD5
         return Ciphersuite(0x0004, "RSA", "RSA", "MD5", "ARC4", 16);

      case 0x0005: // RSA_WITH_RC4_128_SHA
         return Ciphersuite(0x0005, "RSA", "RSA", "SHA-1", "ARC4", 16);

      case 0x0096: // RSA_WITH_SEED_CBC_SHA
         return Ciphersuite(0x0096, "RSA", "RSA", "SHA-1", "SEED", 16);

      case 0xC01C: // SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0xC01C, "DSA", "SRP_SHA", "SHA-1", "3DES", 24);

      case 0xC01F: // SRP_SHA_DSS_WITH_AES_128_CBC_SHA
         return Ciphersuite(0xC01F, "DSA", "SRP_SHA", "SHA-1", "AES-128", 16);

      case 0xC022: // SRP_SHA_DSS_WITH_AES_256_CBC_SHA
         return Ciphersuite(0xC022, "DSA", "SRP_SHA", "SHA-1", "AES-256", 32);

      case 0xC01B: // SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0xC01B, "RSA", "SRP_SHA", "SHA-1", "3DES", 24);

      case 0xC01E: // SRP_SHA_RSA_WITH_AES_128_CBC_SHA
         return Ciphersuite(0xC01E, "RSA", "SRP_SHA", "SHA-1", "AES-128", 16);

      case 0xC021: // SRP_SHA_RSA_WITH_AES_256_CBC_SHA
         return Ciphersuite(0xC021, "RSA", "SRP_SHA", "SHA-1", "AES-256", 32);

      case 0xC01A: // SRP_SHA_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0xC01A, "", "SRP_SHA", "SHA-1", "3DES", 24);

      case 0xC01D: // SRP_SHA_WITH_AES_128_CBC_SHA
         return Ciphersuite(0xC01D, "", "SRP_SHA", "SHA-1", "AES-128", 16);

      case 0xC020: // SRP_SHA_WITH_AES_256_CBC_SHA
         return Ciphersuite(0xC020, "", "SRP_SHA", "SHA-1", "AES-256", 32);

      }

   return Ciphersuite(); // some unknown ciphersuite
   }

}

}
