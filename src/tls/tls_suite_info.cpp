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
         return Ciphersuite(0x0013, "DSA", "DH", "3DES", 24, 8, "SHA-1", 20);

      case 0x0032: // DHE_DSS_WITH_AES_128_CBC_SHA
         return Ciphersuite(0x0032, "DSA", "DH", "AES-128", 16, 16, "SHA-1", 20);

      case 0x0040: // DHE_DSS_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0x0040, "DSA", "DH", "AES-128", 16, 16, "SHA-256", 32);

      case 0x0038: // DHE_DSS_WITH_AES_256_CBC_SHA
         return Ciphersuite(0x0038, "DSA", "DH", "AES-256", 32, 16, "SHA-1", 20);

      case 0x006A: // DHE_DSS_WITH_AES_256_CBC_SHA256
         return Ciphersuite(0x006A, "DSA", "DH", "AES-256", 32, 16, "SHA-256", 32);

      case 0x0044: // DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
         return Ciphersuite(0x0044, "DSA", "DH", "Camellia-128", 16, 16, "SHA-1", 20);

      case 0x00BD: // DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0x00BD, "DSA", "DH", "Camellia-128", 16, 16, "SHA-256", 32);

      case 0x0087: // DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
         return Ciphersuite(0x0087, "DSA", "DH", "Camellia-256", 32, 16, "SHA-1", 20);

      case 0x00C3: // DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256
         return Ciphersuite(0x00C3, "DSA", "DH", "Camellia-256", 32, 16, "SHA-256", 32);

      case 0x0066: // DHE_DSS_WITH_RC4_128_SHA
         return Ciphersuite(0x0066, "DSA", "DH", "ARC4", 16, 0, "SHA-1", 20);

      case 0x0099: // DHE_DSS_WITH_SEED_CBC_SHA
         return Ciphersuite(0x0099, "DSA", "DH", "SEED", 16, 16, "SHA-1", 20);

      case 0x008F: // DHE_PSK_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0x008F, "", "DHE_PSK", "3DES", 24, 8, "SHA-1", 20);

      case 0x0090: // DHE_PSK_WITH_AES_128_CBC_SHA
         return Ciphersuite(0x0090, "", "DHE_PSK", "AES-128", 16, 16, "SHA-1", 20);

      case 0x00B2: // DHE_PSK_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0x00B2, "", "DHE_PSK", "AES-128", 16, 16, "SHA-256", 32);

      case 0x0091: // DHE_PSK_WITH_AES_256_CBC_SHA
         return Ciphersuite(0x0091, "", "DHE_PSK", "AES-256", 32, 16, "SHA-1", 20);

      case 0x00B3: // DHE_PSK_WITH_AES_256_CBC_SHA384
         return Ciphersuite(0x00B3, "", "DHE_PSK", "AES-256", 32, 16, "SHA-384", 48);

      case 0xC096: // DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0xC096, "", "DHE_PSK", "Camellia-128", 16, 16, "SHA-256", 32);

      case 0xC097: // DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
         return Ciphersuite(0xC097, "", "DHE_PSK", "Camellia-256", 32, 16, "SHA-384", 48);

      case 0x008E: // DHE_PSK_WITH_RC4_128_SHA
         return Ciphersuite(0x008E, "", "DHE_PSK", "ARC4", 16, 0, "SHA-1", 20);

      case 0x0016: // DHE_RSA_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0x0016, "RSA", "DH", "3DES", 24, 8, "SHA-1", 20);

      case 0x0033: // DHE_RSA_WITH_AES_128_CBC_SHA
         return Ciphersuite(0x0033, "RSA", "DH", "AES-128", 16, 16, "SHA-1", 20);

      case 0x0067: // DHE_RSA_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0x0067, "RSA", "DH", "AES-128", 16, 16, "SHA-256", 32);

      case 0x0039: // DHE_RSA_WITH_AES_256_CBC_SHA
         return Ciphersuite(0x0039, "RSA", "DH", "AES-256", 32, 16, "SHA-1", 20);

      case 0x006B: // DHE_RSA_WITH_AES_256_CBC_SHA256
         return Ciphersuite(0x006B, "RSA", "DH", "AES-256", 32, 16, "SHA-256", 32);

      case 0x0045: // DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
         return Ciphersuite(0x0045, "RSA", "DH", "Camellia-128", 16, 16, "SHA-1", 20);

      case 0x00BE: // DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0x00BE, "RSA", "DH", "Camellia-128", 16, 16, "SHA-256", 32);

      case 0x0088: // DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
         return Ciphersuite(0x0088, "RSA", "DH", "Camellia-256", 32, 16, "SHA-1", 20);

      case 0x00C4: // DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
         return Ciphersuite(0x00C4, "RSA", "DH", "Camellia-256", 32, 16, "SHA-256", 32);

      case 0x009A: // DHE_RSA_WITH_SEED_CBC_SHA
         return Ciphersuite(0x009A, "RSA", "DH", "SEED", 16, 16, "SHA-1", 20);

      case 0x001B: // DH_anon_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0x001B, "", "DH", "3DES", 24, 8, "SHA-1", 20);

      case 0x0034: // DH_anon_WITH_AES_128_CBC_SHA
         return Ciphersuite(0x0034, "", "DH", "AES-128", 16, 16, "SHA-1", 20);

      case 0x006C: // DH_anon_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0x006C, "", "DH", "AES-128", 16, 16, "SHA-256", 32);

      case 0x003A: // DH_anon_WITH_AES_256_CBC_SHA
         return Ciphersuite(0x003A, "", "DH", "AES-256", 32, 16, "SHA-1", 20);

      case 0x006D: // DH_anon_WITH_AES_256_CBC_SHA256
         return Ciphersuite(0x006D, "", "DH", "AES-256", 32, 16, "SHA-256", 32);

      case 0x0046: // DH_anon_WITH_CAMELLIA_128_CBC_SHA
         return Ciphersuite(0x0046, "", "DH", "Camellia-128", 16, 16, "SHA-1", 20);

      case 0x00BF: // DH_anon_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0x00BF, "", "DH", "Camellia-128", 16, 16, "SHA-256", 32);

      case 0x0089: // DH_anon_WITH_CAMELLIA_256_CBC_SHA
         return Ciphersuite(0x0089, "", "DH", "Camellia-256", 32, 16, "SHA-1", 20);

      case 0x00C5: // DH_anon_WITH_CAMELLIA_256_CBC_SHA256
         return Ciphersuite(0x00C5, "", "DH", "Camellia-256", 32, 16, "SHA-256", 32);

      case 0x0018: // DH_anon_WITH_RC4_128_MD5
         return Ciphersuite(0x0018, "", "DH", "ARC4", 16, 0, "MD5", 16);

      case 0x009B: // DH_anon_WITH_SEED_CBC_SHA
         return Ciphersuite(0x009B, "", "DH", "SEED", 16, 16, "SHA-1", 20);

      case 0xC008: // ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0xC008, "ECDSA", "ECDH", "3DES", 24, 8, "SHA-1", 20);

      case 0xC009: // ECDHE_ECDSA_WITH_AES_128_CBC_SHA
         return Ciphersuite(0xC009, "ECDSA", "ECDH", "AES-128", 16, 16, "SHA-1", 20);

      case 0xC023: // ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0xC023, "ECDSA", "ECDH", "AES-128", 16, 16, "SHA-256", 32);

      case 0xC00A: // ECDHE_ECDSA_WITH_AES_256_CBC_SHA
         return Ciphersuite(0xC00A, "ECDSA", "ECDH", "AES-256", 32, 16, "SHA-1", 20);

      case 0xC024: // ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
         return Ciphersuite(0xC024, "ECDSA", "ECDH", "AES-256", 32, 16, "SHA-384", 48);

      case 0xC072: // ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0xC072, "ECDSA", "ECDH", "Camellia-128", 16, 16, "SHA-256", 32);

      case 0xC073: // ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
         return Ciphersuite(0xC073, "ECDSA", "ECDH", "Camellia-256", 32, 16, "SHA-384", 48);

      case 0xC007: // ECDHE_ECDSA_WITH_RC4_128_SHA
         return Ciphersuite(0xC007, "ECDSA", "ECDH", "ARC4", 16, 0, "SHA-1", 20);

      case 0xC034: // ECDHE_PSK_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0xC034, "", "ECDHE_PSK", "3DES", 24, 8, "SHA-1", 20);

      case 0xC035: // ECDHE_PSK_WITH_AES_128_CBC_SHA
         return Ciphersuite(0xC035, "", "ECDHE_PSK", "AES-128", 16, 16, "SHA-1", 20);

      case 0xC037: // ECDHE_PSK_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0xC037, "", "ECDHE_PSK", "AES-128", 16, 16, "SHA-256", 32);

      case 0xC036: // ECDHE_PSK_WITH_AES_256_CBC_SHA
         return Ciphersuite(0xC036, "", "ECDHE_PSK", "AES-256", 32, 16, "SHA-1", 20);

      case 0xC038: // ECDHE_PSK_WITH_AES_256_CBC_SHA384
         return Ciphersuite(0xC038, "", "ECDHE_PSK", "AES-256", 32, 16, "SHA-384", 48);

      case 0xC09A: // ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0xC09A, "", "ECDHE_PSK", "Camellia-128", 16, 16, "SHA-256", 32);

      case 0xC09B: // ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
         return Ciphersuite(0xC09B, "", "ECDHE_PSK", "Camellia-256", 32, 16, "SHA-384", 48);

      case 0xC033: // ECDHE_PSK_WITH_RC4_128_SHA
         return Ciphersuite(0xC033, "", "ECDHE_PSK", "ARC4", 16, 0, "SHA-1", 20);

      case 0xC012: // ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0xC012, "RSA", "ECDH", "3DES", 24, 8, "SHA-1", 20);

      case 0xC013: // ECDHE_RSA_WITH_AES_128_CBC_SHA
         return Ciphersuite(0xC013, "RSA", "ECDH", "AES-128", 16, 16, "SHA-1", 20);

      case 0xC027: // ECDHE_RSA_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0xC027, "RSA", "ECDH", "AES-128", 16, 16, "SHA-256", 32);

      case 0xC014: // ECDHE_RSA_WITH_AES_256_CBC_SHA
         return Ciphersuite(0xC014, "RSA", "ECDH", "AES-256", 32, 16, "SHA-1", 20);

      case 0xC028: // ECDHE_RSA_WITH_AES_256_CBC_SHA384
         return Ciphersuite(0xC028, "RSA", "ECDH", "AES-256", 32, 16, "SHA-384", 48);

      case 0xC076: // ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0xC076, "RSA", "ECDH", "Camellia-128", 16, 16, "SHA-256", 32);

      case 0xC077: // ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
         return Ciphersuite(0xC077, "RSA", "ECDH", "Camellia-256", 32, 16, "SHA-384", 48);

      case 0xC011: // ECDHE_RSA_WITH_RC4_128_SHA
         return Ciphersuite(0xC011, "RSA", "ECDH", "ARC4", 16, 0, "SHA-1", 20);

      case 0xC017: // ECDH_anon_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0xC017, "", "ECDH", "3DES", 24, 8, "SHA-1", 20);

      case 0xC018: // ECDH_anon_WITH_AES_128_CBC_SHA
         return Ciphersuite(0xC018, "", "ECDH", "AES-128", 16, 16, "SHA-1", 20);

      case 0xC019: // ECDH_anon_WITH_AES_256_CBC_SHA
         return Ciphersuite(0xC019, "", "ECDH", "AES-256", 32, 16, "SHA-1", 20);

      case 0xC016: // ECDH_anon_WITH_RC4_128_SHA
         return Ciphersuite(0xC016, "", "ECDH", "ARC4", 16, 0, "SHA-1", 20);

      case 0x008B: // PSK_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0x008B, "", "PSK", "3DES", 24, 8, "SHA-1", 20);

      case 0x008C: // PSK_WITH_AES_128_CBC_SHA
         return Ciphersuite(0x008C, "", "PSK", "AES-128", 16, 16, "SHA-1", 20);

      case 0x00AE: // PSK_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0x00AE, "", "PSK", "AES-128", 16, 16, "SHA-256", 32);

      case 0x008D: // PSK_WITH_AES_256_CBC_SHA
         return Ciphersuite(0x008D, "", "PSK", "AES-256", 32, 16, "SHA-1", 20);

      case 0x00AF: // PSK_WITH_AES_256_CBC_SHA384
         return Ciphersuite(0x00AF, "", "PSK", "AES-256", 32, 16, "SHA-384", 48);

      case 0xC094: // PSK_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0xC094, "", "PSK", "Camellia-128", 16, 16, "SHA-256", 32);

      case 0xC095: // PSK_WITH_CAMELLIA_256_CBC_SHA384
         return Ciphersuite(0xC095, "", "PSK", "Camellia-256", 32, 16, "SHA-384", 48);

      case 0x008A: // PSK_WITH_RC4_128_SHA
         return Ciphersuite(0x008A, "", "PSK", "ARC4", 16, 0, "SHA-1", 20);

      case 0x000A: // RSA_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0x000A, "RSA", "RSA", "3DES", 24, 8, "SHA-1", 20);

      case 0x002F: // RSA_WITH_AES_128_CBC_SHA
         return Ciphersuite(0x002F, "RSA", "RSA", "AES-128", 16, 16, "SHA-1", 20);

      case 0x003C: // RSA_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0x003C, "RSA", "RSA", "AES-128", 16, 16, "SHA-256", 32);

      case 0x0035: // RSA_WITH_AES_256_CBC_SHA
         return Ciphersuite(0x0035, "RSA", "RSA", "AES-256", 32, 16, "SHA-1", 20);

      case 0x003D: // RSA_WITH_AES_256_CBC_SHA256
         return Ciphersuite(0x003D, "RSA", "RSA", "AES-256", 32, 16, "SHA-256", 32);

      case 0x0041: // RSA_WITH_CAMELLIA_128_CBC_SHA
         return Ciphersuite(0x0041, "RSA", "RSA", "Camellia-128", 16, 16, "SHA-1", 20);

      case 0x00BA: // RSA_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0x00BA, "RSA", "RSA", "Camellia-128", 16, 16, "SHA-256", 32);

      case 0x0084: // RSA_WITH_CAMELLIA_256_CBC_SHA
         return Ciphersuite(0x0084, "RSA", "RSA", "Camellia-256", 32, 16, "SHA-1", 20);

      case 0x00C0: // RSA_WITH_CAMELLIA_256_CBC_SHA256
         return Ciphersuite(0x00C0, "RSA", "RSA", "Camellia-256", 32, 16, "SHA-256", 32);

      case 0x0004: // RSA_WITH_RC4_128_MD5
         return Ciphersuite(0x0004, "RSA", "RSA", "ARC4", 16, 0, "MD5", 16);

      case 0x0005: // RSA_WITH_RC4_128_SHA
         return Ciphersuite(0x0005, "RSA", "RSA", "ARC4", 16, 0, "SHA-1", 20);

      case 0x0096: // RSA_WITH_SEED_CBC_SHA
         return Ciphersuite(0x0096, "RSA", "RSA", "SEED", 16, 16, "SHA-1", 20);

      case 0xC01C: // SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0xC01C, "DSA", "SRP_SHA", "3DES", 24, 8, "SHA-1", 20);

      case 0xC01F: // SRP_SHA_DSS_WITH_AES_128_CBC_SHA
         return Ciphersuite(0xC01F, "DSA", "SRP_SHA", "AES-128", 16, 16, "SHA-1", 20);

      case 0xC022: // SRP_SHA_DSS_WITH_AES_256_CBC_SHA
         return Ciphersuite(0xC022, "DSA", "SRP_SHA", "AES-256", 32, 16, "SHA-1", 20);

      case 0xC01B: // SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0xC01B, "RSA", "SRP_SHA", "3DES", 24, 8, "SHA-1", 20);

      case 0xC01E: // SRP_SHA_RSA_WITH_AES_128_CBC_SHA
         return Ciphersuite(0xC01E, "RSA", "SRP_SHA", "AES-128", 16, 16, "SHA-1", 20);

      case 0xC021: // SRP_SHA_RSA_WITH_AES_256_CBC_SHA
         return Ciphersuite(0xC021, "RSA", "SRP_SHA", "AES-256", 32, 16, "SHA-1", 20);

      case 0xC01A: // SRP_SHA_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0xC01A, "", "SRP_SHA", "3DES", 24, 8, "SHA-1", 20);

      case 0xC01D: // SRP_SHA_WITH_AES_128_CBC_SHA
         return Ciphersuite(0xC01D, "", "SRP_SHA", "AES-128", 16, 16, "SHA-1", 20);

      case 0xC020: // SRP_SHA_WITH_AES_256_CBC_SHA
         return Ciphersuite(0xC020, "", "SRP_SHA", "AES-256", 32, 16, "SHA-1", 20);

      }

   return Ciphersuite(); // some unknown ciphersuite
   }

}

}
