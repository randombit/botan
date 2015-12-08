/*
* TLS cipher suite information
*
* This file was automatically generated from the IANA assignments
* (tls-parameters.txt hash 6a934405ed41aa4d6113dad17f815867741430ac)
* by ./src/scripts/tls_suite_info.py on 2015-11-13
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_ciphersuite.h>

namespace Botan {

namespace TLS {

Ciphersuite Ciphersuite::by_id(u16bit suite)
   {
   switch(suite)
      {
      case 0x0013: // DHE_DSS_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0x0013, "DSA", "DH", "3DES", 24, 8, 0, "SHA-1", 20);

      case 0x0032: // DHE_DSS_WITH_AES_128_CBC_SHA
         return Ciphersuite(0x0032, "DSA", "DH", "AES-128", 16, 16, 0, "SHA-1", 20);

      case 0x0040: // DHE_DSS_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0x0040, "DSA", "DH", "AES-128", 16, 16, 0, "SHA-256", 32);

      case 0x00A2: // DHE_DSS_WITH_AES_128_GCM_SHA256
         return Ciphersuite(0x00A2, "DSA", "DH", "AES-128/GCM", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0x0038: // DHE_DSS_WITH_AES_256_CBC_SHA
         return Ciphersuite(0x0038, "DSA", "DH", "AES-256", 32, 16, 0, "SHA-1", 20);

      case 0x006A: // DHE_DSS_WITH_AES_256_CBC_SHA256
         return Ciphersuite(0x006A, "DSA", "DH", "AES-256", 32, 16, 0, "SHA-256", 32);

      case 0x00A3: // DHE_DSS_WITH_AES_256_GCM_SHA384
         return Ciphersuite(0x00A3, "DSA", "DH", "AES-256/GCM", 32, 4, 8, "AEAD", 0, "SHA-384");

      case 0x0044: // DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
         return Ciphersuite(0x0044, "DSA", "DH", "Camellia-128", 16, 16, 0, "SHA-1", 20);

      case 0x00BD: // DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0x00BD, "DSA", "DH", "Camellia-128", 16, 16, 0, "SHA-256", 32);

      case 0xC080: // DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256
         return Ciphersuite(0xC080, "DSA", "DH", "Camellia-128/GCM", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0x0087: // DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
         return Ciphersuite(0x0087, "DSA", "DH", "Camellia-256", 32, 16, 0, "SHA-1", 20);

      case 0x00C3: // DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256
         return Ciphersuite(0x00C3, "DSA", "DH", "Camellia-256", 32, 16, 0, "SHA-256", 32);

      case 0xC081: // DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384
         return Ciphersuite(0xC081, "DSA", "DH", "Camellia-256/GCM", 32, 4, 8, "AEAD", 0, "SHA-384");

      case 0x0099: // DHE_DSS_WITH_SEED_CBC_SHA
         return Ciphersuite(0x0099, "DSA", "DH", "SEED", 16, 16, 0, "SHA-1", 20);

      case 0x008F: // DHE_PSK_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0x008F, "", "DHE_PSK", "3DES", 24, 8, 0, "SHA-1", 20);

      case 0x0090: // DHE_PSK_WITH_AES_128_CBC_SHA
         return Ciphersuite(0x0090, "", "DHE_PSK", "AES-128", 16, 16, 0, "SHA-1", 20);

      case 0x00B2: // DHE_PSK_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0x00B2, "", "DHE_PSK", "AES-128", 16, 16, 0, "SHA-256", 32);

      case 0xC0A6: // DHE_PSK_WITH_AES_128_CCM
         return Ciphersuite(0xC0A6, "", "DHE_PSK", "AES-128/CCM", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0x00AA: // DHE_PSK_WITH_AES_128_GCM_SHA256
         return Ciphersuite(0x00AA, "", "DHE_PSK", "AES-128/GCM", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0xFFFA: // DHE_PSK_WITH_AES_128_OCB_SHA256
         return Ciphersuite(0xFFFA, "", "DHE_PSK", "AES-128/OCB(12)", 16, 4, 0, "AEAD", 0, "SHA-256");

      case 0x0091: // DHE_PSK_WITH_AES_256_CBC_SHA
         return Ciphersuite(0x0091, "", "DHE_PSK", "AES-256", 32, 16, 0, "SHA-1", 20);

      case 0x00B3: // DHE_PSK_WITH_AES_256_CBC_SHA384
         return Ciphersuite(0x00B3, "", "DHE_PSK", "AES-256", 32, 16, 0, "SHA-384", 48);

      case 0xC0A7: // DHE_PSK_WITH_AES_256_CCM
         return Ciphersuite(0xC0A7, "", "DHE_PSK", "AES-256/CCM", 32, 4, 8, "AEAD", 0, "SHA-256");

      case 0x00AB: // DHE_PSK_WITH_AES_256_GCM_SHA384
         return Ciphersuite(0x00AB, "", "DHE_PSK", "AES-256/GCM", 32, 4, 8, "AEAD", 0, "SHA-384");

      case 0xFFFB: // DHE_PSK_WITH_AES_256_OCB_SHA256
         return Ciphersuite(0xFFFB, "", "DHE_PSK", "AES-256/OCB(12)", 32, 4, 0, "AEAD", 0, "SHA-256");

      case 0xC096: // DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0xC096, "", "DHE_PSK", "Camellia-128", 16, 16, 0, "SHA-256", 32);

      case 0xC090: // DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256
         return Ciphersuite(0xC090, "", "DHE_PSK", "Camellia-128/GCM", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0xC097: // DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
         return Ciphersuite(0xC097, "", "DHE_PSK", "Camellia-256", 32, 16, 0, "SHA-384", 48);

      case 0xC091: // DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384
         return Ciphersuite(0xC091, "", "DHE_PSK", "Camellia-256/GCM", 32, 4, 8, "AEAD", 0, "SHA-384");

      case 0x0016: // DHE_RSA_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0x0016, "RSA", "DH", "3DES", 24, 8, 0, "SHA-1", 20);

      case 0x0033: // DHE_RSA_WITH_AES_128_CBC_SHA
         return Ciphersuite(0x0033, "RSA", "DH", "AES-128", 16, 16, 0, "SHA-1", 20);

      case 0x0067: // DHE_RSA_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0x0067, "RSA", "DH", "AES-128", 16, 16, 0, "SHA-256", 32);

      case 0xC09E: // DHE_RSA_WITH_AES_128_CCM
         return Ciphersuite(0xC09E, "RSA", "DH", "AES-128/CCM", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0xC0A2: // DHE_RSA_WITH_AES_128_CCM_8
         return Ciphersuite(0xC0A2, "RSA", "DH", "AES-128/CCM(8)", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0x009E: // DHE_RSA_WITH_AES_128_GCM_SHA256
         return Ciphersuite(0x009E, "RSA", "DH", "AES-128/GCM", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0xFFF4: // DHE_RSA_WITH_AES_128_OCB_SHA256
         return Ciphersuite(0xFFF4, "RSA", "DH", "AES-128/OCB(12)", 16, 4, 0, "AEAD", 0, "SHA-256");

      case 0x0039: // DHE_RSA_WITH_AES_256_CBC_SHA
         return Ciphersuite(0x0039, "RSA", "DH", "AES-256", 32, 16, 0, "SHA-1", 20);

      case 0x006B: // DHE_RSA_WITH_AES_256_CBC_SHA256
         return Ciphersuite(0x006B, "RSA", "DH", "AES-256", 32, 16, 0, "SHA-256", 32);

      case 0xC09F: // DHE_RSA_WITH_AES_256_CCM
         return Ciphersuite(0xC09F, "RSA", "DH", "AES-256/CCM", 32, 4, 8, "AEAD", 0, "SHA-256");

      case 0xC0A3: // DHE_RSA_WITH_AES_256_CCM_8
         return Ciphersuite(0xC0A3, "RSA", "DH", "AES-256/CCM(8)", 32, 4, 8, "AEAD", 0, "SHA-256");

      case 0x009F: // DHE_RSA_WITH_AES_256_GCM_SHA384
         return Ciphersuite(0x009F, "RSA", "DH", "AES-256/GCM", 32, 4, 8, "AEAD", 0, "SHA-384");

      case 0xFFF5: // DHE_RSA_WITH_AES_256_OCB_SHA256
         return Ciphersuite(0xFFF5, "RSA", "DH", "AES-256/OCB(12)", 32, 4, 0, "AEAD", 0, "SHA-256");

      case 0x0045: // DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
         return Ciphersuite(0x0045, "RSA", "DH", "Camellia-128", 16, 16, 0, "SHA-1", 20);

      case 0x00BE: // DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0x00BE, "RSA", "DH", "Camellia-128", 16, 16, 0, "SHA-256", 32);

      case 0xC07C: // DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
         return Ciphersuite(0xC07C, "RSA", "DH", "Camellia-128/GCM", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0x0088: // DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
         return Ciphersuite(0x0088, "RSA", "DH", "Camellia-256", 32, 16, 0, "SHA-1", 20);

      case 0x00C4: // DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
         return Ciphersuite(0x00C4, "RSA", "DH", "Camellia-256", 32, 16, 0, "SHA-256", 32);

      case 0xC07D: // DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
         return Ciphersuite(0xC07D, "RSA", "DH", "Camellia-256/GCM", 32, 4, 8, "AEAD", 0, "SHA-384");

      case 0xCC15: // DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
         return Ciphersuite(0xCC15, "RSA", "DH", "ChaCha20Poly1305", 32, 0, 0, "AEAD", 0, "SHA-256");

      case 0x009A: // DHE_RSA_WITH_SEED_CBC_SHA
         return Ciphersuite(0x009A, "RSA", "DH", "SEED", 16, 16, 0, "SHA-1", 20);

      case 0x001B: // DH_anon_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0x001B, "", "DH", "3DES", 24, 8, 0, "SHA-1", 20);

      case 0x0034: // DH_anon_WITH_AES_128_CBC_SHA
         return Ciphersuite(0x0034, "", "DH", "AES-128", 16, 16, 0, "SHA-1", 20);

      case 0x006C: // DH_anon_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0x006C, "", "DH", "AES-128", 16, 16, 0, "SHA-256", 32);

      case 0x00A6: // DH_anon_WITH_AES_128_GCM_SHA256
         return Ciphersuite(0x00A6, "", "DH", "AES-128/GCM", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0x003A: // DH_anon_WITH_AES_256_CBC_SHA
         return Ciphersuite(0x003A, "", "DH", "AES-256", 32, 16, 0, "SHA-1", 20);

      case 0x006D: // DH_anon_WITH_AES_256_CBC_SHA256
         return Ciphersuite(0x006D, "", "DH", "AES-256", 32, 16, 0, "SHA-256", 32);

      case 0x00A7: // DH_anon_WITH_AES_256_GCM_SHA384
         return Ciphersuite(0x00A7, "", "DH", "AES-256/GCM", 32, 4, 8, "AEAD", 0, "SHA-384");

      case 0x0046: // DH_anon_WITH_CAMELLIA_128_CBC_SHA
         return Ciphersuite(0x0046, "", "DH", "Camellia-128", 16, 16, 0, "SHA-1", 20);

      case 0x00BF: // DH_anon_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0x00BF, "", "DH", "Camellia-128", 16, 16, 0, "SHA-256", 32);

      case 0xC084: // DH_anon_WITH_CAMELLIA_128_GCM_SHA256
         return Ciphersuite(0xC084, "", "DH", "Camellia-128/GCM", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0x0089: // DH_anon_WITH_CAMELLIA_256_CBC_SHA
         return Ciphersuite(0x0089, "", "DH", "Camellia-256", 32, 16, 0, "SHA-1", 20);

      case 0x00C5: // DH_anon_WITH_CAMELLIA_256_CBC_SHA256
         return Ciphersuite(0x00C5, "", "DH", "Camellia-256", 32, 16, 0, "SHA-256", 32);

      case 0xC085: // DH_anon_WITH_CAMELLIA_256_GCM_SHA384
         return Ciphersuite(0xC085, "", "DH", "Camellia-256/GCM", 32, 4, 8, "AEAD", 0, "SHA-384");

      case 0x009B: // DH_anon_WITH_SEED_CBC_SHA
         return Ciphersuite(0x009B, "", "DH", "SEED", 16, 16, 0, "SHA-1", 20);

      case 0xC008: // ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0xC008, "ECDSA", "ECDH", "3DES", 24, 8, 0, "SHA-1", 20);

      case 0xC009: // ECDHE_ECDSA_WITH_AES_128_CBC_SHA
         return Ciphersuite(0xC009, "ECDSA", "ECDH", "AES-128", 16, 16, 0, "SHA-1", 20);

      case 0xC023: // ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0xC023, "ECDSA", "ECDH", "AES-128", 16, 16, 0, "SHA-256", 32);

      case 0xC0AC: // ECDHE_ECDSA_WITH_AES_128_CCM
         return Ciphersuite(0xC0AC, "ECDSA", "ECDH", "AES-128/CCM", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0xC0AE: // ECDHE_ECDSA_WITH_AES_128_CCM_8
         return Ciphersuite(0xC0AE, "ECDSA", "ECDH", "AES-128/CCM(8)", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0xC02B: // ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
         return Ciphersuite(0xC02B, "ECDSA", "ECDH", "AES-128/GCM", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0xFFF2: // ECDHE_ECDSA_WITH_AES_128_OCB_SHA256
         return Ciphersuite(0xFFF2, "ECDSA", "ECDH", "AES-128/OCB(12)", 16, 4, 0, "AEAD", 0, "SHA-256");

      case 0xC00A: // ECDHE_ECDSA_WITH_AES_256_CBC_SHA
         return Ciphersuite(0xC00A, "ECDSA", "ECDH", "AES-256", 32, 16, 0, "SHA-1", 20);

      case 0xC024: // ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
         return Ciphersuite(0xC024, "ECDSA", "ECDH", "AES-256", 32, 16, 0, "SHA-384", 48);

      case 0xC0AD: // ECDHE_ECDSA_WITH_AES_256_CCM
         return Ciphersuite(0xC0AD, "ECDSA", "ECDH", "AES-256/CCM", 32, 4, 8, "AEAD", 0, "SHA-256");

      case 0xC0AF: // ECDHE_ECDSA_WITH_AES_256_CCM_8
         return Ciphersuite(0xC0AF, "ECDSA", "ECDH", "AES-256/CCM(8)", 32, 4, 8, "AEAD", 0, "SHA-256");

      case 0xC02C: // ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
         return Ciphersuite(0xC02C, "ECDSA", "ECDH", "AES-256/GCM", 32, 4, 8, "AEAD", 0, "SHA-384");

      case 0xFFF3: // ECDHE_ECDSA_WITH_AES_256_OCB_SHA256
         return Ciphersuite(0xFFF3, "ECDSA", "ECDH", "AES-256/OCB(12)", 32, 4, 0, "AEAD", 0, "SHA-256");

      case 0xC072: // ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0xC072, "ECDSA", "ECDH", "Camellia-128", 16, 16, 0, "SHA-256", 32);

      case 0xC086: // ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
         return Ciphersuite(0xC086, "ECDSA", "ECDH", "Camellia-128/GCM", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0xC073: // ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
         return Ciphersuite(0xC073, "ECDSA", "ECDH", "Camellia-256", 32, 16, 0, "SHA-384", 48);

      case 0xC087: // ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
         return Ciphersuite(0xC087, "ECDSA", "ECDH", "Camellia-256/GCM", 32, 4, 8, "AEAD", 0, "SHA-384");

      case 0xCC14: // ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
         return Ciphersuite(0xCC14, "ECDSA", "ECDH", "ChaCha20Poly1305", 32, 0, 0, "AEAD", 0, "SHA-256");

      case 0xC034: // ECDHE_PSK_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0xC034, "", "ECDHE_PSK", "3DES", 24, 8, 0, "SHA-1", 20);

      case 0xC035: // ECDHE_PSK_WITH_AES_128_CBC_SHA
         return Ciphersuite(0xC035, "", "ECDHE_PSK", "AES-128", 16, 16, 0, "SHA-1", 20);

      case 0xC037: // ECDHE_PSK_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0xC037, "", "ECDHE_PSK", "AES-128", 16, 16, 0, "SHA-256", 32);

      case 0xFFF8: // ECDHE_PSK_WITH_AES_128_OCB_SHA256
         return Ciphersuite(0xFFF8, "", "ECDHE_PSK", "AES-128/OCB(12)", 16, 4, 0, "AEAD", 0, "SHA-256");

      case 0xC036: // ECDHE_PSK_WITH_AES_256_CBC_SHA
         return Ciphersuite(0xC036, "", "ECDHE_PSK", "AES-256", 32, 16, 0, "SHA-1", 20);

      case 0xC038: // ECDHE_PSK_WITH_AES_256_CBC_SHA384
         return Ciphersuite(0xC038, "", "ECDHE_PSK", "AES-256", 32, 16, 0, "SHA-384", 48);

      case 0xFFF9: // ECDHE_PSK_WITH_AES_256_OCB_SHA256
         return Ciphersuite(0xFFF9, "", "ECDHE_PSK", "AES-256/OCB(12)", 32, 4, 0, "AEAD", 0, "SHA-256");

      case 0xC09A: // ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0xC09A, "", "ECDHE_PSK", "Camellia-128", 16, 16, 0, "SHA-256", 32);

      case 0xC09B: // ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
         return Ciphersuite(0xC09B, "", "ECDHE_PSK", "Camellia-256", 32, 16, 0, "SHA-384", 48);

      case 0xC012: // ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0xC012, "RSA", "ECDH", "3DES", 24, 8, 0, "SHA-1", 20);

      case 0xC013: // ECDHE_RSA_WITH_AES_128_CBC_SHA
         return Ciphersuite(0xC013, "RSA", "ECDH", "AES-128", 16, 16, 0, "SHA-1", 20);

      case 0xC027: // ECDHE_RSA_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0xC027, "RSA", "ECDH", "AES-128", 16, 16, 0, "SHA-256", 32);

      case 0xC02F: // ECDHE_RSA_WITH_AES_128_GCM_SHA256
         return Ciphersuite(0xC02F, "RSA", "ECDH", "AES-128/GCM", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0xFFF0: // ECDHE_RSA_WITH_AES_128_OCB_SHA256
         return Ciphersuite(0xFFF0, "RSA", "ECDH", "AES-128/OCB(12)", 16, 4, 0, "AEAD", 0, "SHA-256");

      case 0xC014: // ECDHE_RSA_WITH_AES_256_CBC_SHA
         return Ciphersuite(0xC014, "RSA", "ECDH", "AES-256", 32, 16, 0, "SHA-1", 20);

      case 0xC028: // ECDHE_RSA_WITH_AES_256_CBC_SHA384
         return Ciphersuite(0xC028, "RSA", "ECDH", "AES-256", 32, 16, 0, "SHA-384", 48);

      case 0xC030: // ECDHE_RSA_WITH_AES_256_GCM_SHA384
         return Ciphersuite(0xC030, "RSA", "ECDH", "AES-256/GCM", 32, 4, 8, "AEAD", 0, "SHA-384");

      case 0xFFF1: // ECDHE_RSA_WITH_AES_256_OCB_SHA256
         return Ciphersuite(0xFFF1, "RSA", "ECDH", "AES-256/OCB(12)", 32, 4, 0, "AEAD", 0, "SHA-256");

      case 0xC076: // ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0xC076, "RSA", "ECDH", "Camellia-128", 16, 16, 0, "SHA-256", 32);

      case 0xC08A: // ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
         return Ciphersuite(0xC08A, "RSA", "ECDH", "Camellia-128/GCM", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0xC077: // ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
         return Ciphersuite(0xC077, "RSA", "ECDH", "Camellia-256", 32, 16, 0, "SHA-384", 48);

      case 0xC08B: // ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
         return Ciphersuite(0xC08B, "RSA", "ECDH", "Camellia-256/GCM", 32, 4, 8, "AEAD", 0, "SHA-384");

      case 0xCC13: // ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
         return Ciphersuite(0xCC13, "RSA", "ECDH", "ChaCha20Poly1305", 32, 0, 0, "AEAD", 0, "SHA-256");

      case 0xC017: // ECDH_anon_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0xC017, "", "ECDH", "3DES", 24, 8, 0, "SHA-1", 20);

      case 0xC018: // ECDH_anon_WITH_AES_128_CBC_SHA
         return Ciphersuite(0xC018, "", "ECDH", "AES-128", 16, 16, 0, "SHA-1", 20);

      case 0xC019: // ECDH_anon_WITH_AES_256_CBC_SHA
         return Ciphersuite(0xC019, "", "ECDH", "AES-256", 32, 16, 0, "SHA-1", 20);

      case 0xC0AA: // PSK_DHE_WITH_AES_128_CCM_8
         return Ciphersuite(0xC0AA, "", "DHE_PSK", "AES-128/CCM(8)", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0xC0AB: // PSK_DHE_WITH_AES_256_CCM_8
         return Ciphersuite(0xC0AB, "", "DHE_PSK", "AES-256/CCM(8)", 32, 4, 8, "AEAD", 0, "SHA-256");

      case 0x008B: // PSK_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0x008B, "", "PSK", "3DES", 24, 8, 0, "SHA-1", 20);

      case 0x008C: // PSK_WITH_AES_128_CBC_SHA
         return Ciphersuite(0x008C, "", "PSK", "AES-128", 16, 16, 0, "SHA-1", 20);

      case 0x00AE: // PSK_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0x00AE, "", "PSK", "AES-128", 16, 16, 0, "SHA-256", 32);

      case 0xC0A4: // PSK_WITH_AES_128_CCM
         return Ciphersuite(0xC0A4, "", "PSK", "AES-128/CCM", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0xC0A8: // PSK_WITH_AES_128_CCM_8
         return Ciphersuite(0xC0A8, "", "PSK", "AES-128/CCM(8)", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0x00A8: // PSK_WITH_AES_128_GCM_SHA256
         return Ciphersuite(0x00A8, "", "PSK", "AES-128/GCM", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0xFFF6: // PSK_WITH_AES_128_OCB_SHA256
         return Ciphersuite(0xFFF6, "", "PSK", "AES-128/OCB(12)", 16, 4, 0, "AEAD", 0, "SHA-256");

      case 0x008D: // PSK_WITH_AES_256_CBC_SHA
         return Ciphersuite(0x008D, "", "PSK", "AES-256", 32, 16, 0, "SHA-1", 20);

      case 0x00AF: // PSK_WITH_AES_256_CBC_SHA384
         return Ciphersuite(0x00AF, "", "PSK", "AES-256", 32, 16, 0, "SHA-384", 48);

      case 0xC0A5: // PSK_WITH_AES_256_CCM
         return Ciphersuite(0xC0A5, "", "PSK", "AES-256/CCM", 32, 4, 8, "AEAD", 0, "SHA-256");

      case 0xC0A9: // PSK_WITH_AES_256_CCM_8
         return Ciphersuite(0xC0A9, "", "PSK", "AES-256/CCM(8)", 32, 4, 8, "AEAD", 0, "SHA-256");

      case 0x00A9: // PSK_WITH_AES_256_GCM_SHA384
         return Ciphersuite(0x00A9, "", "PSK", "AES-256/GCM", 32, 4, 8, "AEAD", 0, "SHA-384");

      case 0xFFF7: // PSK_WITH_AES_256_OCB_SHA256
         return Ciphersuite(0xFFF7, "", "PSK", "AES-256/OCB(12)", 32, 4, 0, "AEAD", 0, "SHA-256");

      case 0xC094: // PSK_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0xC094, "", "PSK", "Camellia-128", 16, 16, 0, "SHA-256", 32);

      case 0xC08E: // PSK_WITH_CAMELLIA_128_GCM_SHA256
         return Ciphersuite(0xC08E, "", "PSK", "Camellia-128/GCM", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0xC095: // PSK_WITH_CAMELLIA_256_CBC_SHA384
         return Ciphersuite(0xC095, "", "PSK", "Camellia-256", 32, 16, 0, "SHA-384", 48);

      case 0xC08F: // PSK_WITH_CAMELLIA_256_GCM_SHA384
         return Ciphersuite(0xC08F, "", "PSK", "Camellia-256/GCM", 32, 4, 8, "AEAD", 0, "SHA-384");

      case 0x000A: // RSA_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0x000A, "RSA", "RSA", "3DES", 24, 8, 0, "SHA-1", 20);

      case 0x002F: // RSA_WITH_AES_128_CBC_SHA
         return Ciphersuite(0x002F, "RSA", "RSA", "AES-128", 16, 16, 0, "SHA-1", 20);

      case 0x003C: // RSA_WITH_AES_128_CBC_SHA256
         return Ciphersuite(0x003C, "RSA", "RSA", "AES-128", 16, 16, 0, "SHA-256", 32);

      case 0xC09C: // RSA_WITH_AES_128_CCM
         return Ciphersuite(0xC09C, "RSA", "RSA", "AES-128/CCM", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0xC0A0: // RSA_WITH_AES_128_CCM_8
         return Ciphersuite(0xC0A0, "RSA", "RSA", "AES-128/CCM(8)", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0x009C: // RSA_WITH_AES_128_GCM_SHA256
         return Ciphersuite(0x009C, "RSA", "RSA", "AES-128/GCM", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0x0035: // RSA_WITH_AES_256_CBC_SHA
         return Ciphersuite(0x0035, "RSA", "RSA", "AES-256", 32, 16, 0, "SHA-1", 20);

      case 0x003D: // RSA_WITH_AES_256_CBC_SHA256
         return Ciphersuite(0x003D, "RSA", "RSA", "AES-256", 32, 16, 0, "SHA-256", 32);

      case 0xC09D: // RSA_WITH_AES_256_CCM
         return Ciphersuite(0xC09D, "RSA", "RSA", "AES-256/CCM", 32, 4, 8, "AEAD", 0, "SHA-256");

      case 0xC0A1: // RSA_WITH_AES_256_CCM_8
         return Ciphersuite(0xC0A1, "RSA", "RSA", "AES-256/CCM(8)", 32, 4, 8, "AEAD", 0, "SHA-256");

      case 0x009D: // RSA_WITH_AES_256_GCM_SHA384
         return Ciphersuite(0x009D, "RSA", "RSA", "AES-256/GCM", 32, 4, 8, "AEAD", 0, "SHA-384");

      case 0x0041: // RSA_WITH_CAMELLIA_128_CBC_SHA
         return Ciphersuite(0x0041, "RSA", "RSA", "Camellia-128", 16, 16, 0, "SHA-1", 20);

      case 0x00BA: // RSA_WITH_CAMELLIA_128_CBC_SHA256
         return Ciphersuite(0x00BA, "RSA", "RSA", "Camellia-128", 16, 16, 0, "SHA-256", 32);

      case 0xC07A: // RSA_WITH_CAMELLIA_128_GCM_SHA256
         return Ciphersuite(0xC07A, "RSA", "RSA", "Camellia-128/GCM", 16, 4, 8, "AEAD", 0, "SHA-256");

      case 0x0084: // RSA_WITH_CAMELLIA_256_CBC_SHA
         return Ciphersuite(0x0084, "RSA", "RSA", "Camellia-256", 32, 16, 0, "SHA-1", 20);

      case 0x00C0: // RSA_WITH_CAMELLIA_256_CBC_SHA256
         return Ciphersuite(0x00C0, "RSA", "RSA", "Camellia-256", 32, 16, 0, "SHA-256", 32);

      case 0xC07B: // RSA_WITH_CAMELLIA_256_GCM_SHA384
         return Ciphersuite(0xC07B, "RSA", "RSA", "Camellia-256/GCM", 32, 4, 8, "AEAD", 0, "SHA-384");

      case 0x0096: // RSA_WITH_SEED_CBC_SHA
         return Ciphersuite(0x0096, "RSA", "RSA", "SEED", 16, 16, 0, "SHA-1", 20);

      case 0xC01C: // SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0xC01C, "DSA", "SRP_SHA", "3DES", 24, 8, 0, "SHA-1", 20);

      case 0xC01F: // SRP_SHA_DSS_WITH_AES_128_CBC_SHA
         return Ciphersuite(0xC01F, "DSA", "SRP_SHA", "AES-128", 16, 16, 0, "SHA-1", 20);

      case 0xC022: // SRP_SHA_DSS_WITH_AES_256_CBC_SHA
         return Ciphersuite(0xC022, "DSA", "SRP_SHA", "AES-256", 32, 16, 0, "SHA-1", 20);

      case 0xC01B: // SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0xC01B, "RSA", "SRP_SHA", "3DES", 24, 8, 0, "SHA-1", 20);

      case 0xC01E: // SRP_SHA_RSA_WITH_AES_128_CBC_SHA
         return Ciphersuite(0xC01E, "RSA", "SRP_SHA", "AES-128", 16, 16, 0, "SHA-1", 20);

      case 0xC021: // SRP_SHA_RSA_WITH_AES_256_CBC_SHA
         return Ciphersuite(0xC021, "RSA", "SRP_SHA", "AES-256", 32, 16, 0, "SHA-1", 20);

      case 0xC01A: // SRP_SHA_WITH_3DES_EDE_CBC_SHA
         return Ciphersuite(0xC01A, "", "SRP_SHA", "3DES", 24, 8, 0, "SHA-1", 20);

      case 0xC01D: // SRP_SHA_WITH_AES_128_CBC_SHA
         return Ciphersuite(0xC01D, "", "SRP_SHA", "AES-128", 16, 16, 0, "SHA-1", 20);

      case 0xC020: // SRP_SHA_WITH_AES_256_CBC_SHA
         return Ciphersuite(0xC020, "", "SRP_SHA", "AES-256", 32, 16, 0, "SHA-1", 20);

      }

   return Ciphersuite(); // some unknown ciphersuite
   }

}

}
