/*
* TLS cipher suite information
*
* This file was automatically generated from the IANA assignments
* (tls-parameters.txt sha256 ab105c99c5d0828af3742aaa6cf5a7ce8c890f8322f824ffa2abb41028a60d72)
* by tls_suite_info.py on 2021-07-29
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_ciphersuite.h>

namespace Botan::TLS {

//static
const std::vector<Ciphersuite>& Ciphersuite::all_known_ciphersuites()
   {
   // Note that this list of ciphersuites is ordered by id!
   static const std::vector<Ciphersuite> g_ciphersuite_list = {
      Ciphersuite(0x000A, "RSA_WITH_3DES_EDE_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "3DES", 24, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0016, "DHE_RSA_WITH_3DES_EDE_CBC_SHA", Auth_Method::RSA, Kex_Algo::DH, "3DES", 24, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x002F, "RSA_WITH_AES_128_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "AES-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0033, "DHE_RSA_WITH_AES_128_CBC_SHA", Auth_Method::RSA, Kex_Algo::DH, "AES-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0035, "RSA_WITH_AES_256_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "AES-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0039, "DHE_RSA_WITH_AES_256_CBC_SHA", Auth_Method::RSA, Kex_Algo::DH, "AES-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x003C, "RSA_WITH_AES_128_CBC_SHA256", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "AES-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x003D, "RSA_WITH_AES_256_CBC_SHA256", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "AES-256", 32, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0067, "DHE_RSA_WITH_AES_128_CBC_SHA256", Auth_Method::RSA, Kex_Algo::DH, "AES-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x006B, "DHE_RSA_WITH_AES_256_CBC_SHA256", Auth_Method::RSA, Kex_Algo::DH, "AES-256", 32, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x008B, "PSK_WITH_3DES_EDE_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::PSK, "3DES", 24, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x008C, "PSK_WITH_AES_128_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x008D, "PSK_WITH_AES_256_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x009C, "RSA_WITH_AES_128_GCM_SHA256", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "AES-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x009D, "RSA_WITH_AES_256_GCM_SHA384", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "AES-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x009E, "DHE_RSA_WITH_AES_128_GCM_SHA256", Auth_Method::RSA, Kex_Algo::DH, "AES-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x009F, "DHE_RSA_WITH_AES_256_GCM_SHA384", Auth_Method::RSA, Kex_Algo::DH, "AES-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x00A8, "PSK_WITH_AES_128_GCM_SHA256", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x00A9, "PSK_WITH_AES_256_GCM_SHA384", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x00AE, "PSK_WITH_AES_128_CBC_SHA256", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x00AF, "PSK_WITH_AES_256_CBC_SHA384", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-256", 32, "SHA-384", 48, KDF_Algo::SHA_384, Nonce_Format::CBC_MODE),
      Ciphersuite(0x1301, "AES_128_GCM_SHA256", Auth_Method::UNDEFINED, Kex_Algo::UNDEFINED, "AES-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x1302, "AES_256_GCM_SHA384", Auth_Method::UNDEFINED, Kex_Algo::UNDEFINED, "AES-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x1303, "CHACHA20_POLY1305_SHA256", Auth_Method::UNDEFINED, Kex_Algo::UNDEFINED, "ChaCha20Poly1305", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0x1304, "AES_128_CCM_SHA256", Auth_Method::UNDEFINED, Kex_Algo::UNDEFINED, "AES-128/CCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x1305, "AES_128_CCM_8_SHA256", Auth_Method::UNDEFINED, Kex_Algo::UNDEFINED, "AES-128/CCM(8)", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x16B7, "CECPQ1_RSA_WITH_CHACHA20_POLY1305_SHA256", Auth_Method::RSA, Kex_Algo::CECPQ1, "ChaCha20Poly1305", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0x16B8, "CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256", Auth_Method::ECDSA, Kex_Algo::CECPQ1, "ChaCha20Poly1305", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0x16B9, "CECPQ1_RSA_WITH_AES_256_GCM_SHA384", Auth_Method::RSA, Kex_Algo::CECPQ1, "AES-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x16BA, "CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384", Auth_Method::ECDSA, Kex_Algo::CECPQ1, "AES-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC008, "ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", Auth_Method::ECDSA, Kex_Algo::ECDH, "3DES", 24, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC009, "ECDHE_ECDSA_WITH_AES_128_CBC_SHA", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC00A, "ECDHE_ECDSA_WITH_AES_256_CBC_SHA", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC012, "ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", Auth_Method::RSA, Kex_Algo::ECDH, "3DES", 24, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC013, "ECDHE_RSA_WITH_AES_128_CBC_SHA", Auth_Method::RSA, Kex_Algo::ECDH, "AES-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC014, "ECDHE_RSA_WITH_AES_256_CBC_SHA", Auth_Method::RSA, Kex_Algo::ECDH, "AES-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC023, "ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC024, "ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-256", 32, "SHA-384", 48, KDF_Algo::SHA_384, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC027, "ECDHE_RSA_WITH_AES_128_CBC_SHA256", Auth_Method::RSA, Kex_Algo::ECDH, "AES-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC028, "ECDHE_RSA_WITH_AES_256_CBC_SHA384", Auth_Method::RSA, Kex_Algo::ECDH, "AES-256", 32, "SHA-384", 48, KDF_Algo::SHA_384, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC02B, "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC02C, "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC02F, "ECDHE_RSA_WITH_AES_128_GCM_SHA256", Auth_Method::RSA, Kex_Algo::ECDH, "AES-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC030, "ECDHE_RSA_WITH_AES_256_GCM_SHA384", Auth_Method::RSA, Kex_Algo::ECDH, "AES-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC034, "ECDHE_PSK_WITH_3DES_EDE_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "3DES", 24, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC035, "ECDHE_PSK_WITH_AES_128_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "AES-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC036, "ECDHE_PSK_WITH_AES_256_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "AES-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC037, "ECDHE_PSK_WITH_AES_128_CBC_SHA256", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "AES-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC038, "ECDHE_PSK_WITH_AES_256_CBC_SHA384", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "AES-256", 32, "SHA-384", 48, KDF_Algo::SHA_384, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC050, "RSA_WITH_ARIA_128_GCM_SHA256", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "ARIA-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC051, "RSA_WITH_ARIA_256_GCM_SHA384", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "ARIA-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC052, "DHE_RSA_WITH_ARIA_128_GCM_SHA256", Auth_Method::RSA, Kex_Algo::DH, "ARIA-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC053, "DHE_RSA_WITH_ARIA_256_GCM_SHA384", Auth_Method::RSA, Kex_Algo::DH, "ARIA-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC05C, "ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256", Auth_Method::ECDSA, Kex_Algo::ECDH, "ARIA-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC05D, "ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384", Auth_Method::ECDSA, Kex_Algo::ECDH, "ARIA-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC060, "ECDHE_RSA_WITH_ARIA_128_GCM_SHA256", Auth_Method::RSA, Kex_Algo::ECDH, "ARIA-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC061, "ECDHE_RSA_WITH_ARIA_256_GCM_SHA384", Auth_Method::RSA, Kex_Algo::ECDH, "ARIA-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC06A, "PSK_WITH_ARIA_128_GCM_SHA256", Auth_Method::IMPLICIT, Kex_Algo::PSK, "ARIA-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC06B, "PSK_WITH_ARIA_256_GCM_SHA384", Auth_Method::IMPLICIT, Kex_Algo::PSK, "ARIA-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC07A, "RSA_WITH_CAMELLIA_128_GCM_SHA256", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "Camellia-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC07B, "RSA_WITH_CAMELLIA_256_GCM_SHA384", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "Camellia-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC07C, "DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", Auth_Method::RSA, Kex_Algo::DH, "Camellia-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC07D, "DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", Auth_Method::RSA, Kex_Algo::DH, "Camellia-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC086, "ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", Auth_Method::ECDSA, Kex_Algo::ECDH, "Camellia-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC087, "ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", Auth_Method::ECDSA, Kex_Algo::ECDH, "Camellia-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC08A, "ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", Auth_Method::RSA, Kex_Algo::ECDH, "Camellia-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC08B, "ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", Auth_Method::RSA, Kex_Algo::ECDH, "Camellia-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC08E, "PSK_WITH_CAMELLIA_128_GCM_SHA256", Auth_Method::IMPLICIT, Kex_Algo::PSK, "Camellia-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC08F, "PSK_WITH_CAMELLIA_256_GCM_SHA384", Auth_Method::IMPLICIT, Kex_Algo::PSK, "Camellia-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC09C, "RSA_WITH_AES_128_CCM", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "AES-128/CCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC09D, "RSA_WITH_AES_256_CCM", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "AES-256/CCM", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC09E, "DHE_RSA_WITH_AES_128_CCM", Auth_Method::RSA, Kex_Algo::DH, "AES-128/CCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC09F, "DHE_RSA_WITH_AES_256_CCM", Auth_Method::RSA, Kex_Algo::DH, "AES-256/CCM", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0A0, "RSA_WITH_AES_128_CCM_8", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "AES-128/CCM(8)", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0A1, "RSA_WITH_AES_256_CCM_8", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "AES-256/CCM(8)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0A2, "DHE_RSA_WITH_AES_128_CCM_8", Auth_Method::RSA, Kex_Algo::DH, "AES-128/CCM(8)", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0A3, "DHE_RSA_WITH_AES_256_CCM_8", Auth_Method::RSA, Kex_Algo::DH, "AES-256/CCM(8)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0A4, "PSK_WITH_AES_128_CCM", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-128/CCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0A5, "PSK_WITH_AES_256_CCM", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-256/CCM", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0A8, "PSK_WITH_AES_128_CCM_8", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-128/CCM(8)", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0A9, "PSK_WITH_AES_256_CCM_8", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-256/CCM(8)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0AC, "ECDHE_ECDSA_WITH_AES_128_CCM", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-128/CCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0AD, "ECDHE_ECDSA_WITH_AES_256_CCM", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-256/CCM", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0AE, "ECDHE_ECDSA_WITH_AES_128_CCM_8", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-128/CCM(8)", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0AF, "ECDHE_ECDSA_WITH_AES_256_CCM_8", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-256/CCM(8)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xCCA8, "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", Auth_Method::RSA, Kex_Algo::ECDH, "ChaCha20Poly1305", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xCCA9, "ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", Auth_Method::ECDSA, Kex_Algo::ECDH, "ChaCha20Poly1305", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xCCAA, "DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", Auth_Method::RSA, Kex_Algo::DH, "ChaCha20Poly1305", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xCCAB, "PSK_WITH_CHACHA20_POLY1305_SHA256", Auth_Method::IMPLICIT, Kex_Algo::PSK, "ChaCha20Poly1305", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xCCAC, "ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "ChaCha20Poly1305", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xD001, "ECDHE_PSK_WITH_AES_128_GCM_SHA256", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "AES-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xD002, "ECDHE_PSK_WITH_AES_256_GCM_SHA384", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "AES-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xD003, "ECDHE_PSK_WITH_AES_128_CCM_8_SHA256", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "AES-128/CCM(8)", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xD005, "ECDHE_PSK_WITH_AES_128_CCM_SHA256", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "AES-128/CCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xFFC3, "ECDHE_RSA_WITH_AES_256_OCB_SHA256", Auth_Method::RSA, Kex_Algo::ECDH, "AES-256/OCB(12)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xFFC5, "ECDHE_ECDSA_WITH_AES_256_OCB_SHA256", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-256/OCB(12)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xFFC7, "PSK_WITH_AES_256_OCB_SHA256", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-256/OCB(12)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xFFCB, "ECDHE_PSK_WITH_AES_256_OCB_SHA256", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "AES-256/OCB(12)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xFFCC, "CECPQ1_RSA_WITH_AES_256_OCB_SHA256", Auth_Method::RSA, Kex_Algo::CECPQ1, "AES-256/OCB(12)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xFFCD, "CECPQ1_ECDSA_WITH_AES_256_OCB_SHA256", Auth_Method::ECDSA, Kex_Algo::CECPQ1, "AES-256/OCB(12)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      };

   return g_ciphersuite_list;
   }

}
