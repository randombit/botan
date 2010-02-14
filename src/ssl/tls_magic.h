/**
* SSL/TLS Protocol Constants Header File
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_PROTOCOL_MAGIC_H__
#define BOTAN_PROTOCOL_MAGIC_H__

namespace Botan {

/**
* Protocol Constants for SSL/TLS
*/
enum Size_Limits {
   MAX_PLAINTEXT_SIZE = 16*1024,
   MAX_COMPRESSED_SIZE = MAX_PLAINTEXT_SIZE + 1024,
   MAX_CIPHERTEXT_SIZE = MAX_COMPRESSED_SIZE + 1024
};

enum Version_Code {
   NO_VERSION_SET     = 0x0000,
   SSL_V3             = 0x0300,
   TLS_V10            = 0x0301,
   TLS_V11            = 0x0302
};

enum Connection_Side { CLIENT, SERVER };

enum Record_Type {
   CONNECTION_CLOSED  = 0,

   CHANGE_CIPHER_SPEC = 20,
   ALERT              = 21,
   HANDSHAKE          = 22,
   APPLICATION_DATA   = 23
};

enum Handshake_Type {
   HELLO_REQUEST       = 0,
   CLIENT_HELLO        = 1,
   SERVER_HELLO        = 2,
   CERTIFICATE         = 11,
   SERVER_KEX          = 12,
   CERTIFICATE_REQUEST = 13,
   SERVER_HELLO_DONE   = 14,
   CERTIFICATE_VERIFY  = 15,
   CLIENT_KEX          = 16,
   FINISHED            = 20,

   HANDSHAKE_CCS       = 100,
   HANDSHAKE_NONE      = 101
};

enum Alert_Level {
   WARNING                 = 1,
   FATAL                   = 2
};

enum Alert_Type {
   CLOSE_NOTIFY            = 0,
   UNEXPECTED_MESSAGE      = 10,
   BAD_RECORD_MAC          = 20,
   DECRYPTION_FAILED       = 21,
   RECORD_OVERFLOW         = 22,
   DECOMPRESSION_FAILURE   = 30,
   HANDSHAKE_FAILURE       = 40,
   BAD_CERTIFICATE         = 42,
   UNSUPPORTED_CERTIFICATE = 43,
   CERTIFICATE_REVOKED     = 44,
   CERTIFICATE_EXPIRED     = 45,
   CERTIFICATE_UNKNOWN     = 46,
   ILLEGAL_PARAMETER       = 47,
   UNKNOWN_CA              = 48,
   ACCESS_DENIED           = 49,
   DECODE_ERROR            = 50,
   DECRYPT_ERROR           = 51,
   EXPORT_RESTRICTION      = 60,
   PROTOCOL_VERSION        = 70,
   INSUFFICIENT_SECURITY   = 71,
   INTERNAL_ERROR          = 80,
   USER_CANCELED           = 90,
   NO_RENEGOTIATION        = 100,

   NO_ALERT_TYPE           = 0xFFFF
};

enum Certificate_Type {
   RSA_CERT    = 1,
   DSS_CERT    = 2,
   DH_RSA_CERT = 3,
   DH_DSS_CERT = 4
};

enum Ciphersuite_Code {
   RSA_RC4_MD5         = 0x0004,
   RSA_RC4_SHA         = 0x0005,
   RSA_3DES_SHA        = 0x000A,
   RSA_AES128_SHA      = 0x002F,
   RSA_AES256_SHA      = 0x0035,

   DHE_RSA_3DES_SHA    = 0x0016,
   DHE_RSA_AES128_SHA  = 0x0033,
   DHE_RSA_AES256_SHA  = 0x0039,

   DHE_DSS_3DES_SHA    = 0x0013,
   DHE_DSS_AES128_SHA  = 0x0032,
   DHE_DSS_AES256_SHA  = 0x0038
};

enum Compression_Algo {
   NO_COMPRESSION      = 0x00
};

}

#endif
