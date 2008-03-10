/*************************************************
* Enumerations Header File                       *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_ENUMS_H__
#define BOTAN_ENUMS_H__

namespace Botan {

/*************************************************
* ASN.1 Type and Class Tags                      *
*************************************************/
enum ASN1_Tag {
   UNIVERSAL        = 0x00,
   APPLICATION      = 0x40,
   CONTEXT_SPECIFIC = 0x80,
   PRIVATE          = 0xC0,

   CONSTRUCTED      = 0x20,

   EOC              = 0x00,
   BOOLEAN          = 0x01,
   INTEGER          = 0x02,
   BIT_STRING       = 0x03,
   OCTET_STRING     = 0x04,
   NULL_TAG         = 0x05,
   OBJECT_ID        = 0x06,
   ENUMERATED       = 0x0A,
   SEQUENCE         = 0x10,
   SET              = 0x11,

   UTF8_STRING      = 0x0C,
   NUMERIC_STRING   = 0x12,
   PRINTABLE_STRING = 0x13,
   T61_STRING       = 0x14,
   IA5_STRING       = 0x16,
   VISIBLE_STRING   = 0x1A,
   BMP_STRING       = 0x1E,

   UTC_TIME         = 0x17,
   GENERALIZED_TIME = 0x18,

   NO_OBJECT        = 0xFF00,
   DIRECTORY_STRING = 0xFF01
};

/*************************************************
* X.509v3 Key Constraints                        *
*************************************************/
enum Key_Constraints {
   NO_CONSTRAINTS     = 0,
   DIGITAL_SIGNATURE  = 32768,
   NON_REPUDIATION    = 16384,
   KEY_ENCIPHERMENT   = 8192,
   DATA_ENCIPHERMENT  = 4096,
   KEY_AGREEMENT      = 2048,
   KEY_CERT_SIGN      = 1024,
   CRL_SIGN           = 512,
   ENCIPHER_ONLY      = 256,
   DECIPHER_ONLY      = 128
};

/*************************************************
* X.509v2 CRL Reason Code                        *
*************************************************/
enum CRL_Code {
   UNSPECIFIED            = 0,
   KEY_COMPROMISE         = 1,
   CA_COMPROMISE          = 2,
   AFFILIATION_CHANGED    = 3,
   SUPERSEDED             = 4,
   CESSATION_OF_OPERATION = 5,
   CERTIFICATE_HOLD       = 6,
   REMOVE_FROM_CRL        = 8,
   PRIVLEDGE_WITHDRAWN    = 9,
   AA_COMPROMISE          = 10,

   DELETE_CRL_ENTRY       = 0xFF00,
   OCSP_GOOD              = 0xFF01,
   OCSP_UNKNOWN           = 0xFF02
};

/*************************************************
* Various Other Enumerations                     *
*************************************************/
enum Decoder_Checking { NONE, IGNORE_WS, FULL_CHECK };

enum X509_Encoding { RAW_BER, PEM };

enum Cipher_Dir { ENCRYPTION, DECRYPTION };

enum Signature_Format { IEEE_1363, DER_SEQUENCE };

enum Character_Set {
   LOCAL_CHARSET,
   UCS2_CHARSET,
   UTF8_CHARSET,
   LATIN1_CHARSET
};

/*************************************************
* Pulse Function                                 *
*************************************************/
enum Pulse_Type {
   GENERAL_PULSE,

   PIPE_WRITE,

   PRIME_SEARCHING,
   PRIME_SIEVING,
   PRIME_PASSED_SIEVE,
   PRIME_TESTING,
   PRIME_FOUND
};

static const u32bit NO_CERT_PATH_LIMIT = 0xFFFFFFF0;

}

#endif
