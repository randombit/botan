/*************************************************
* Enumerations Header File                       *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_ENUMS_H__
#define BOTAN_ENUMS_H__

namespace Botan {

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

enum Character_Set {
   LOCAL_CHARSET,
   UCS2_CHARSET,
   UTF8_CHARSET,
   LATIN1_CHARSET
};

static const u32bit NO_CERT_PATH_LIMIT = 0xFFFFFFF0;

}

#endif
