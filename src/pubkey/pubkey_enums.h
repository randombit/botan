/*
* Enumerations
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ENUMS_H__
#define BOTAN_ENUMS_H__

#include <botan/ber_dec.h>

namespace Botan {

/**
* X.509v3 Key Constraints.
*/
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

/**
* BER Decoding Function for key constraints
*/
namespace BER {

void BOTAN_DLL decode(BER_Decoder&, Key_Constraints&);

}

/*
* Various Other Enumerations
*/

/**
* The two types of X509 encoding supported by Botan.
*/
enum X509_Encoding { RAW_BER, PEM };

}

#endif
