/*
* NEWHOPE Ring-LWE scheme
* Based on the public domain reference implementation by the
* designers (https://github.com/tpoeppelmann/newhope)
*
* Further changes
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef NEWHOPE_H
#define NEWHOPE_H

#include <botan/rng.h>

namespace Botan {

/*
* WARNING: This API is preliminary and will change
* Currently pubkey.h does not support a 2-phase KEM scheme of
* the sort NEWHOPE exports.
*/
#define PARAM_N 1024

#define NEWHOPE_SENDABYTES 1824
#define NEWHOPE_SENDBBYTES 2048

typedef struct {
  uint16_t coeffs[PARAM_N];
} newhope_poly __attribute__ ((aligned (32)));


void BOTAN_DLL newhope_keygen(unsigned char *send, newhope_poly *sk, RandomNumberGenerator& rng);
void BOTAN_DLL newhope_sharedb(unsigned char *sharedkey, unsigned char *send, const unsigned char *received, RandomNumberGenerator& rng);
void BOTAN_DLL newhope_shareda(unsigned char *sharedkey, const newhope_poly *ska, const unsigned char *received);


/*
* This is just exposed for testing
*/
void BOTAN_DLL newhope_hash(unsigned char *output, const unsigned char *input, unsigned int inputByteLen);


}

#endif
