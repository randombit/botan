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

#ifndef BOTAN_NEWHOPE_H__
#define BOTAN_NEWHOPE_H__

#include <botan/rng.h>

namespace Botan {

/*
* WARNING: This API is preliminary and will change
* Currently pubkey.h does not support a 2-phase KEM scheme of
* the sort NEWHOPE exports.
*/
#define NEWHOPE_SENDABYTES 1824
#define NEWHOPE_SENDBBYTES 2048

typedef struct {
  uint16_t coeffs[1024];
} newhope_poly;

void BOTAN_DLL newhope_keygen(uint8_t *send, newhope_poly *sk, RandomNumberGenerator& rng);
void BOTAN_DLL newhope_sharedb(uint8_t *sharedkey, uint8_t *send, const uint8_t *received, RandomNumberGenerator& rng);
void BOTAN_DLL newhope_shareda(uint8_t *sharedkey, const newhope_poly *ska, const uint8_t *received);


/*
* This is just exposed for testing
*/
void BOTAN_DLL newhope_hash(uint8_t *output, const uint8_t *input, size_t inputByteLen);


}

#endif
