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

/**
* This chooses the XOF + hash for NewHope

* The official NewHope specification and reference implementation use
* SHA-3 and SHAKE-128. BoringSSL instead uses SHA-256 and AES-128 in
* CTR mode.
*/
enum class Newhope_Mode {
   SHA3,
   BoringSSL
};

void BOTAN_DLL newhope_keygen(uint8_t *send,
                              newhope_poly *sk,
                              RandomNumberGenerator& rng,
                              Newhope_Mode = Newhope_Mode::SHA3);

void BOTAN_DLL newhope_sharedb(uint8_t *sharedkey,
                               uint8_t *send,
                               const uint8_t *received,
                               RandomNumberGenerator& rng,
                               Newhope_Mode mode = Newhope_Mode::SHA3);

void BOTAN_DLL newhope_shareda(uint8_t *sharedkey,
                               const newhope_poly *ska,
                               const uint8_t *received,
                               Newhope_Mode mode = Newhope_Mode::SHA3);

}

#endif
