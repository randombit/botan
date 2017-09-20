/*
* PMULL hook
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_GCM_PMULL_H_
#define BOTAN_GCM_PMULL_H_

#include <botan/types.h>

namespace Botan {

void gcm_multiply_pmull(uint8_t x[16], const uint8_t H[16]);

}

#endif
