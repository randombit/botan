/*
* System RNG interface
* (C) 2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SYSTEM_RNG_H__
#define BOTAN_SYSTEM_RNG_H__

#include <botan/rng.h>

namespace Botan {

BOTAN_DLL RandomNumberGenerator& system_rng();

}

#endif
