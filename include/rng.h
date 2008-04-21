/*************************************************
* Global RNG Header File                         *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_GLOBAL_RNG_H__
#define BOTAN_GLOBAL_RNG_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* RNG Access and Seeding Functions               *
*************************************************/
namespace Global_RNG {

BOTAN_DLL void randomize(byte[], u32bit);
BOTAN_DLL byte random();

BOTAN_DLL void add_entropy(const byte[], u32bit);
BOTAN_DLL void add_entropy(EntropySource&, bool = true);

BOTAN_DLL u32bit seed(bool = true, u32bit = 256);

BOTAN_DLL void add_es(EntropySource*, bool = true);

}

}

#endif
