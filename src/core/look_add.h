/*************************************************
* Lookup Table Management Header File            *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_LOOKUP_MANGEMENT_H__
#define BOTAN_LOOKUP_MANGEMENT_H__

#include <botan/base.h>
#include <botan/mode_pad.h>
#include <botan/s2k.h>

namespace Botan {

/*************************************************
* Add an algorithm to the lookup table           *
*************************************************/
BOTAN_DLL void add_algorithm(BlockCipher*);
BOTAN_DLL void add_algorithm(StreamCipher*);
BOTAN_DLL void add_algorithm(HashFunction*);
BOTAN_DLL void add_algorithm(MessageAuthenticationCode*);
BOTAN_DLL void add_algorithm(S2K*);
BOTAN_DLL void add_algorithm(BlockCipherModePaddingMethod*);

}

#endif
