/*************************************************
* Lookup Table Management Header File            *
* (C) 1999-2007 The Botan Project                *
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
void add_algorithm(BlockCipher*);
void add_algorithm(StreamCipher*);
void add_algorithm(HashFunction*);
void add_algorithm(MessageAuthenticationCode*);
void add_algorithm(S2K*);
void add_algorithm(BlockCipherModePaddingMethod*);

}

#endif
