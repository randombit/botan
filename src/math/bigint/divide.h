/*************************************************
* Division Header File                           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_DIVISON_ALGORITHM_H__
#define BOTAN_DIVISON_ALGORITHM_H__

#include <botan/bigint.h>

namespace Botan {

void BOTAN_DLL divide(const BigInt&, const BigInt&, BigInt&, BigInt&);

}

#endif
