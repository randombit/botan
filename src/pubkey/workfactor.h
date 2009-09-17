/*
* Public Key Work Factor Functions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_WORKFACTOR_H__
#define BOTAN_WORKFACTOR_H__

#include <botan/types.h>

namespace Botan {

/*
* Work Factor Estimates
*/
BOTAN_DLL u32bit dl_work_factor(u32bit prime_group_size);

}

#endif
