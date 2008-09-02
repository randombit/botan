/*************************************************
* Bit/Word Operations Header File                *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_BIT_OPS_H__
#define BOTAN_BIT_OPS_H__

#include <botan/types.h>

namespace Botan {

/*************************************************
* Simple Bit Manipulation                        *
*************************************************/
bool power_of_2(u64bit);
u32bit high_bit(u64bit);
u32bit low_bit(u64bit);
u32bit significant_bytes(u64bit);
u32bit hamming_weight(u64bit);

}

#endif
