/*************************************************
* Low Level MPI Types Header File                *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_MPI_TYPES_H__
#define BOTAN_MPI_TYPES_H__

#include <botan/types.h>

namespace Botan {

#if (BOTAN_MP_WORD_BITS == 8)
  typedef byte word;
#elif (BOTAN_MP_WORD_BITS == 16)
  typedef u16bit word;
#elif (BOTAN_MP_WORD_BITS == 32)
  typedef u32bit word;
#elif (BOTAN_MP_WORD_BITS == 64)
  typedef u64bit word;
#else
  #error BOTAN_MP_WORD_BITS must be 8, 16, 32, or 64
#endif

const word MP_WORD_MASK = ~((word)0);
const word MP_WORD_TOP_BIT = (word)1 << (8*sizeof(word) - 1);
const word MP_WORD_MAX = MP_WORD_MASK;

}

#endif
