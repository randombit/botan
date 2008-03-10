/*************************************************
* AEP Interface Header File                      *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_EXT_HW_AEP_H__
#define BOTAN_EXT_HW_AEP_H__

#include <botan/types.h>

namespace Botan {

namespace AEP {

const u32bit MAX_MODULO_BITS = 2048;

const u32bit ALREADY_INIT = 0x10000191;

extern "C" {

u32bit AEP_Initialize(void*);
u32bit AEP_Finalize();

u32bit AEP_OpenConnection(u32bit*);
u32bit AEP_CloseConnection(u32bit);

u32bit AEP_ModExp(u32bit, const void*, const void*, const void*, void*,
                  u32bit*);
u32bit AEP_ModExpCrt(u32bit, const void*, const void*, const void*,
                     const void*, const void*, const void*, void*,
                     u32bit*);

u32bit AEP_GenRandom(u32bit, u32bit, u32bit, void*, u32bit*);

typedef u32bit (*AEP_get_bignum_size_fn)(void*, u32bit*);
typedef u32bit (*AEP_read_bignum_fn)(void*, u32bit, byte*);
typedef u32bit (*AEP_write_bignum_fn)(void*, u32bit, byte*);

u32bit AEP_SetBNCallBacks(AEP_get_bignum_size_fn, AEP_read_bignum_fn,
                          AEP_write_bignum_fn);

}

}

}

#endif
