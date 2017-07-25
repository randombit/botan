/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FFI_MP_H__
#define BOTAN_FFI_MP_H__

#include <botan/bigint.h>
#include <botan/internal/ffi_util.h>

extern "C" {

using namespace Botan_FFI;

BOTAN_FFI_DECLARE_STRUCT(botan_mp_struct, Botan::BigInt, 0xC828B9D2);

}

#endif
