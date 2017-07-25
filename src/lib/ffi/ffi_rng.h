/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FFI_RNG_H__
#define BOTAN_FFI_RNG_H__

#include <botan/rng.h>
#include <botan/internal/ffi_util.h>

extern "C" {

using namespace Botan_FFI;

BOTAN_FFI_DECLARE_STRUCT(botan_rng_struct, Botan::RandomNumberGenerator, 0x4901F9C1);

}

#endif
