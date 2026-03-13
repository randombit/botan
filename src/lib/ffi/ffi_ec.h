/*
* (C) 2025 Jack Lloyd
* (C) 2025,2026 Dominik Schricker
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FFI_EC_H_
#define BOTAN_FFI_EC_H_

#include <botan/ec_group.h>
#include <botan/internal/ffi_util.h>

extern "C" {

BOTAN_FFI_DECLARE_STRUCT(botan_ec_group_struct, Botan::EC_Group, 0xC5A5DB46);
BOTAN_FFI_DECLARE_STRUCT(botan_ec_scalar_struct, Botan::EC_Scalar, 0x504CC641);
BOTAN_FFI_DECLARE_STRUCT(botan_ec_point_struct, Botan::EC_AffinePoint, 0xE3DAD046);
}

#endif
