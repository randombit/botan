/*
* (C) 2025 Jack Lloyd
* (C) 2025 Dominik Schricker
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FFI_OID_H_
#define BOTAN_FFI_OID_H_

#include <botan/asn1_obj.h>
#include <botan/internal/ffi_util.h>

extern "C" {

BOTAN_FFI_DECLARE_STRUCT(botan_asn1_oid_struct, Botan::OID, 0x9217DA20);
}

#endif
