/*
* (C) 2025 Jack Lloyd
* (C) 2025 Dominik Schricker
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FFI_X509_RPKI_H_
#define BOTAN_FFI_X509_RPKI_H_

#include <botan/internal/ffi_util.h>

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/x509_ext.h>
#endif

extern "C" {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

BOTAN_FFI_DECLARE_STRUCT(botan_x509_ext_as_blocks_struct, Botan::Cert_Extension::ASBlocks, 0xA56348EC);
BOTAN_FFI_DECLARE_STRUCT(botan_x509_ext_ip_addr_blocks_struct, Botan::Cert_Extension::IPAddressBlocks, 0xB489828F);

#endif
}

#endif
