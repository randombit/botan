/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FFI_CERT_H_
#define BOTAN_FFI_CERT_H_

#include <botan/internal/ffi_util.h>

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/data_src.h>
   #include <botan/x509_ca.h>
   #include <botan/x509_crl.h>
   #include <botan/x509cert.h>
   #include <botan/x509path.h>
#endif

extern "C" {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

BOTAN_FFI_DECLARE_STRUCT(botan_x509_cert_struct, Botan::X509_Certificate, 0x8F628937);
BOTAN_FFI_DECLARE_STRUCT(botan_x509_crl_struct, Botan::X509_CRL, 0x2C628910);
BOTAN_FFI_DECLARE_STRUCT(botan_x509_crl_entry_struct, Botan::CRL_Entry, 0x4EAA5346);
BOTAN_FFI_DECLARE_STRUCT(botan_x509_general_name_struct, Botan::GeneralName, 0x563654FD);

#endif
}

#endif
