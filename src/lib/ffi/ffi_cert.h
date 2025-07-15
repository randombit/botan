/*
* (C) 2025 Jack Lloyd
* (C) 2025 Dominik Schricker
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
   #include <botan/x509_ext.h>
   #include <botan/x509cert.h>
   #include <botan/x509path.h>
   #include <botan/x509self.h>
#endif

extern "C" {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

BOTAN_FFI_DECLARE_STRUCT(botan_x509_cert_params_builder_struct, Botan::X509_Cert_Options, 0x92597C7D);
BOTAN_FFI_DECLARE_STRUCT(botan_x509_pkcs10_req_struct, Botan::PKCS10_Request, 0x87F0690A);
BOTAN_FFI_DECLARE_STRUCT(botan_x509_cert_struct, Botan::X509_Certificate, 0x8F628937);
BOTAN_FFI_DECLARE_STRUCT(botan_x509_crl_struct, Botan::X509_CRL, 0x2C628910);

#endif
}

#endif
