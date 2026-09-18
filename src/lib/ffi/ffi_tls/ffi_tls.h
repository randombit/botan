/*
* TLS interface for the FFI (C89 API)
* (C) 2026 Moritz Schmitt
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FFI_TLS_H_
#define BOTAN_FFI_TLS_H_

#include <botan/ffi.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
* This header is provided by the experimental module ffi_tls, which is not
* part of a default build (configure with --enable-modules=ffi_tls or
* --enable-experimental-features). The functions declared here may change
* incompatibly in a future release until the module is marked stable.
*
* C code can detect the module at compile time by including <botan/build.h>
* and testing BOTAN_HAS_FFI_TLS, and at run time by calling
* botan_ffi_tls_api_version() (declared in ffi.h, always available, returns
* 0 when the module is absent).
*
* The conventions of ffi.h apply: every object is an opaque handle, every
* function returns 0 (BOTAN_FFI_SUCCESS) or a negative BOTAN_FFI_ERROR code,
* no memory ownership crosses the boundary, variable-length outputs use view
* functions, and strings are NUL-terminated.
*/

/**
* The compile time version of the TLS FFI API (YYYYMMDD). Matches the value
* returned by botan_ffi_tls_api_version() and BOTAN_HAS_FFI_TLS in build.h.
*/
#define BOTAN_FFI_TLS_API_VERSION 20260911

/*
* TLS policies
*
* A policy (Botan::TLS::Policy) controls which protocol versions,
* ciphersuites and parameters a TLS channel accepts. A policy object is
* immutable after creation and may be shared between several channels.
*/
typedef struct botan_tls_policy_struct* botan_tls_policy_t;

/**
* Create one of the library's stock policies.
*
* @param policy the output handle; set to NULL on failure
* @param name "default" (Botan::TLS::Policy), "strict" (Strict_Policy) or
*        "bsi_tr_02102_2" (BSI_TR_02102_2); NULL selects "default"
*
* Returns BOTAN_FFI_ERROR_BAD_PARAMETER for an unknown name.
*/
BOTAN_FFI_EXPORT(3, 14) int botan_tls_policy_init(botan_tls_policy_t* policy, const char* name);

/**
* Create a policy from text in the format of Botan::TLS::Text_Policy: one
* "key = value" setting per line, '#' starts a comment, and any key that is
* not mentioned keeps the value of the default policy. See the TLS policy
* section of the handbook for the available keys.
*
* @param policy the output handle; set to NULL on failure
* @param text the policy text
*
* A line that is not of the form "key = value" is rejected with
* BOTAN_FFI_ERROR_INVALID_INPUT. Values are checked only when the policy is
* consulted, so an invalid value (such as a boolean key set to "maybe") is
* reported by a later call that uses the policy, not by this function.
*/
BOTAN_FFI_EXPORT(3, 14) int botan_tls_policy_init_from_text(botan_tls_policy_t* policy, const char* text);

/**
* View the main settings of the policy as text (Botan::TLS::Policy::to_string),
* one "key = value" line per setting, using the key names of Text_Policy.
* Not every setting is included.
*/
BOTAN_FFI_EXPORT(3, 14)
int botan_tls_policy_view_text(botan_tls_policy_t policy, botan_view_ctx ctx, botan_view_str_fn view);

/**
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(3, 14) int botan_tls_policy_destroy(botan_tls_policy_t policy);

#ifdef __cplusplus
}
#endif

#endif
