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
/* NOLINTNEXTLINE(*-macro-usage) */
#define BOTAN_FFI_TLS_API_VERSION 20260916

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

/*
* TLS credentials
*
* A credentials object holds what a channel needs to authenticate the peer
* and itself: trust anchors and CRLs for verifying the peer's certificate
* chain, and certificate chains with private keys for authenticating this
* side (as a server, or as a client when the server requests a client
* certificate).
*
* Everything passed to the setters is copied, so the certificate, CRL and
* key handles may be destroyed after the call. Configure the object before
* passing it to a channel and do not call its setters afterwards; it may
* then be shared by any number of channels, which keep it alive.
*/
typedef struct botan_tls_credentials_struct* botan_tls_credentials_t;

/**
* Create an empty credentials object with no trust anchors and no
* certificate chains.
*/
BOTAN_FFI_EXPORT(3, 14) int botan_tls_credentials_init(botan_tls_credentials_t* creds);

/**
* Add a certificate (copied) as a trust anchor for verifying the peer.
*/
BOTAN_FFI_EXPORT(3, 14)
int botan_tls_credentials_add_trusted_cert(botan_tls_credentials_t creds, botan_x509_cert_t cert);

/**
* Add a CRL (copied) to the revocation data consulted when verifying the
* peer. Note that the default policy requires revocation information for
* the peer's certificates (require_cert_revocation_info), so without CRLs
* or stapled OCSP responses verification fails unless the policy relaxes
* that requirement.
*/
BOTAN_FFI_EXPORT(3, 14) int botan_tls_credentials_add_crl(botan_tls_credentials_t creds, botan_x509_crl_t crl);

/**
* Add every certificate found in the files below the directory path
* (searched recursively; files that do not contain a certificate are
* skipped) as a trust anchor, as Botan::Certificate_Store_In_Memory does.
* Returns BOTAN_FFI_ERROR_BAD_PARAMETER if no certificate was found, which
* includes a directory that does not exist or cannot be read, and
* BOTAN_FFI_ERROR_NOT_IMPLEMENTED in a build without filesystem support.
*/
BOTAN_FFI_EXPORT(3, 14) int botan_tls_credentials_add_trusted_dir(botan_tls_credentials_t creds, const char* path);

/**
* Also trust the certificates in the operating system's certificate store
* (Botan::System_Certificate_Store). Returns BOTAN_FFI_ERROR_NOT_IMPLEMENTED
* in a build without the certstor_system module.
*/
BOTAN_FFI_EXPORT(3, 14) int botan_tls_credentials_use_system_store(botan_tls_credentials_t creds);

/**
* Add a certificate chain, leaf first, together with the private key of the
* leaf certificate. The chain must contain at least one certificate. The
* certificates are copied; the key is copied by re-encoding it as a PKCS #8
* PrivateKeyInfo (Private_Key::private_key_info), so a key that cannot be
* exported, such as a hardware backed key, is rejected with the error code
* of the exception it throws.
*
* Returns BOTAN_FFI_ERROR_BAD_PARAMETER if chain_len is 0 or the key does
* not belong to the leaf certificate.
*
* Several chains may be added, for instance one with an RSA and one with an
* ECDSA key, or chains for different server names. A channel uses the first
* chain whose key type the peer accepts. A server that has a chain whose
* leaf certificate matches the server name the client asked for offers only
* such chains. If the peer named acceptable certificate authorities, a chain
* with a certificate issued by one of them is preferred.
*/
BOTAN_FFI_EXPORT(3, 14)
int botan_tls_credentials_add_cert_chain(botan_tls_credentials_t creds,
                                         const botan_x509_cert_t* chain,
                                         size_t chain_len,
                                         botan_privkey_t key);

/**
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(3, 14) int botan_tls_credentials_destroy(botan_tls_credentials_t creds);

/*
* TLS session managers
*
* A session manager stores the information needed to resume sessions. It
* may be shared by any number of channels, which keep it alive; the
* in-memory manager synchronizes its own state.
*/
typedef struct botan_tls_session_manager_struct* botan_tls_session_manager_t;

/**
* Create a session manager that keeps sessions in memory
* (Botan::TLS::Session_Manager_In_Memory).
*
* @param mgr the output handle; set to NULL on failure
* @param rng the random number generator the manager uses; may be NULL, in
*        which case an internal system RNG is used. A non-NULL rng is not
*        copied: it must stay valid until the manager and every channel
*        using the manager have been destroyed.
* @param max_sessions the maximum number of sessions kept, 0 for no limit
*/
BOTAN_FFI_EXPORT(3, 14)
int botan_tls_session_manager_init_memory(botan_tls_session_manager_t* mgr, botan_rng_t rng, size_t max_sessions);

/**
* Create a session manager that stores nothing
* (Botan::TLS::Session_Manager_Noop), which disables session resumption.
*
* @param mgr the output handle; set to NULL on failure
*/
BOTAN_FFI_EXPORT(3, 14) int botan_tls_session_manager_init_noop(botan_tls_session_manager_t* mgr);

/**
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(3, 14) int botan_tls_session_manager_destroy(botan_tls_session_manager_t mgr);

#ifdef __cplusplus
}
#endif

#endif
