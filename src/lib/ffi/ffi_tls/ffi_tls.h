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

/* NOLINTBEGIN(*-macro-usage) */

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
#define BOTAN_FFI_TLS_API_VERSION 20260919

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
* Certificates and CRLs passed to the setters are copied and a private key
* is shared with the object, so the handles may be destroyed after the
* call. The object may be shared by
* any number of channels, which keep it alive, and its setters may be called
* at any time; later handshakes see the change. It is not synchronized, so
* modifying it while a channel on another thread uses it is a data race.
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
* All of them are loaded at once and kept in memory for the lifetime of the
* credentials object.
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
* certificates are copied; the key object is shared between the key handle
* and the credentials, so the handle may be destroyed afterwards and a key
* that cannot be exported, such as a hardware backed key, can be used.
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
*        which case an internal system RNG is used. The manager keeps its own
*        reference to a non-NULL rng, so the handle may be destroyed after
*        the call; the RNG object then lives on until the manager and every
*        channel using the manager have been destroyed.
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

/*
* Protocol versions and alerts
*/

/**
* Protocol version codes as used on the wire (Botan::TLS::Protocol_Version).
*/
#define BOTAN_TLS_VERSION_TLS_12 0x0303
#define BOTAN_TLS_VERSION_TLS_13 0x0304

/**
* Alert codes (RFC 8446 section 6, RFC 5246 section 7.2). The values match
* the wire encoding and Botan::TLS::AlertType. A received alert may carry
* any other value as well, because received alert codes are not validated.
*/
/* NOLINTNEXTLINE(*-use-enum-class) */
enum BOTAN_TLS_ALERT {
   BOTAN_TLS_ALERT_CLOSE_NOTIFY = 0,
   BOTAN_TLS_ALERT_UNEXPECTED_MESSAGE = 10,
   BOTAN_TLS_ALERT_BAD_RECORD_MAC = 20,
   BOTAN_TLS_ALERT_RECORD_OVERFLOW = 22,
   BOTAN_TLS_ALERT_HANDSHAKE_FAILURE = 40,
   BOTAN_TLS_ALERT_BAD_CERTIFICATE = 42,
   BOTAN_TLS_ALERT_UNSUPPORTED_CERTIFICATE = 43,
   BOTAN_TLS_ALERT_CERTIFICATE_REVOKED = 44,
   BOTAN_TLS_ALERT_CERTIFICATE_EXPIRED = 45,
   BOTAN_TLS_ALERT_CERTIFICATE_UNKNOWN = 46,
   BOTAN_TLS_ALERT_ILLEGAL_PARAMETER = 47,
   BOTAN_TLS_ALERT_UNKNOWN_CA = 48,
   BOTAN_TLS_ALERT_ACCESS_DENIED = 49,
   BOTAN_TLS_ALERT_DECODE_ERROR = 50,
   BOTAN_TLS_ALERT_DECRYPT_ERROR = 51,
   BOTAN_TLS_ALERT_PROTOCOL_VERSION = 70,
   BOTAN_TLS_ALERT_INSUFFICIENT_SECURITY = 71,
   BOTAN_TLS_ALERT_INTERNAL_ERROR = 80,
   BOTAN_TLS_ALERT_INAPPROPRIATE_FALLBACK = 86,
   BOTAN_TLS_ALERT_USER_CANCELED = 90,
   BOTAN_TLS_ALERT_NO_RENEGOTIATION = 100,
   BOTAN_TLS_ALERT_MISSING_EXTENSION = 109,
   BOTAN_TLS_ALERT_UNSUPPORTED_EXTENSION = 110,
   BOTAN_TLS_ALERT_UNRECOGNIZED_NAME = 112,
   BOTAN_TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE = 113,
   BOTAN_TLS_ALERT_UNKNOWN_PSK_IDENTITY = 115,
   BOTAN_TLS_ALERT_CERTIFICATE_REQUIRED = 116,
   BOTAN_TLS_ALERT_NO_APPLICATION_PROTOCOL = 120 /* NOLINT(*-trailing-comma) */
};

/**
* Return 1 if the protocol version (BOTAN_TLS_VERSION_TLS_12 or
* BOTAN_TLS_VERSION_TLS_13) is compiled into this library (modules tls12
* and tls13 respectively), 0 for any other value. Never fails.
*/
BOTAN_FFI_EXPORT(3, 14) int botan_tls_version_is_available(uint16_t version_code);

/**
* View the name of a ciphersuite code as the library spells it, which is the
* IANA name without the "TLS_" prefix (for example "AES_128_GCM_SHA256" for
* 0x1301). Returns BOTAN_FFI_ERROR_NO_VALUE for a code the library does not
* know.
*/
BOTAN_FFI_EXPORT(3, 14)
int botan_tls_ciphersuite_view_name(uint16_t ciphersuite_code, botan_view_ctx ctx, botan_view_str_fn view);

/*
* TLS callbacks
*
* A callbacks object is the table of functions through which a channel talks
* to the application. It carries no application state: the context pointer
* given to botan_tls_channel_init_client or _init_server is passed as the
* first argument of every callback, so one callbacks object can serve any
* number of channels. A channel copies the table when it is created, so the
* object may be destroyed or modified afterwards without affecting existing
* channels.
*
* All callbacks run synchronously on the thread that called the channel
* function, and the data pointers they receive are valid only during the
* call. A callback returns 0 to continue; any other value aborts the
* connection (see botan_tls_channel_t for the exact consequences).
*/
typedef struct botan_tls_callbacks_struct* botan_tls_callbacks_t;

/**
* Ciphertext to be sent to the peer, in order. The buffer is overwritten
* after the callback returns, so copy it if it cannot be written at once.
*/
typedef int (*botan_tls_emit_data_fn)(void* ctx, const uint8_t data[], size_t len);

/**
* Application data received from the peer. seq_no is the record layer's
* sequence number; it restarts at zero when the keys change (TLS 1.3 key
* update, TLS 1.2 renegotiation). A TLS 1.3 peer may send empty records;
* they are delivered with len 0.
*/
typedef int (*botan_tls_record_received_fn)(void* ctx, uint64_t seq_no, const uint8_t data[], size_t len);

/**
* An alert was received from the peer: alert_code is the alert's code (a
* BOTAN_TLS_ALERT value, or whatever the peer sent) and is_fatal its level.
* When a fatal alert arrives the channel has already been closed. A received
* close_notify is answered with a close_notify after this callback returns.
* Alerts received before the handshake completed are not authenticated.
*/
typedef int (*botan_tls_alert_received_fn)(void* ctx, uint16_t alert_code, int is_fatal);

/**
* The handshake completed and application data may be exchanged
* (Botan::TLS::Callbacks::tls_session_activated): once per connection in
* TLS 1.3, once per (re)negotiation in TLS 1.2. botan_tls_channel_send and
* the channel's getters may be called from inside this callback.
*/
typedef int (*botan_tls_handshake_complete_fn)(void* ctx);

/**
* Create a callbacks object with the three mandatory callbacks; none of them
* may be NULL.
*/
BOTAN_FFI_EXPORT(3, 14)
int botan_tls_callbacks_init(botan_tls_callbacks_t* cb,
                             botan_tls_emit_data_fn emit_data,
                             botan_tls_record_received_fn record_received,
                             botan_tls_alert_received_fn alert_received);

/**
* Set or (with NULL) remove the handshake completion callback.
*/
BOTAN_FFI_EXPORT(3, 14)
int botan_tls_callbacks_set_handshake_complete(botan_tls_callbacks_t cb, botan_tls_handshake_complete_fn fn);

/**
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(3, 14) int botan_tls_callbacks_destroy(botan_tls_callbacks_t cb);

/*
* TLS channels
*
* A channel is a TLS client or server endpoint (Botan::TLS::Client / Server)
* for stream transports. The application moves bytes between the channel
* and its transport:
*
*   bytes from the peer  --> botan_tls_channel_received_data()
*   bytes to the peer    <-- emit_data callback
*   plaintext to send    --> botan_tls_channel_send()
*   plaintext received   <-- record_received callback
*
* Callbacks run from inside botan_tls_channel_init_client (the ClientHello
* is emitted before it returns), received_data, send and close;
* destroy invokes none. The library also emits records of its own (key
* updates, session tickets, alerts), so emit_data may run inside any
* received_data or send call.
*
* Callback failures: a record_received, alert_received or handshake_complete
* callback returning nonzero makes the channel send a fatal internal_error
* alert, close, and the channel function in progress returns
* BOTAN_FFI_ERROR_TLS_ERROR. An emit_data callback returning nonzero marks
* the channel as failed: the function in progress returns
* BOTAN_FFI_ERROR_TLS_ERROR (init_client then creates no channel),
* botan_tls_channel_is_closed returns 1 and further send, received_data and
* close calls return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE.
*
* Re-entrancy: from inside record_received and handshake_complete the
* application may call botan_tls_channel_send and the query functions on
* the same channel. It must not call received_data, close or
* destroy on the channel from inside any of its callbacks, and nothing at
* all from inside emit_data; the library detects these cases and returns
* BOTAN_FFI_ERROR_INVALID_OBJECT_STATE.
*
* Threading: a channel and the callbacks it runs are used by one thread at
* a time. The policy, credentials and session manager it was created with
* may be shared with other channels and threads.
*/
typedef struct botan_tls_channel_struct* botan_tls_channel_t;

/**
* Create a TLS client and start the handshake: the ClientHello is passed to
* emit_data before this function returns.
*
* @param chan the output handle; NULL on failure
* @param callbacks the callbacks table (copied)
* @param ctx passed as the first argument to every callback; may be NULL
* @param policy shared with the channel, which keeps it alive
* @param creds shared with the channel; must contain trust anchors
* @param sessions may be NULL (no resumption); shared with the channel
* @param rng may be NULL (an internal system RNG is used); otherwise
*        shared with the channel, which keeps it alive
* @param server_name the server's DNS name, used for SNI, for hostname
*        verification and as part of the session lookup key; must not be
*        empty (BOTAN_FFI_ERROR_BAD_PARAMETER)
* @param server_port the port, part of the session lookup key; 0 if unknown
* @param offer_version BOTAN_TLS_VERSION_TLS_13, BOTAN_TLS_VERSION_TLS_12,
*        or 0 for the newest version in this build. A version that is not
*        compiled in returns BOTAN_FFI_ERROR_NOT_IMPLEMENTED, one the policy
*        forbids BOTAN_FFI_ERROR_BAD_PARAMETER, any other code
*        BOTAN_FFI_ERROR_BAD_PARAMETER. Offering TLS 1.3 with a policy that
*        also allows TLS 1.2 negotiates either.
* @param alpn_protocols alpn_count NUL-terminated protocol names to offer,
*        most preferred first (e.g. "h2", "http/1.1"); NULL with alpn_count 0
*        offers none
* @param flags must be 0 (reserved); any other value returns
*        BOTAN_FFI_ERROR_BAD_FLAG
*/
BOTAN_FFI_EXPORT(3, 14)
int botan_tls_channel_init_client(botan_tls_channel_t* chan,
                                  botan_tls_callbacks_t callbacks,
                                  void* ctx,
                                  botan_tls_policy_t policy,
                                  botan_tls_credentials_t creds,
                                  botan_tls_session_manager_t sessions,
                                  botan_rng_t rng,
                                  const char* server_name,
                                  uint16_t server_port,
                                  uint16_t offer_version,
                                  const char* const* alpn_protocols,
                                  size_t alpn_count,
                                  uint32_t flags);

/**
* Create a TLS server. Parameters as for the client, except:
* @param creds must contain at least one certificate chain with key; trust
*        anchors are needed only if the policy requests client certificates
* @param alpn_protocols the protocols the server supports, most preferred
*        first; the first one the client also offers is selected. With an
*        empty list client ALPN offers are ignored. If the client offers ALPN
*        and no protocol matches, the handshake fails with
*        BOTAN_TLS_ALERT_NO_APPLICATION_PROTOCOL.
* The protocol version is chosen from the ClientHello within the limits of
* the policy; a policy that allows no version returns
* BOTAN_FFI_ERROR_INVALID_OBJECT_STATE. Nothing is emitted before the first
* received_data call.
*/
BOTAN_FFI_EXPORT(3, 14)
int botan_tls_channel_init_server(botan_tls_channel_t* chan,
                                  botan_tls_callbacks_t callbacks,
                                  void* ctx,
                                  botan_tls_policy_t policy,
                                  botan_tls_credentials_t creds,
                                  botan_tls_session_manager_t sessions,
                                  botan_rng_t rng,
                                  const char* const* alpn_protocols,
                                  size_t alpn_count,
                                  uint32_t flags);

/**
* Feed bytes received from the peer. Any number of callbacks may run before
* this returns. If bytes_needed is not NULL it receives a hint how many more
* bytes are needed to complete the current record (0 on a record boundary,
* and 0 once the channel no longer reads).
*
* Returns BOTAN_FFI_ERROR_TLS_ERROR if the peer's data or a callback caused
* a fatal alert (the alert was emitted and the channel is closed),
* BOTAN_FFI_ERROR_INVALID_INPUT
* or BOTAN_FFI_ERROR_BAD_MAC for undecodable or unauthentic records (also
* with the channel closed). After a fatal alert the channel ignores further
* data and returns 0. After an orderly close_notify exchange a TLS 1.2
* channel still decodes incoming records and reports errors for damaged
* data, while a TLS 1.3 channel ignores them.
*/
BOTAN_FFI_EXPORT(3, 14)
int botan_tls_channel_received_data(botan_tls_channel_t chan, const uint8_t data[], size_t len, size_t* bytes_needed);

/**
* Encrypt and emit application data. Requires botan_tls_channel_is_active()
* == 1, otherwise returns BOTAN_FFI_ERROR_INVALID_OBJECT_STATE. TLS 1.2
* invokes emit_data once per record of at most 16 KiB and emits nothing for
* zero bytes; TLS 1.3 invokes it once with all records of this call (an
* empty record for zero bytes), possibly preceded by a KeyUpdate record.
*/
BOTAN_FFI_EXPORT(3, 14) int botan_tls_channel_send(botan_tls_channel_t chan, const uint8_t data[], size_t len);

/**
* Send a close_notify alert and stop sending. In TLS 1.2 the channel is then
* closed. In TLS 1.3 it keeps reading until the peer's close_notify arrives;
* a Botan peer answers a close_notify with its own at once, so after the
* exchange both sides report botan_tls_channel_is_closed() == 1. Closing a
* closed channel succeeds and emits nothing. A server whose policy allows
* only TLS 1.2 cannot send anything before its first received_data call;
* closing it then emits nothing either, but the channel is closed.
*/
BOTAN_FFI_EXPORT(3, 14) int botan_tls_channel_close(botan_tls_channel_t chan);

/**
* Return 1 once the handshake completed and the peer was authenticated, 0
* before or after a failed handshake, or a negative error code.
*/
BOTAN_FFI_EXPORT(3, 14) int botan_tls_channel_is_handshake_complete(botan_tls_channel_t chan);

/**
* Return 1 if application data can be sent now, 0 otherwise. A TLS 1.3
* server is active before it has verified the client's Finished message;
* use is_handshake_complete to wait for the peer's authentication.
*/
BOTAN_FFI_EXPORT(3, 14) int botan_tls_channel_is_active(botan_tls_channel_t chan);

/**
* Return 1 if the connection is closed in both directions, after a fatal
* alert, or after a transport failure; 0 otherwise.
*/
BOTAN_FFI_EXPORT(3, 14) int botan_tls_channel_is_closed(botan_tls_channel_t chan);

/**
* Return 1 if no more data is expected from the peer (it sent close_notify,
* or the channel is closed). In TLS 1.2 the same as is_closed.
*/
BOTAN_FFI_EXPORT(3, 14) int botan_tls_channel_is_closed_for_reading(botan_tls_channel_t chan);

/**
* Return 1 if no more data may be sent (close_notify was sent, or the
* channel is closed). In TLS 1.2 the same as is_closed.
*/
BOTAN_FFI_EXPORT(3, 14) int botan_tls_channel_is_closed_for_writing(botan_tls_channel_t chan);

/**
* Destroy the channel. Sends nothing and invokes no callback; call
* botan_tls_channel_close first for an orderly shutdown. Returns
* BOTAN_FFI_ERROR_INVALID_OBJECT_STATE when called from inside one of the
* channel's callbacks. Destroying NULL succeeds. Afterwards the ctx pointer
* is no longer used by this channel, and the policy, credentials, session
* manager and rng shared with it are released.
*/
BOTAN_FFI_EXPORT(3, 14) int botan_tls_channel_destroy(botan_tls_channel_t chan);

/* NOLINTEND(*-macro-usage) */

#ifdef __cplusplus
}
#endif

#endif
