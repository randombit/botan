/*
* Hooks for application level policies on TLS connections
* (C) 2004-2006,2013 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2022 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_POLICY_H_
#define BOTAN_TLS_POLICY_H_

#include <botan/tls_ciphersuite.h>
#include <botan/tls_extensions.h>
#include <botan/tls_signature_scheme.h>
#include <botan/tls_version.h>
#include <chrono>
#include <map>
#include <optional>
#include <vector>

namespace Botan {

class Public_Key;

namespace TLS {

/**
* TLS Policy Base Class
* Inherit and overload as desired to suit local policy concerns
*/
class BOTAN_PUBLIC_API(2, 0) Policy {
   public:
      /**
      * Allow ssl key log file
      * @note If function returns true, then Callbacks::tls_ssl_key_log_data
      *       will be invoked containing secret information for logging purposes
      */
      virtual bool allow_ssl_key_log_file() const;

      /**
      * Returns a list of ciphers we are willing to negotiate, in
      * order of preference.
      */
      virtual std::vector<std::string> allowed_ciphers() const;

      /**
      * Returns a list of hash algorithms we are willing to use for
      * signatures, in order of preference.
      */
      virtual std::vector<std::string> allowed_signature_hashes() const;

      /**
      * Returns a list of MAC algorithms we are willing to use.
      */
      virtual std::vector<std::string> allowed_macs() const;

      /**
      * Returns a list of key exchange algorithms we are willing to
      * use, in order of preference. Allowed values: DH, empty string
      * (representing RSA using server certificate key)
      */
      virtual std::vector<std::string> allowed_key_exchange_methods() const;

      /**
      * Returns a list of signature algorithms we are willing to
      * use, in order of preference.
      */
      virtual std::vector<std::string> allowed_signature_methods() const;

      virtual std::vector<Signature_Scheme> allowed_signature_schemes() const;

      /**
      * Return a list of schemes we are willing to accept
      */
      virtual std::vector<Signature_Scheme> acceptable_signature_schemes() const;

      /**
      * Return a list of schemes we are willing to accept for signatures in
      * certificates.
      *
      * By default, the same restrictions as in acceptable_signature_schemes()
      * apply.
      *
      * @return std::nullopt if the same restrictions as defined in
      *         acceptable_signature_schemes() should apply
      */
      virtual std::optional<std::vector<Signature_Scheme>> acceptable_certificate_signature_schemes() const;

      /**
      * The minimum signature strength we will accept
      *
      * Returning 80 allows RSA 1024 and SHA-1. Values larger than 80 disable
      * SHA-1 support. Returning 110 allows RSA 2048. Return 128 to force ECC
      * (P-256) or large (~3000 bit) RSA keys.
      *
      * Default is 110
      */
      virtual size_t minimum_signature_strength() const;

      /**
      * Return if certificate revocation info (CRL/OCSP) is required
      *
      * If true, certificates won't be trusted unless a valid CRL or OCSP
      * response was examined.
      *
      * Default: true
      */
      virtual bool require_cert_revocation_info() const;

      bool allowed_signature_method(std::string_view sig_method) const;
      bool allowed_signature_hash(std::string_view hash) const;

      /**
      * Return a list of ECC curve and DH group TLS identifiers we are willing
      * to use, in order of preference. The default ordering puts the best
      * performing ECC first.
      *
      * Default: Group_Params::X25519, Group_Params::SECP256R1,
      *          Group_Params::BRAINPOOL256R1, Group_Params::SECP384R1,
      *          Group_Params::BRAINPOOL384R1, Group_Params::SECP521R1,
      *          Group_Params::BRAINPOOL512R1, Group_Params::FFDHE_2048,
      *          Group_Params::FFDHE_3072, Group_Params::FFDHE_4096,
      *          Group_Params::FFDHE_6144, Group_Params::FFDHE_8192
      *
      * No other values are currently defined.
      */
      virtual std::vector<Group_Params> key_exchange_groups() const;

      /**
      * Return a list of groups to provide prepared key share offers in the
      * initial client hello for. Groups in this list must be reflected in
      * key_exchange_groups() and in the same order.
      * If an empty list is returned, no prepared key share offers are sent
      * and the decision of the group to use is left to the server.
      *
      * Default: the most preferred group from key_exchange_groups().
      *
      * @note Has an effect on TLS 1.3 clients, only.
      */
      virtual std::vector<Group_Params> key_exchange_groups_to_offer() const;

      /**
      * Request that ECC curve points are sent compressed
      *
      * Signals that we prefer ECC points to be compressed when transmitted to
      * us. The other party may not support ECC point compression and therefore
      * may still send points uncompressed.
      *
      * Note that the certificate used during authentication must also follow
      * the other party's preference.
      *
      * @note Support for EC point compression is deprecated and will be removed
      *       in a future major release. TLS 1.3 does not support point compression
      *       at all (see RFC 8446 4.2.8.2)
      */
      virtual bool use_ecc_point_compression() const;

      /**
      * Select a key exchange group to use, from the list of groups sent by the
      * peer. In TLS 1.3 handshakes the peer might have provided cryptographic material
      * for a subset of its available groups. Choosing a group for which no share was
      * provided will result in an additional round trip. If none are acceptable, return
      * Group_Params::NONE.
      *
      * By default this will try to optimize for less round trips even if this results
      * in the usage of a less preferred group.
      */
      virtual Group_Params choose_key_exchange_group(const std::vector<Group_Params>& supported_by_peer,
                                                     const std::vector<Group_Params>& offered_by_peer) const;

      /**
      * Allow renegotiation even if the counterparty doesn't support the secure
      * renegotiation extension.
      *
      * Default: false
      *
      * @warning Changing this to true exposes you to injected plaintext
      *          attacks. Read RFC 5746 for background.
      *
      * @note Has no effect for TLS 1.3 connections.
      */
      virtual bool allow_insecure_renegotiation() const;

      /**
      * The protocol dictates that the first 32 bits of the random
      * field are the current time in seconds. However this allows
      * client fingerprinting attacks. Set to false to disable, in
      * which case random bytes will be used instead.
      *
      * Default: true
      */
      virtual bool include_time_in_hello_random() const;

      /**
      * Consulted by server side. If true, allows clients to initiate a new
      * handshake
      *
      * If this function returns true, a server will accept a client-initiated
      * renegotiation attempt. Otherwise it will send the client a non-fatal
      * TLS::AlertType::NoRenegotiation alert.
      *
      * Default: false
      *
      * @note Has no effect for TLS 1.3 connections.
      */
      virtual bool allow_client_initiated_renegotiation() const;

      /**
      * Consulted by client side. If true, allows servers to initiate a new
      * handshake
      *
      * If this function returns true, a client will accept a server-initiated
      * renegotiation attempt. Otherwise it will send the server a non-fatal
      * TLS::AlertType::NoRenegotiation alert.
      *
      * Default: false
      *
      * @note Has no effect for TLS 1.3 connections.
      */
      virtual bool allow_server_initiated_renegotiation() const;

      /**
      * If true, a request to renegotiate will close the connection with
      * a fatal alert. Otherwise, a warning alert is sent.
      *
      * @sa allow_client_initiated_renegotiation
      * @sa allow_server_initiated_renegotiation
      *
      * Default: false
      *
      * @note Has no effect for TLS 1.3 connections.
      */
      virtual bool abort_connection_on_undesired_renegotiation() const;

      /**
       * Only resume sessions when their original protocol version matches
       * the current version exactly.
       *
       * Default: true
       */
      virtual bool only_resume_with_exact_version() const;

      /**
      * Allow TLS v1.2
      */
      virtual bool allow_tls12() const;

      /**
      * Allow TLS v1.3
      */
      virtual bool allow_tls13() const;

      /**
      * Allow DTLS v1.2
      */
      virtual bool allow_dtls12() const;

      /**
      * For ephemeral Diffie-Hellman key exchange, the server sends a group
      * parameter. Return the 2 Byte TLS group identifier specifying the group
      * parameter a server should use.
      *
      * Default: 2048 bit IETF IPsec group ("modp/ietf/2048")
      *
      * @note Has no effect for TLS 1.3 connections.
      */
      virtual Group_Params default_dh_group() const;

      /**
      * Return the minimum DH group size we're willing to use
      *
      * Return the minimum size in bits for a Diffie-Hellman group that a client
      * will accept. Due to the design of the protocol the client has only two
      * options - accept the group, or reject it with a fatal alert then attempt
      * to reconnect after disabling ephemeral Diffie-Hellman.
      *
      * Default: 2048 bits
      */
      virtual size_t minimum_dh_group_size() const;

      /**
      * For ECDSA authenticated ciphersuites, the smallest key size the
      * client will accept.
      * This policy is currently only enforced on the server by the client.
      *
      * Default: 256
      */
      virtual size_t minimum_ecdsa_group_size() const;

      /**
      * Return the minimum ECDH group size we're willing to use
      * for key exchange
      *
      * Default 255, allowing x25519 and larger
      * x25519 is the smallest curve we will negotiate
      * P-521 is the largest
      */
      virtual size_t minimum_ecdh_group_size() const;

      /**
      * Return the minimum bit size we're willing to accept for RSA
      * key exchange or server signatures.
      *
      * It does not place any requirements on the size of any RSA signature(s)
      * which were used to check the server certificate. This is only
      * concerned with the server's public key.
      *
      * Default is 2048 which is smallest RSA key size still secure
      * for medium term security.
      */
      virtual size_t minimum_rsa_bits() const;

      /**
      * Allows the policy to examine peer public keys. Throw an exception if the
      * key should be rejected. Default implementation checks against policy
      * values minimum_dh_group_size(), minimum_rsa_bits(),
      * minimum_ecdsa_group_size(), and minimum_ecdh_group_size().
      *
      * Override if you'd like to perform some other kind of test on (or logging
      * of) the peer's keys.
      */
      virtual void check_peer_key_acceptable(const Public_Key& public_key) const;

      /**
      * The PSK suites work using an identifier along with a shared secret. If
      * this function returns true, when an identifier that the server does not
      * recognize is provided by a client, a random shared secret will be
      * generated in such a way that a client should not be able to tell the
      * difference between the identifier not being known and the secret being
      * wrong. This can help protect against some username probing attacks. If
      * it returns false, the server will instead send an
      * TLS::AlertType::UnknownPSKIdentity alert when an unknown identifier is
      * used.
      *
      * Default: false
      */
      virtual bool hide_unknown_users() const;

      /**
      * Defines the maximum number of session tickets a client might
      * offer in a single resumption attempt. Must be greater than 0.
      *
      * TODO: Currently, the TLS 1.3 client implementation supports
      *       exactly one ticket per handshake. RFC 8446 allows for
      *       an arbitrary amount, though.
      *
      * Default: 1
      *
      * @note Has an effect on TLS 1.3 connections, only.
      */
      virtual size_t maximum_session_tickets_per_client_hello() const;

      /**
      * Return the allowed lifetime of a session ticket. If 0, session
      * tickets do not expire until the session ticket key rolls over.
      * For TLS 1.3 session tickets the lifetime must not be longer than
      * seven days. Expired session tickets cannot be used to resume a
      * session.
      *
      * Default: 1 day
      */
      virtual std::chrono::seconds session_ticket_lifetime() const;

      /**
       * Decides whether stored session tickets should be used multiple
       * times (until their lifetime runs out). This might allow passive
       * observers to correlate connections (RFC 8446 Appendix C.4). This
       * has no effect on TLS 1.2 resumptions based on session IDs as those
       * are negotiated in the clear anyway.
       *
       * Default: false
       */
      virtual bool reuse_session_tickets() const;

      /**
      * Return the number of new session tickets a TLS 1.3 server should issue
      * automatically upon a successful handshake. Note that applications can
      * use `TLS::Server::send_new_session_tickets()` regardless of this policy.
      *
      * For convenience (and compatibility with the TLS 1.2 behaviour), this
      * returns '1' by default.
      *
      * @note Has an effect on TLS 1.3 connections, only.
      */
      virtual size_t new_session_tickets_upon_handshake_success() const;

      /**
      * If this returns a non-empty vector, and DTLS is negotiated,
      * then we will also attempt to negotiate the SRTP extension from
      * RFC 5764 using the returned values as the profile ids.
      */
      virtual std::vector<uint16_t> srtp_profiles() const;

      /**
      * @return true if and only if we are willing to accept this version
      * Default accepts TLS v1.2 and later or DTLS v1.2 or later.
      */
      virtual bool acceptable_protocol_version(Protocol_Version version) const;

      /**
      * Returns the most recent protocol version we are willing to
      * use, for either TLS or DTLS depending on datagram param.
      * Shouldn't ever need to override this unless you want to allow
      * a user to disable specific TLS versions.
      */
      virtual Protocol_Version latest_supported_version(bool datagram) const;

      /**
      * Allows policy to reject any ciphersuites which are undesirable
      * for whatever reason without having to reimplement ciphersuite_list
      */
      virtual bool acceptable_ciphersuite(const Ciphersuite& suite) const;

      /**
      * Default: true
      *
      * @return true if servers should choose the ciphersuite matching
      *         their highest preference, rather than the clients.
      *         Has no effect on client side.
      */
      virtual bool server_uses_own_ciphersuite_preferences() const;

      /**
      * Indicates whether the encrypt-then-MAC extension should be negotiated
      * (RFC 7366)
      *
      * @note Has no effect for TLS 1.3 connections.
      */
      virtual bool negotiate_encrypt_then_mac() const;

      /**
       * Defines the maximum TLS record length for TLS connections.
       * This is based on the Record Size Limit extension described in RFC 8449.
       * By default (i.e. if std::nullopt is returned), TLS clients will omit
       * this extension altogether.
       *
       * This value may be between 64 and 16385 (TLS 1.3) or 16384 (TLS 1.2).
       *
       * @note This is currently not implemented for TLS 1.2, hence the limit
       *       won't be negotiated by TLS 1.3 clients that support downgrading
       *       to TLS 1.2 (i.e. #allow_tls12() returning true).
       */
      virtual std::optional<uint16_t> record_size_limit() const;

      /**
      * Indicates whether certificate status messages should be supported
      */
      virtual bool support_cert_status_message() const;

      /**
      * Indicate if client certificate authentication is required.
      * If true, then a cert will be requested and if the client does
      * not send a certificate the connection will be closed.
      */
      virtual bool require_client_certificate_authentication() const;

      /**
      * Indicate if client certificate authentication is requested.
      * If true, then a cert will be requested.
      */
      virtual bool request_client_certificate_authentication() const;

      /**
      * Returns a list of accepted certificate types for client authentication
      * in order of preference. See RFC 7250 and RFC 8446 4.4.2 for details.
      * Defaults to X509 only.
      *
      * Note that it is the application's responsibility to provide public keys
      * and/or certificates according to the specification in this list via the
      * Credentials_Manager.
      */
      virtual std::vector<Certificate_Type> accepted_client_certificate_types() const;

      /**
      * Returns a list of accepted certificate types for server authentication
      * in order of preference. See RFC 7250 and RFC 8446 4.4.2 for details.
      * Defaults to X509 only.
      *
      * Note that it is the application's responsibility to provide public keys
      * and/or certificates according to the specification in this list via the
      * Credentials_Manager.
      */
      virtual std::vector<Certificate_Type> accepted_server_certificate_types() const;

      /**
      * If true, then allow a DTLS client to restart a connection to the
      * same server association as described in section 4.2.8 of the DTLS RFC
      */
      virtual bool allow_dtls_epoch0_restart() const;

      /**
      * Return allowed ciphersuites, in order of preference for the provided
      * protocol version.
      *
      * @param version  the exact protocol version to select supported and allowed
      *                 ciphersuites for
      */
      virtual std::vector<uint16_t> ciphersuite_list(Protocol_Version version) const;

      /**
      * @return the default MTU for DTLS
      */
      virtual size_t dtls_default_mtu() const;

      /**
      * @return the initial timeout for DTLS
      */
      virtual size_t dtls_initial_timeout() const;

      /**
      * @return the maximum timeout for DTLS
      */
      virtual size_t dtls_maximum_timeout() const;

      /**
      * @return the maximum size of the certificate chain, in bytes.
      * Return 0 to disable this and accept any size.
      */
      virtual size_t maximum_certificate_chain_size() const;

      /**
      * @note Has no effect for TLS 1.3 connections.
      */
      virtual bool allow_resumption_for_renegotiation() const;

      /**
      * Defines whether or not the middlebox compatibility mode should be
      * used. Enabled by default.
      *
      * RFC 8446 Appendix D.4
      *    [This makes] the TLS 1.3 handshake resemble TLS 1.2 session resumption,
      *    which improves the chance of successfully connecting through middleboxes.
      *
      * Default: true
      *
      * @note Has an effect on TLS 1.3 connections, only.
      */
      virtual bool tls_13_middlebox_compatibility_mode() const;

      /**
       * Hash the RNG output for the client/server hello random. This is a pre-caution
       * to avoid writing "raw" RNG output to the wire.
       *
       * There's not normally a reason to disable this, except when deterministic output
       * is required for testing.
       *
       * Default: true
       */
      virtual bool hash_hello_random() const;

      /**
      * Convert this policy to a printable format.
      * @param o stream to be printed to
      */
      virtual void print(std::ostream& o) const;

      /**
      * Convert this policy to a printable format.
      * Same as calling `print` on a ostringstream and reading o.str()
      */
      std::string to_string() const;

      virtual ~Policy() = default;
};

typedef Policy Default_Policy;

/**
* NSA Suite B 128-bit security level (RFC 6460)
*
* @warning As of August 2015 NSA indicated only the 192-bit Suite B
* should be used for all classification levels.
*/
class BOTAN_PUBLIC_API(2, 0) NSA_Suite_B_128 : public Policy {
   public:
      BOTAN_DEPRECATED("This suite is no longer approved") NSA_Suite_B_128() = default;

      std::vector<std::string> allowed_ciphers() const override { return std::vector<std::string>({"AES-128/GCM"}); }

      std::vector<std::string> allowed_signature_hashes() const override {
         return std::vector<std::string>({"SHA-256"});
      }

      std::vector<std::string> allowed_macs() const override { return std::vector<std::string>({"AEAD"}); }

      std::vector<std::string> allowed_key_exchange_methods() const override {
         return std::vector<std::string>({"ECDH"});
      }

      std::vector<std::string> allowed_signature_methods() const override {
         return std::vector<std::string>({"ECDSA"});
      }

      std::vector<Group_Params> key_exchange_groups() const override { return {Group_Params::SECP256R1}; }

      size_t minimum_signature_strength() const override { return 128; }

      bool allow_tls12() const override { return true; }

      bool allow_tls13() const override { return false; }

      bool allow_dtls12() const override { return false; }
};

/**
* NSA Suite B 192-bit security level (RFC 6460)
*/
class BOTAN_PUBLIC_API(2, 7) NSA_Suite_B_192 : public Policy {
   public:
      std::vector<std::string> allowed_ciphers() const override { return std::vector<std::string>({"AES-256/GCM"}); }

      std::vector<std::string> allowed_signature_hashes() const override {
         return std::vector<std::string>({"SHA-384"});
      }

      std::vector<std::string> allowed_macs() const override { return std::vector<std::string>({"AEAD"}); }

      std::vector<std::string> allowed_key_exchange_methods() const override {
         return std::vector<std::string>({"ECDH"});
      }

      std::vector<std::string> allowed_signature_methods() const override {
         return std::vector<std::string>({"ECDSA"});
      }

      std::vector<Group_Params> key_exchange_groups() const override { return {Group_Params::SECP384R1}; }

      size_t minimum_signature_strength() const override { return 192; }

      bool allow_tls12() const override { return true; }

      bool allow_tls13() const override { return false; }

      bool allow_dtls12() const override { return false; }
};

/**
* BSI TR-02102-2 Policy
*/
class BOTAN_PUBLIC_API(2, 0) BSI_TR_02102_2 : public Policy {
   public:
      std::vector<std::string> allowed_ciphers() const override {
         return std::vector<std::string>(
            {"AES-256/GCM", "AES-128/GCM", "AES-256/CCM", "AES-128/CCM", "AES-256", "AES-128"});
      }

      std::vector<std::string> allowed_signature_hashes() const override {
         return std::vector<std::string>({"SHA-512", "SHA-384", "SHA-256"});
      }

      std::vector<std::string> allowed_macs() const override {
         return std::vector<std::string>({"AEAD", "SHA-384", "SHA-256"});
      }

      std::vector<std::string> allowed_key_exchange_methods() const override {
         return std::vector<std::string>({"ECDH", "DH", "ECDHE_PSK"});
      }

      std::vector<std::string> allowed_signature_methods() const override {
         return std::vector<std::string>({"ECDSA", "RSA", "DSA"});
      }

      std::vector<Group_Params> key_exchange_groups() const override {
         return std::vector<Group_Params>({Group_Params::BRAINPOOL512R1,
                                           Group_Params::BRAINPOOL384R1,
                                           Group_Params::BRAINPOOL256R1,
                                           Group_Params::SECP521R1,
                                           Group_Params::SECP384R1,
                                           Group_Params::SECP256R1,
                                           Group_Params::FFDHE_4096,
                                           Group_Params::FFDHE_3072});
      }

      size_t minimum_signature_strength() const override { return 120; }

      bool allow_insecure_renegotiation() const override { return false; }

      bool allow_server_initiated_renegotiation() const override { return true; }

      bool server_uses_own_ciphersuite_preferences() const override { return true; }

      bool negotiate_encrypt_then_mac() const override { return true; }

      size_t minimum_rsa_bits() const override { return 3000; }

      size_t minimum_dh_group_size() const override { return 3000; }

      size_t minimum_ecdh_group_size() const override { return 250; }

      size_t minimum_ecdsa_group_size() const override { return 250; }

      bool allow_tls12() const override { return true; }

      bool allow_tls13() const override { return true; }

      bool allow_dtls12() const override { return false; }
};

/**
* Policy for DTLS. We require DTLS v1.2 and an AEAD mode.
*/
class BOTAN_PUBLIC_API(2, 0) Datagram_Policy : public Policy {
   public:
      std::vector<std::string> allowed_macs() const override { return std::vector<std::string>({"AEAD"}); }

      bool allow_tls12() const override { return false; }

      bool allow_tls13() const override { return false; }

      bool allow_dtls12() const override { return true; }
};

/*
* This policy requires a secure version of TLS and disables all insecure
* algorithms. It is compatible with other botan TLSes (including those using the
* default policy) and with many other recent implementations. It is a great idea
* to use if you control both sides of the protocol and don't have to worry
* about ancient and/or bizarre TLS implementations.
*/
class BOTAN_PUBLIC_API(2, 0) Strict_Policy : public Policy {
   public:
      std::vector<std::string> allowed_ciphers() const override;

      std::vector<std::string> allowed_signature_hashes() const override;

      std::vector<std::string> allowed_macs() const override;

      std::vector<std::string> allowed_key_exchange_methods() const override;
};

class BOTAN_PUBLIC_API(2, 0) Text_Policy : public Policy {
   public:
      bool allow_ssl_key_log_file() const override;

      std::vector<std::string> allowed_ciphers() const override;

      std::vector<std::string> allowed_signature_hashes() const override;

      std::vector<std::string> allowed_macs() const override;

      std::vector<std::string> allowed_key_exchange_methods() const override;

      std::vector<std::string> allowed_signature_methods() const override;

      std::vector<Group_Params> key_exchange_groups() const override;

      std::vector<Group_Params> key_exchange_groups_to_offer() const override;

      bool use_ecc_point_compression() const override;

      bool allow_tls12() const override;

      bool allow_tls13() const override;

      bool allow_dtls12() const override;

      bool allow_insecure_renegotiation() const override;

      bool include_time_in_hello_random() const override;

      bool allow_client_initiated_renegotiation() const override;
      bool allow_server_initiated_renegotiation() const override;

      bool server_uses_own_ciphersuite_preferences() const override;

      bool negotiate_encrypt_then_mac() const override;

      std::optional<uint16_t> record_size_limit() const override;

      bool support_cert_status_message() const override;

      bool require_client_certificate_authentication() const override;

      std::vector<Certificate_Type> accepted_client_certificate_types() const override;
      std::vector<Certificate_Type> accepted_server_certificate_types() const override;

      size_t minimum_ecdh_group_size() const override;

      size_t minimum_ecdsa_group_size() const override;

      size_t minimum_dh_group_size() const override;

      size_t minimum_rsa_bits() const override;

      size_t minimum_signature_strength() const override;

      size_t dtls_default_mtu() const override;

      size_t dtls_initial_timeout() const override;

      size_t dtls_maximum_timeout() const override;

      bool require_cert_revocation_info() const override;

      bool hide_unknown_users() const override;

      size_t maximum_session_tickets_per_client_hello() const override;

      std::chrono::seconds session_ticket_lifetime() const override;

      bool reuse_session_tickets() const override;

      size_t new_session_tickets_upon_handshake_success() const override;

      bool tls_13_middlebox_compatibility_mode() const override;

      bool hash_hello_random() const override;

      std::vector<uint16_t> srtp_profiles() const override;

      void set(const std::string& key, const std::string& value);

      explicit Text_Policy(std::string_view s);

      explicit Text_Policy(std::istream& in);

   protected:
      std::vector<std::string> get_list(const std::string& key, const std::vector<std::string>& def) const;

      std::vector<Group_Params> read_group_list(std::string_view group_str) const;
      std::vector<Certificate_Type> read_cert_type_list(const std::string& cert_type_str) const;

      size_t get_len(const std::string& key, size_t def) const;

      std::chrono::seconds get_duration(const std::string& key, std::chrono::seconds def) const;

      bool get_bool(const std::string& key, bool def) const;

      std::string get_str(const std::string& key, const std::string& def = "") const;

      bool set_value(const std::string& key, std::string_view val, bool overwrite);

   private:
      std::map<std::string, std::string> m_kv;
};

}  // namespace TLS

}  // namespace Botan

#endif
