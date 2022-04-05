/*
* Hooks for application level policies on TLS connections
* (C) 2004-2006,2013 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_POLICY_H_
#define BOTAN_TLS_POLICY_H_

#include <botan/tls_version.h>
#include <botan/tls_algos.h>
#include <botan/tls_ciphersuite.h>
#include <optional>
#include <vector>
#include <map>

namespace Botan {

class Public_Key;

namespace TLS {

/**
* TLS Policy Base Class
* Inherit and overload as desired to suit local policy concerns
*/
class BOTAN_PUBLIC_API(2,0) Policy
   {
   public:

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
      * The minimum signature strength we will accept
      * Returning 80 allows RSA 1024 and SHA-1. Values larger than 80 disable SHA-1 support.
      * Returning 110 allows RSA 2048.
      * Return 128 to force ECC (P-256) or large (~3000 bit) RSA keys.
      * Default is 110
      */
      virtual size_t minimum_signature_strength() const;

      /**
      * Return if cert revocation info (CRL/OCSP) is required
      * If true, validation will fail unless a valid CRL or OCSP response
      * was examined.
      */
      virtual bool require_cert_revocation_info() const;

      bool allowed_signature_method(const std::string& sig_method) const;
      bool allowed_signature_hash(const std::string& hash) const;

      /**
      * Return list of ECC curves and FFDHE groups we are willing to
      * use in order of preference.
      */
      virtual std::vector<Group_Params> key_exchange_groups() const;

      /**
      * TLS 1.3 specific
      * Return a list of groups to provide prepared key share offers in the
      * initial client hello for. Groups in this list must be reflected in
      * key_exchange_groups() and in the same order. By default this returns
      * the most preferred group from key_exchange_groups().
      * If an empty list is returned, no prepared key share offers are sent
      * and the decision of the group to use is left to the server.
      */
      virtual std::vector<Group_Params> key_exchange_groups_to_offer() const;

      /**
      * Request that ECC curve points are sent compressed
      * This does not have an effect on TLS 1.3 as it always uses uncompressed ECC points.
      *
      * RFC 8446 P. 50:
      *    Versions of TLS prior to 1.3 permitted point format
      *    negotiation; TLS 1.3 removes this feature in favor of a single point
      *    format for each curve.
      */
      virtual bool use_ecc_point_compression() const;

      /**
      * Select a key exchange group to use, from the list of groups sent by the
      * peer. If none are acceptable, return Group_Params::NONE
      */
      virtual Group_Params choose_key_exchange_group(const std::vector<Group_Params>& peer_groups) const;

      /**
      * Allow renegotiation even if the counterparty doesn't
      * support the secure renegotiation extension.
      *
      * @warning Changing this to true exposes you to injected
      * plaintext attacks. Read RFC 5746 for background.
      */
      virtual bool allow_insecure_renegotiation() const;

      /**
      * The protocol dictates that the first 32 bits of the random
      * field are the current time in seconds. However this allows
      * client fingerprinting attacks. Set to false to disable, in
      * which case random bytes will be used instead.
      */
      virtual bool include_time_in_hello_random() const;

      /**
      * Consulted by server side. If true, allows clients to initiate a new handshake
      */
      virtual bool allow_client_initiated_renegotiation() const;

      /**
      * Consulted by client side. If true, allows servers to initiate a new handshake
      */
      virtual bool allow_server_initiated_renegotiation() const;

      /**
      * If true, a request to renegotiate will close the connection with
      * a fatal alert. Otherwise, a warning alert is sent.
      */
      virtual bool abort_connection_on_undesired_renegotiation() const;

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

      virtual Group_Params default_dh_group() const;

      /**
      * Return the minimum DH group size we're willing to use
      * Default is currently 1024 (insecure), should be 2048
      */
      virtual size_t minimum_dh_group_size() const;

      /**
      * For ECDSA authenticated ciphersuites, the smallest key size the
      * client will accept.
      * This policy is currently only enforced on the server by the client.
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
      * Throw an exception if you don't like the peer's key.
      * Default impl checks the key size against minimum_rsa_bits, minimum_ecdsa_group_size,
      * or minimum_ecdh_group_size depending on the key's type.
      * Override if you'd like to perform some other kind of test on
      * (or logging of) the peer's keys.
      */
      virtual void check_peer_key_acceptable(const Public_Key& public_key) const;

      /**
      * If this function returns false, unknown PSK identifiers
      * will be rejected with an unknown_psk_identifier alert as soon
      * as the non-existence is identified. Otherwise, a false
      * identifier value will be used and the protocol allowed to
      * proceed, causing the handshake to eventually fail without
      * revealing that the username does not exist on this system.
      */
      virtual bool hide_unknown_users() const;

      /**
      * Return the allowed lifetime of a session ticket. If 0, session
      * tickets do not expire until the session ticket key rolls over.
      * Expired session tickets cannot be used to resume a session.
      */
      virtual uint32_t session_ticket_lifetime() const;

      /**
      * If this returns a non-empty vector, and DTLS is negotiated,
      * then we will also attempt to negotiate the SRTP extension from
      * RFC 5764 using the returned values as the profile ids.
      */
      virtual std::vector<uint16_t> srtp_profiles() const;

      /**
      * @return true if and only if we are willing to accept this version
      * Default accepts TLS v1.0 and later or DTLS v1.2 or later.
      */
      virtual bool acceptable_protocol_version(Protocol_Version version) const;

      /**
      * Returns the more recent protocol version we are willing to
      * use, for either TLS or DTLS depending on datagram param.
      * Shouldn't ever need to override this unless you want to allow
      * a user to disable use of TLS v1.2 (which is *not recommended*)
      */
      virtual Protocol_Version latest_supported_version(bool datagram) const;

      /**
      * Allows policy to reject any ciphersuites which are undesirable
      * for whatever reason without having to reimplement ciphersuite_list
      */
      virtual bool acceptable_ciphersuite(const Ciphersuite& suite) const;

      /**
      * @return true if servers should choose the ciphersuite matching
      *         their highest preference, rather than the clients.
      *         Has no effect on client side.
      */
      virtual bool server_uses_own_ciphersuite_preferences() const;

      /**
      * Indicates whether the encrypt-then-MAC extension should be negotiated
      * (RFC 7366)
      */
      virtual bool negotiate_encrypt_then_mac() const;

      /**
      * TODO: This should probably be removed as it doesn't have an effect on either
      *       TLS 1.2 or 1.3.
      *
      * Indicates whether the extended master secret extension (RFC 7627) should be used.
      *
      * This is always enabled if the client supports TLS 1.2 (the option has no effect).
      * For TLS 1.3 _only_ clients the extension is disabled by default.
      *
      * RFC 8446 Appendix D:
      *   TLS 1.2 and prior supported an "Extended Master Secret" [RFC7627]
      *   extension which digested large parts of the handshake transcript into
      *   the master secret.  Because TLS 1.3 always hashes in the transcript
      *   up to the server Finished, implementations which support both TLS 1.3
      *   and earlier versions SHOULD indicate the use of the Extended Master
      *   Secret extension in their APIs whenever TLS 1.3 is used.
      */
      virtual bool use_extended_master_secret() const;

      /**
       * Defines the maximum TLS record length for TLS connections.
       * This is based on the Record Size Limit extension described in RFC 8449.
       * By default (i.e. if std::nullopt is returned), TLS clients will omit
       * this extension altogether.
       *
       * This value may be between 64 and 16385 (TLS 1.3) or 16384 (TLS 1.2).
       *
       * TODO: This is currently not implemented for TLS 1.2, hence the limit
       *       won't be negotiated by TLS 1.3 clients that support downgrading
       *       to TLS 1.2 (i.e. ::allow_tls12() returning true).
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

      virtual bool allow_resumption_for_renegotiation() const;

      /**
       * Defines whether or not the middlebox compatibility mode should be
       * used.
       *
       * RFC 8446 Appendix D.4
       *    [This makes] the TLS 1.3 handshake resemble TLS 1.2 session resumption,
       *    which improves the chance of successfully connecting through middleboxes.
       *
       * Enabled by default.
       */
      virtual bool tls_13_middlebox_compatibility_mode() const;

      /**
       * Hash the RNG output for the client/server hello random. This is a pre-caution
       * to avoid writing "raw" RNG output to the wire.
       *
       * There's not normally a reason to disable this, except when deterministic output
       * is required for testing.
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
class BOTAN_PUBLIC_API(2,0) NSA_Suite_B_128 : public Policy
   {
   public:
      std::vector<std::string> allowed_ciphers() const override
         { return std::vector<std::string>({"AES-128/GCM"}); }

      std::vector<std::string> allowed_signature_hashes() const override
         { return std::vector<std::string>({"SHA-256"}); }

      std::vector<std::string> allowed_macs() const override
         { return std::vector<std::string>({"AEAD"}); }

      std::vector<std::string> allowed_key_exchange_methods() const override
         { return std::vector<std::string>({"ECDH"}); }

      std::vector<std::string> allowed_signature_methods() const override
         { return std::vector<std::string>({"ECDSA"}); }

      std::vector<Group_Params> key_exchange_groups() const override
         { return {Group_Params::SECP256R1}; }

      size_t minimum_signature_strength() const override { return 128; }

      bool allow_tls12()  const override { return true;  }
      bool allow_tls13()  const override { return false; }
      bool allow_dtls12() const override { return false; }
   };

/**
* NSA Suite B 192-bit security level (RFC 6460)
*/
class BOTAN_PUBLIC_API(2,7) NSA_Suite_B_192 : public Policy
   {
   public:
      std::vector<std::string> allowed_ciphers() const override
         { return std::vector<std::string>({"AES-256/GCM"}); }

      std::vector<std::string> allowed_signature_hashes() const override
         { return std::vector<std::string>({"SHA-384"}); }

      std::vector<std::string> allowed_macs() const override
         { return std::vector<std::string>({"AEAD"}); }

      std::vector<std::string> allowed_key_exchange_methods() const override
         { return std::vector<std::string>({"ECDH"}); }

      std::vector<std::string> allowed_signature_methods() const override
         { return std::vector<std::string>({"ECDSA"}); }

      std::vector<Group_Params> key_exchange_groups() const override
         { return {Group_Params::SECP384R1}; }

      size_t minimum_signature_strength() const override { return 192; }

      bool allow_tls12()  const override { return true;  }
      bool allow_tls13()  const override { return false; }
      bool allow_dtls12() const override { return false; }
   };

/**
* BSI TR-02102-2 Policy
*/
class BOTAN_PUBLIC_API(2,0) BSI_TR_02102_2 : public Policy
   {
   public:
      std::vector<std::string> allowed_ciphers() const override
         {
         return std::vector<std::string>({"AES-256/GCM", "AES-128/GCM", "AES-256/CCM", "AES-128/CCM", "AES-256", "AES-128"});
         }

      std::vector<std::string> allowed_signature_hashes() const override
         {
         return std::vector<std::string>({"SHA-512", "SHA-384", "SHA-256"});
         }

      std::vector<std::string> allowed_macs() const override
         {
         return std::vector<std::string>({"AEAD", "SHA-384", "SHA-256"});
         }

      std::vector<std::string> allowed_key_exchange_methods() const override
         {
         return std::vector<std::string>({"ECDH", "DH", "ECDHE_PSK" });
         }

      std::vector<std::string> allowed_signature_methods() const override
         {
         return std::vector<std::string>({"ECDSA", "RSA", "DSA"});
         }

      std::vector<Group_Params> key_exchange_groups() const override
         {
         return std::vector<Group_Params>({
            Group_Params::BRAINPOOL512R1,
            Group_Params::BRAINPOOL384R1,
            Group_Params::BRAINPOOL256R1,
            Group_Params::SECP384R1,
            Group_Params::SECP256R1,
            Group_Params::FFDHE_4096,
            Group_Params::FFDHE_3072,
            Group_Params::FFDHE_2048
            });
         }

      bool allow_insecure_renegotiation() const override { return false; }
      bool allow_server_initiated_renegotiation() const override { return true; }
      bool server_uses_own_ciphersuite_preferences() const override { return true; }
      bool negotiate_encrypt_then_mac() const override { return true; }

      size_t minimum_rsa_bits() const override { return 2000; }
      size_t minimum_dh_group_size() const override { return 2000; }

      size_t minimum_ecdh_group_size() const override { return 250; }
      size_t minimum_ecdsa_group_size() const override { return 250; }

      bool allow_tls12()  const override { return true;  }
      bool allow_tls13()  const override { return false; }
      bool allow_dtls12() const override { return false; }
   };

/**
* Policy for DTLS. We require DTLS v1.2 and an AEAD mode.
*/
class BOTAN_PUBLIC_API(2,0) Datagram_Policy : public Policy
   {
   public:
      std::vector<std::string> allowed_macs() const override
         { return std::vector<std::string>({"AEAD"}); }

      bool allow_tls12()  const override { return false; }
      bool allow_tls13()  const override { return false; }
      bool allow_dtls12() const override { return true;  }
   };

/*
* This policy requires a secure version of TLS and disables all insecure
* algorithms. It is compatible with other botan TLSes (including those using the
* default policy) and with many other recent implementations. It is a great idea
* to use if you control both sides of the protocol and don't have to worry
* about ancient and/or bizarre TLS implementations.
*/
class BOTAN_PUBLIC_API(2,0) Strict_Policy : public Policy
   {
   public:
      std::vector<std::string> allowed_ciphers() const override;

      std::vector<std::string> allowed_signature_hashes() const override;

      std::vector<std::string> allowed_macs() const override;

      std::vector<std::string> allowed_key_exchange_methods() const override;

      bool allow_tls12()  const override;
      bool allow_tls13()  const override;
      bool allow_dtls12() const override;
   };

class BOTAN_PUBLIC_API(2,0) Text_Policy : public Policy
   {
   public:

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

      bool use_extended_master_secret() const override;

      std::optional<uint16_t> record_size_limit() const override;

      bool support_cert_status_message() const override;

      bool require_client_certificate_authentication() const override;

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

      uint32_t session_ticket_lifetime() const override;

      bool tls_13_middlebox_compatibility_mode() const override;

      bool hash_hello_random() const override;

      std::vector<uint16_t> srtp_profiles() const override;

      void set(const std::string& k, const std::string& v);

      explicit Text_Policy(const std::string& s);

      explicit Text_Policy(std::istream& in);

   protected:

      std::vector<std::string> get_list(const std::string& key,
                                        const std::vector<std::string>& def) const;

      std::vector<Group_Params> read_group_list(const std::string &group_str) const;

      size_t get_len(const std::string& key, size_t def) const;

      bool get_bool(const std::string& key, bool def) const;

      std::string get_str(const std::string& key, const std::string& def = "") const;

      bool set_value(const std::string& key, const std::string& val, bool overwrite);

   private:
      std::map<std::string, std::string> m_kv;
   };

}

}

#endif
