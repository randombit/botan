/*
* TLS Session
* (C) 2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef TLS_SESSION_STATE_H__
#define TLS_SESSION_STATE_H__

#include <botan/x509cert.h>
#include <botan/tls_magic.h>
#include <botan/secmem.h>

namespace Botan {

/**
* Class representing a TLS session state
*/
class BOTAN_DLL TLS_Session
   {
   public:

      /**
      * Uninitialized session
      */
      TLS_Session() :
         m_start_time(0),
         m_version(0),
         m_ciphersuite(0),
         m_compression_method(0),
         m_connection_side(static_cast<Connection_Side>(0)),
         m_secure_renegotiation_supported(false),
         m_fragment_size(0)
            {}

      /**
      * New session (sets session start time)
      */
      TLS_Session(const MemoryRegion<byte>& session_id,
                  const MemoryRegion<byte>& master_secret,
                  Version_Code version,
                  u16bit ciphersuite,
                  byte compression_method,
                  Connection_Side side,
                  bool secure_renegotiation_supported,
                  size_t fragment_size,
                  const std::vector<X509_Certificate>& peer_certs,
                  const std::string& sni_hostname = "",
                  const std::string& srp_identifier = "");

      /**
      * Load a session from BER (created by BER_encode)
      */
      TLS_Session(const byte ber[], size_t ber_len);

      /**
      * Encode this session data for storage
      * @warning if the master secret is compromised so is the
      * session traffic
      */
      SecureVector<byte> BER_encode() const;

      /**
      * Get the version of the saved session
      */
      Version_Code version() const
         { return static_cast<Version_Code>(m_version); }

      /**
      * Get the major version of the saved session
      */
      byte major_version() const { return get_byte(0, m_version); }

      /**
      * Get the minor version of the saved session
      */
      byte minor_version() const { return get_byte(1, m_version); }

      /**
      * Get the ciphersuite of the saved session
      */
      u16bit ciphersuite() const { return m_ciphersuite; }

      /**
      * Get the compression method used in the saved session
      */
      byte compression_method() const { return m_compression_method; }

      /**
      * Get which side of the connection the resumed session we are/were
      * acting as.
      */
      Connection_Side side() const { return m_connection_side; }

      /**
      * Get the SNI hostname (if sent by the client in the initial handshake)
      */
      std::string sni_hostname() const { return m_sni_hostname; }

      /**
      * Get the SRP identity (if sent by the client in the initial handshake)
      */
      std::string srp_identifier() const { return m_srp_identifier; }

      /**
      * Get the saved master secret
      */
      const SecureVector<byte>& master_secret() const
         { return m_master_secret; }

      /**
      * Get the session identifier
      */
      const MemoryVector<byte>& session_id() const
         { return m_identifier; }

      /**
      * Get the negotiated maximum fragment size (or 0 if default)
      */
      size_t fragment_size() const { return m_fragment_size; }

      /**
      * Is secure renegotiation supported?
      */
      bool secure_renegotiation() const
         { return m_secure_renegotiation_supported; }

      /**
      * Get the time this session began (seconds since Epoch)
      */
      u64bit start_time() const { return m_start_time; }

   private:
      enum { TLS_SESSION_PARAM_STRUCT_VERSION = 1 };

      u64bit m_start_time;

      MemoryVector<byte> m_identifier;
      SecureVector<byte> m_master_secret;

      u16bit m_version;
      u16bit m_ciphersuite;
      byte m_compression_method;
      Connection_Side m_connection_side;

      bool m_secure_renegotiation_supported;
      size_t m_fragment_size;

      MemoryVector<byte> m_peer_certificate; // optional
      std::string m_sni_hostname; // optional
      std::string m_srp_identifier; // optional
   };

}

#endif
