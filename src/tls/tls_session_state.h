/*
* TLS Session Management
* (C) 2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef TLS_SESSION_STATE_H_
#define TLS_SESSION_STATE_H_

#include <botan/x509cert.h>
#include <botan/tls_magic.h>
#include <botan/secmem.h>
#include <botan/hex.h>
#include <map>
#include <ctime>

namespace Botan {

/**
* Class representing a TLS session state
*/
class BOTAN_DLL TLS_Session_Params
   {
   public:

      /**
      * Uninitialized session
      */
      TLS_Session_Params() :
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
      TLS_Session_Params(const MemoryRegion<byte>& session_id,
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
      TLS_Session_Params(const byte ber[], size_t ber_len);

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
      * Is secure negotiation supported?
      */
      bool secure_negotiation() const
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

/**
* TLS_Session_Manager is an interface to systems which can save
* session parameters for support session resumption.
*
* Implementations should strive to be thread safe
*/
class BOTAN_DLL TLS_Session_Manager
   {
   public:
      /**
      * Try to load a saved session
      * @param session_id the session identifier we are trying to resume
      * @param params will be set to the saved session data (if found),
               or not modified if not found
      * @return true if params was modified
      */
      virtual bool find(const MemoryVector<byte>& session_id,
                        TLS_Session_Params& params) = 0;

      /**
      * Prohibit resumption of this session. Effectively an erase.
      */
      virtual void prohibit_resumption(const MemoryVector<byte>& session_id) = 0;

      /**
      * Save a session on a best effort basis; the manager may not in
      * fact be able to save the session for whatever reason, this is
      * not an error. Caller cannot assume that calling save followed
      * immediately by find will result in a successful lookup.
      *
      * @param session_id the session identifier
      * @param params to save
      */
      virtual void save(const TLS_Session_Params& params) = 0;

      virtual ~TLS_Session_Manager() {}
   };

/**
* A simple implementation of TLS_Session_Manager that just saves
* values in memory, with no persistance abilities
*
* @todo add locking
*/
class BOTAN_DLL TLS_Session_Manager_In_Memory : public TLS_Session_Manager
   {
   public:
      /**
      * @param max_sessions a hint on the maximum number of sessions
      *        to save at any one time. (If zero, don't cap at all)
      * @param session_lifetime sesions are expired after this many
      *         seconds have elapsed.
      */
      TLS_Session_Manager_In_Memory(size_t max_sessions = 1000,
                                    size_t session_lifetime = 300) :
         max_sessions(max_sessions),
         session_lifetime(session_lifetime)
            {}

      bool find(const MemoryVector<byte>& session_id,
                TLS_Session_Params& params);

      void prohibit_resumption(const MemoryVector<byte>& session_id);

      void save(const TLS_Session_Params& session_data);

   private:
      size_t max_sessions, session_lifetime;
      std::map<std::string, TLS_Session_Params> sessions;
   };

}

#endif
