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
struct BOTAN_DLL TLS_Session_Params
   {
   enum { TLS_SESSION_PARAM_STRUCT_VERSION = 1 };

   /**
   * Uninitialized session
   */
   TLS_Session_Params() :
      session_start_time(0),
      version(0),
      ciphersuite(0),
      compression_method(0),
      connection_side(static_cast<Connection_Side>(0))
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
                      const X509_Certificate* cert = 0,
                      const std::string& sni_hostname = "",
                      const std::string& srp_identity = "");

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

   time_t session_start_time;

   MemoryVector<byte> session_id;
   SecureVector<byte> master_secret;

   u16bit version;
   u16bit ciphersuite;
   byte compression_method;
   Connection_Side connection_side;

   MemoryVector<byte> peer_certificate; // optional
   std::string sni_hostname; // optional
   std::string srp_identity; // optional
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
      * @param which side of the connection we are
      * @return true if params was modified
      */
      virtual bool find(const MemoryVector<byte>& session_id,
                        TLS_Session_Params& params,
                        Connection_Side side) = 0;

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
                TLS_Session_Params& params,
                Connection_Side side);

      void prohibit_resumption(const MemoryVector<byte>& session_id);

      void save(const TLS_Session_Params& session_data);

   private:
      size_t max_sessions, session_lifetime;
      std::map<std::string, TLS_Session_Params> sessions;
   };

}

#endif
