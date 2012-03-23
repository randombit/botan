/*
* TLS Messages
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_MESSAGES_H__
#define BOTAN_TLS_MESSAGES_H__

#include <botan/internal/tls_handshake_state.h>
#include <botan/tls_session.h>
#include <botan/tls_policy.h>
#include <botan/tls_magic.h>
#include <botan/tls_ciphersuite.h>
#include <botan/bigint.h>
#include <botan/pkcs8.h>
#include <botan/x509cert.h>
#include <vector>

namespace Botan {

class Credentials_Manager;

namespace TLS {

class Record_Writer;
class Record_Reader;

/**
* TLS Handshake Message Base Class
*/
class Handshake_Message
   {
   public:
      virtual MemoryVector<byte> serialize() const = 0;
      virtual Handshake_Type type() const = 0;

      Handshake_Message() {}
      virtual ~Handshake_Message() {}
   private:
      Handshake_Message(const Handshake_Message&) {}
      Handshake_Message& operator=(const Handshake_Message&) { return (*this); }
   };

MemoryVector<byte> make_hello_random(RandomNumberGenerator& rng);

/**
* DTLS Hello Verify Request
*/
class Hello_Verify_Request : public Handshake_Message
   {
   public:
      MemoryVector<byte> serialize() const;
      Handshake_Type type() const { return HELLO_VERIFY_REQUEST; }

      MemoryVector<byte> cookie() const { return m_cookie; }

      Hello_Verify_Request(const MemoryRegion<byte>& buf);

      Hello_Verify_Request(const MemoryVector<byte>& client_hello_bits,
                           const std::string& client_identity,
                           const SymmetricKey& secret_key);
   private:
      MemoryVector<byte> m_cookie;
   };

/**
* Client Hello Message
*/
class Client_Hello : public Handshake_Message
   {
   public:
      Handshake_Type type() const { return CLIENT_HELLO; }
      Protocol_Version version() const { return m_version; }
      const MemoryVector<byte>& session_id() const { return m_session_id; }

      std::vector<byte> session_id_vector() const
         {
         std::vector<byte> v;
         v.insert(v.begin(), &m_session_id[0], &m_session_id[m_session_id.size()]);
         return v;
         }

      const std::vector<std::pair<std::string, std::string> >& supported_algos() const
         { return m_supported_algos; }

      const std::vector<std::string>& supported_ecc_curves() const
         { return m_supported_curves; }

      std::vector<u16bit> ciphersuites() const { return m_suites; }
      std::vector<byte> compression_methods() const { return m_comp_methods; }

      const MemoryVector<byte>& random() const { return m_random; }

      std::string sni_hostname() const { return m_hostname; }

      std::string srp_identifier() const { return m_srp_identifier; }

      bool secure_renegotiation() const { return m_secure_renegotiation; }

      const MemoryVector<byte>& renegotiation_info()
         { return m_renegotiation_info; }

      bool offered_suite(u16bit ciphersuite) const;

      bool next_protocol_notification() const { return m_next_protocol; }

      size_t fragment_size() const { return m_fragment_size; }

      bool supports_session_ticket() const { return m_supports_session_ticket; }

      const MemoryRegion<byte>& session_ticket() const
         { return m_session_ticket; }

      Client_Hello(Record_Writer& writer,
                   Handshake_Hash& hash,
                   const Policy& policy,
                   RandomNumberGenerator& rng,
                   const MemoryRegion<byte>& reneg_info,
                   bool next_protocol = false,
                   const std::string& hostname = "",
                   const std::string& srp_identifier = "");

      Client_Hello(Record_Writer& writer,
                   Handshake_Hash& hash,
                   const Policy& policy,
                   RandomNumberGenerator& rng,
                   const Session& resumed_session,
                   bool next_protocol = false);

      Client_Hello(const MemoryRegion<byte>& buf,
                   Handshake_Type type);

   private:
      MemoryVector<byte> serialize() const;
      void deserialize(const MemoryRegion<byte>& buf);
      void deserialize_sslv2(const MemoryRegion<byte>& buf);

      Protocol_Version m_version;
      MemoryVector<byte> m_session_id, m_random;
      std::vector<u16bit> m_suites;
      std::vector<byte> m_comp_methods;
      std::string m_hostname;
      std::string m_srp_identifier;
      bool m_next_protocol;

      size_t m_fragment_size;
      bool m_secure_renegotiation;
      MemoryVector<byte> m_renegotiation_info;

      std::vector<std::pair<std::string, std::string> > m_supported_algos;
      std::vector<std::string> m_supported_curves;

      bool m_supports_session_ticket;
      MemoryVector<byte> m_session_ticket;
   };

/**
* Server Hello Message
*/
class Server_Hello : public Handshake_Message
   {
   public:
      Handshake_Type type() const { return SERVER_HELLO; }
      Protocol_Version version() { return s_version; }
      const MemoryVector<byte>& session_id() const { return m_session_id; }
      u16bit ciphersuite() const { return suite; }
      byte compression_method() const { return comp_method; }

      std::vector<byte> session_id_vector() const
         {
         std::vector<byte> v;
         v.insert(v.begin(), &m_session_id[0], &m_session_id[m_session_id.size()]);
         return v;
         }

      bool secure_renegotiation() const { return m_secure_renegotiation; }

      bool next_protocol_notification() const { return m_next_protocol; }

      bool supports_session_ticket() const { return m_supports_session_ticket; }

      const std::vector<std::string>& next_protocols() const
         { return m_next_protocols; }

      size_t fragment_size() const { return m_fragment_size; }

      const MemoryVector<byte>& renegotiation_info()
         { return m_renegotiation_info; }

      const MemoryVector<byte>& random() const { return s_random; }

      Server_Hello(Record_Writer& writer,
                   Handshake_Hash& hash,
                   Protocol_Version version,
                   const Client_Hello& other,
                   const std::vector<std::string>& available_cert_types,
                   const Policy& policies,
                   bool client_has_secure_renegotiation,
                   const MemoryRegion<byte>& reneg_info,
                   bool client_has_npn,
                   const std::vector<std::string>& next_protocols,
                   RandomNumberGenerator& rng);

      Server_Hello(Record_Writer& writer,
                   Handshake_Hash& hash,
                   const MemoryRegion<byte>& session_id,
                   Protocol_Version ver,
                   u16bit ciphersuite,
                   byte compression,
                   size_t max_fragment_size,
                   bool client_has_secure_renegotiation,
                   const MemoryRegion<byte>& reneg_info,
                   bool client_supports_session_tickets,
                   bool client_has_npn,
                   const std::vector<std::string>& next_protocols,
                   RandomNumberGenerator& rng);

      Server_Hello(const MemoryRegion<byte>& buf);
   private:
      MemoryVector<byte> serialize() const;

      Protocol_Version s_version;
      MemoryVector<byte> m_session_id, s_random;
      u16bit suite;
      byte comp_method;

      size_t m_fragment_size;
      bool m_secure_renegotiation;
      MemoryVector<byte> m_renegotiation_info;

      bool m_next_protocol;
      std::vector<std::string> m_next_protocols;
      bool m_supports_session_ticket;
   };

/**
* Client Key Exchange Message
*/
class Client_Key_Exchange : public Handshake_Message
   {
   public:
      Handshake_Type type() const { return CLIENT_KEX; }

      const SecureVector<byte>& pre_master_secret() const
         { return pre_master; }

      Client_Key_Exchange(Record_Writer& output,
                          Handshake_State* state,
                          Credentials_Manager& creds,
                          const std::vector<X509_Certificate>& peer_certs,
                          RandomNumberGenerator& rng);

      Client_Key_Exchange(const MemoryRegion<byte>& buf,
                          const Handshake_State* state,
                          Credentials_Manager& creds,
                          const Policy& policy,
                          RandomNumberGenerator& rng);

   private:
      MemoryVector<byte> serialize() const { return key_material; }

      SecureVector<byte> key_material, pre_master;
   };

/**
* Certificate Message
*/
class Certificate : public Handshake_Message
   {
   public:
      Handshake_Type type() const { return CERTIFICATE; }
      const std::vector<X509_Certificate>& cert_chain() const { return m_certs; }

      size_t count() const { return m_certs.size(); }
      bool empty() const { return m_certs.empty(); }

      Certificate(Record_Writer& writer,
                  Handshake_Hash& hash,
                  const std::vector<X509_Certificate>& certs);

      Certificate(const MemoryRegion<byte>& buf);
   private:
      MemoryVector<byte> serialize() const;

      std::vector<X509_Certificate> m_certs;
   };

/**
* Certificate Request Message
*/
class Certificate_Req : public Handshake_Message
   {
   public:
      Handshake_Type type() const { return CERTIFICATE_REQUEST; }

      const std::vector<std::string>& acceptable_cert_types() const
         { return cert_key_types; }

      std::vector<X509_DN> acceptable_CAs() const { return names; }

      std::vector<std::pair<std::string, std::string> > supported_algos() const
         { return m_supported_algos; }

      Certificate_Req(Record_Writer& writer,
                      Handshake_Hash& hash,
                      const Policy& policy,
                      const std::vector<X509_Certificate>& allowed_cas,
                      Protocol_Version version);

      Certificate_Req(const MemoryRegion<byte>& buf,
                      Protocol_Version version);
   private:
      MemoryVector<byte> serialize() const;

      std::vector<X509_DN> names;
      std::vector<std::string> cert_key_types;

      std::vector<std::pair<std::string, std::string> > m_supported_algos;
   };

/**
* Certificate Verify Message
*/
class Certificate_Verify : public Handshake_Message
   {
   public:
      Handshake_Type type() const { return CERTIFICATE_VERIFY; }

      /**
      * Check the signature on a certificate verify message
      * @param cert the purported certificate
      * @param state the handshake state
      */
      bool verify(const X509_Certificate& cert,
                  Handshake_State* state);

      Certificate_Verify(Record_Writer& writer,
                         Handshake_State* state,
                         RandomNumberGenerator& rng,
                         const Private_Key* key);

      Certificate_Verify(const MemoryRegion<byte>& buf,
                         Protocol_Version version);
   private:
      MemoryVector<byte> serialize() const;

      std::string sig_algo; // sig algo used to create signature
      std::string hash_algo; // hash used to create signature
      MemoryVector<byte> signature;
   };

/**
* Finished Message
*/
class Finished : public Handshake_Message
   {
   public:
      Handshake_Type type() const { return FINISHED; }

      MemoryVector<byte> verify_data() const
         { return verification_data; }

      bool verify(Handshake_State* state,
                  Connection_Side side);

      Finished(Record_Writer& writer,
               Handshake_State* state,
               Connection_Side side);

      Finished(const MemoryRegion<byte>& buf);
   private:
      MemoryVector<byte> serialize() const;

      Connection_Side side;
      MemoryVector<byte> verification_data;
   };

/**
* Hello Request Message
*/
class Hello_Request : public Handshake_Message
   {
   public:
      Handshake_Type type() const { return HELLO_REQUEST; }

      Hello_Request(Record_Writer& writer);
      Hello_Request(const MemoryRegion<byte>& buf);
   private:
      MemoryVector<byte> serialize() const;
   };

/**
* Server Key Exchange Message
*/
class Server_Key_Exchange : public Handshake_Message
   {
   public:
      Handshake_Type type() const { return SERVER_KEX; }

      const MemoryVector<byte>& params() const { return m_params; }

      bool verify(const X509_Certificate& cert,
                  Handshake_State* state) const;

      // Only valid for certain kex types
      const Private_Key& server_kex_key() const;

      Server_Key_Exchange(Record_Writer& writer,
                          Handshake_State* state,
                          const Policy& policy,
                          Credentials_Manager& creds,
                          RandomNumberGenerator& rng,
                          const Private_Key* signing_key = 0);

      Server_Key_Exchange(const MemoryRegion<byte>& buf,
                          const std::string& kex_alg,
                          const std::string& sig_alg,
                          Protocol_Version version);

      ~Server_Key_Exchange() { delete m_kex_key; }
   private:
      MemoryVector<byte> serialize() const;

      Private_Key* m_kex_key;

      MemoryVector<byte> m_params;

      std::string m_sig_algo; // sig algo used to create signature
      std::string m_hash_algo; // hash used to create signature
      MemoryVector<byte> m_signature;
   };

/**
* Server Hello Done Message
*/
class Server_Hello_Done : public Handshake_Message
   {
   public:
      Handshake_Type type() const { return SERVER_HELLO_DONE; }

      Server_Hello_Done(Record_Writer& writer, Handshake_Hash& hash);
      Server_Hello_Done(const MemoryRegion<byte>& buf);
   private:
      MemoryVector<byte> serialize() const;
   };

/**
* Next Protocol Message
*/
class Next_Protocol : public Handshake_Message
   {
   public:
      Handshake_Type type() const { return NEXT_PROTOCOL; }

      std::string protocol() const { return m_protocol; }

      Next_Protocol(Record_Writer& writer,
                    Handshake_Hash& hash,
                    const std::string& protocol);

      Next_Protocol(const MemoryRegion<byte>& buf);
   private:
      MemoryVector<byte> serialize() const;

      std::string m_protocol;
   };

class New_Session_Ticket : public Handshake_Message
   {
   public:
      Handshake_Type type() const { return NEW_SESSION_TICKET; }

      u32bit ticket_lifetime_hint() const { return m_ticket_lifetime_hint; }
      const MemoryVector<byte>& ticket() const { return m_ticket; }

      New_Session_Ticket(Record_Writer& writer,
                         Handshake_Hash& hash,
                         const MemoryRegion<byte>& ticket,
                         u32bit lifetime = 0);

      New_Session_Ticket(Record_Writer& writer,
                         Handshake_Hash& hash);

      New_Session_Ticket(const MemoryRegion<byte>& buf);
   private:
      MemoryVector<byte> serialize() const;

      u32bit m_ticket_lifetime_hint;
      MemoryVector<byte> m_ticket;
   };

}

}

#endif
