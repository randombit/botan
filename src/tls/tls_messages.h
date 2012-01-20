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
#include <botan/tls_suites.h>
#include <botan/bigint.h>
#include <botan/pkcs8.h>
#include <botan/x509cert.h>
#include <vector>

namespace Botan {

class Record_Writer;
class Record_Reader;

/**
* TLS Handshake Message Base Class
*/
class Handshake_Message
   {
   public:
      void send(Record_Writer& writer, TLS_Handshake_Hash& hash) const;

      virtual Handshake_Type type() const = 0;

      virtual ~Handshake_Message() {}
   private:
      Handshake_Message& operator=(const Handshake_Message&) { return (*this); }
      virtual MemoryVector<byte> serialize() const = 0;
   };

MemoryVector<byte> make_hello_random(RandomNumberGenerator& rng);

/**
* Client Hello Message
*/
class Client_Hello : public Handshake_Message
   {
   public:
      Handshake_Type type() const { return CLIENT_HELLO; }
      Version_Code version() const { return m_version; }
      const MemoryVector<byte>& session_id() const { return m_session_id; }

      std::vector<byte> session_id_vector() const
         {
         std::vector<byte> v;
         v.insert(v.begin(), &m_session_id[0], &m_session_id[m_session_id.size()]);
         return v;
         }

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

      Client_Hello(Record_Writer& writer,
                   TLS_Handshake_Hash& hash,
                   const TLS_Policy& policy,
                   RandomNumberGenerator& rng,
                   const MemoryRegion<byte>& reneg_info,
                   bool next_protocol = false,
                   const std::string& hostname = "",
                   const std::string& srp_identifier = "");

      Client_Hello(Record_Writer& writer,
                   TLS_Handshake_Hash& hash,
                   RandomNumberGenerator& rng,
                   const TLS_Session& resumed_session,
                   bool next_protocol = false);

      Client_Hello(const MemoryRegion<byte>& buf,
                   Handshake_Type type)
         {
         if(type == CLIENT_HELLO)
            deserialize(buf);
         else
            deserialize_sslv2(buf);
         }

   private:
      MemoryVector<byte> serialize() const;
      void deserialize(const MemoryRegion<byte>& buf);
      void deserialize_sslv2(const MemoryRegion<byte>& buf);

      Version_Code m_version;
      MemoryVector<byte> m_session_id, m_random;
      std::vector<u16bit> m_suites;
      std::vector<byte> m_comp_methods;
      std::string m_hostname;
      std::string m_srp_identifier;
      bool m_next_protocol;

      size_t m_fragment_size;
      bool m_secure_renegotiation;
      MemoryVector<byte> m_renegotiation_info;
   };

/**
* Server Hello Message
*/
class Server_Hello : public Handshake_Message
   {
   public:
      Handshake_Type type() const { return SERVER_HELLO; }
      Version_Code version() { return s_version; }
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

      const std::vector<std::string>& next_protocols() const
         { return m_next_protocols; }

      size_t fragment_size() const { return m_fragment_size; }

      const MemoryVector<byte>& renegotiation_info()
         { return m_renegotiation_info; }

      const MemoryVector<byte>& random() const { return s_random; }

      Server_Hello(Record_Writer& writer,
                   TLS_Handshake_Hash& hash,
                   Version_Code version,
                   const Client_Hello& other,
                   const std::vector<X509_Certificate>& certs,
                   const TLS_Policy& policies,
                   bool client_has_secure_renegotiation,
                   const MemoryRegion<byte>& reneg_info,
                   bool client_has_npn,
                   const std::vector<std::string>& next_protocols,
                   RandomNumberGenerator& rng);

      Server_Hello(Record_Writer& writer,
                   TLS_Handshake_Hash& hash,
                   const MemoryRegion<byte>& session_id,
                   Version_Code ver,
                   u16bit ciphersuite,
                   byte compression,
                   size_t max_fragment_size,
                   bool client_has_secure_renegotiation,
                   const MemoryRegion<byte>& reneg_info,
                   bool client_has_npn,
                   const std::vector<std::string>& next_protocols,
                   RandomNumberGenerator& rng);

      Server_Hello(const MemoryRegion<byte>& buf);
   private:
      MemoryVector<byte> serialize() const;

      Version_Code s_version;
      MemoryVector<byte> m_session_id, s_random;
      u16bit suite;
      byte comp_method;

      size_t m_fragment_size;
      bool m_secure_renegotiation;
      MemoryVector<byte> m_renegotiation_info;

      bool m_next_protocol;
      std::vector<std::string> m_next_protocols;
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

      SecureVector<byte> pre_master_secret(RandomNumberGenerator& rng,
                                           const Private_Key* key,
                                           Version_Code version);

      Client_Key_Exchange(Record_Writer& output,
                          TLS_Handshake_Hash& hash,
                          RandomNumberGenerator& rng,
                          const Public_Key* my_key,
                          Version_Code using_version,
                          Version_Code pref_version);

      Client_Key_Exchange(const MemoryRegion<byte>& buf,
                          const TLS_Cipher_Suite& suite,
                          Version_Code using_version);
   private:
      MemoryVector<byte> serialize() const;

      SecureVector<byte> key_material, pre_master;
      bool include_length;
   };

/**
* Certificate Message
*/
class Certificate : public Handshake_Message
   {
   public:
      Handshake_Type type() const { return CERTIFICATE; }
      const std::vector<X509_Certificate>& cert_chain() const { return certs; }

      size_t count() const { return certs.size(); }
      bool empty() const { return certs.empty(); }

      Certificate(Record_Writer& writer,
                  TLS_Handshake_Hash& hash,
                  const std::vector<X509_Certificate>& certs);

      Certificate(const MemoryRegion<byte>& buf);
   private:
      MemoryVector<byte> serialize() const;

      std::vector<X509_Certificate> certs;
   };

/**
* Certificate Request Message
*/
class Certificate_Req : public Handshake_Message
   {
   public:
      Handshake_Type type() const { return CERTIFICATE_REQUEST; }

      std::vector<byte> acceptable_types() const { return cert_types; }
      std::vector<X509_DN> acceptable_CAs() const { return names; }

      Certificate_Req(Record_Writer& writer,
                      TLS_Handshake_Hash& hash,
                      const std::vector<X509_Certificate>& allowed_cas,
                      Version_Code version);

      Certificate_Req(const MemoryRegion<byte>& buf,
                      Version_Code version);
   private:
      MemoryVector<byte> serialize() const;

      std::vector<X509_DN> names;
      std::vector<byte> cert_types;
      MemoryVector<byte> sig_and_hash_algos; // for TLS 1.2
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
                  TLS_Handshake_State* state);

      Certificate_Verify(Record_Writer& writer,
                         TLS_Handshake_State* state,
                         RandomNumberGenerator& rng,
                         const Private_Key* key);

      Certificate_Verify(const MemoryRegion<byte>& buf,
                         Version_Code version);
   private:
      MemoryVector<byte> serialize() const;

      TLS_Ciphersuite_Algos sig_algo; // sig algo used to create signature
      TLS_Ciphersuite_Algos hash_algo; // hash used to create signature
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

      bool verify(TLS_Handshake_State* state,
                  Connection_Side side);

      Finished(Record_Writer& writer,
               TLS_Handshake_State* state,
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
      Public_Key* key() const;

      bool verify(const X509_Certificate& cert,
                  TLS_Handshake_State* state) const;

      Server_Key_Exchange(Record_Writer& writer,
                          TLS_Handshake_State* state,
                          RandomNumberGenerator& rng,
                          const Private_Key* priv_key);

      Server_Key_Exchange(const MemoryRegion<byte>& buf,
                          TLS_Ciphersuite_Algos kex_alg,
                          TLS_Ciphersuite_Algos sig_alg,
                          Version_Code version);
   private:
      MemoryVector<byte> serialize() const;
      MemoryVector<byte> serialize_params() const;

      std::vector<BigInt> params;

      TLS_Ciphersuite_Algos sig_algo; // sig algo used to create signature
      TLS_Ciphersuite_Algos hash_algo; // hash used to create signature
      MemoryVector<byte> signature;
   };

/**
* Server Hello Done Message
*/
class Server_Hello_Done : public Handshake_Message
   {
   public:
      Handshake_Type type() const { return SERVER_HELLO_DONE; }

      Server_Hello_Done(Record_Writer& writer, TLS_Handshake_Hash& hash);
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
                    TLS_Handshake_Hash& hash,
                    const std::string& protocol);

      Next_Protocol(const MemoryRegion<byte>& buf);
   private:
      MemoryVector<byte> serialize() const;

      std::string m_protocol;
   };

}

#endif
