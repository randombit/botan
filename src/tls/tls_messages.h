/*
* TLS Messages
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_MESSAGES_H__
#define BOTAN_TLS_MESSAGES_H__

#include <botan/internal/tls_handshake_hash.h>
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
class HandshakeMessage
   {
   public:
      void send(Record_Writer& writer, TLS_Handshake_Hash& hash) const;

      virtual Handshake_Type type() const = 0;

      virtual ~HandshakeMessage() {}
   private:
      HandshakeMessage& operator=(const HandshakeMessage&) { return (*this); }
      virtual MemoryVector<byte> serialize() const = 0;
      virtual void deserialize(const MemoryRegion<byte>&) = 0;
   };

/**
* Client Hello Message
*/
class Client_Hello : public HandshakeMessage
   {
   public:
      Handshake_Type type() const { return CLIENT_HELLO; }
      Version_Code version() const { return c_version; }
      const MemoryVector<byte>& session_id() const { return sess_id; }

      std::vector<byte> session_id_vector() const
         {
         std::vector<byte> v;
         v.insert(v.begin(), &sess_id[0], &sess_id[sess_id.size()]);
         return v;
         }

      std::vector<u16bit> ciphersuites() const { return suites; }
      std::vector<byte> compression_methods() const { return comp_methods; }

      const MemoryVector<byte>& random() const { return c_random; }

      std::string sni_hostname() const { return requested_hostname; }

      std::string srp_identifier() const { return requested_srp_id; }

      bool secure_renegotiation() const { return has_secure_renegotiation; }

      const MemoryVector<byte>& renegotiation_info()
         { return renegotiation_info_bits; }

      bool offered_suite(u16bit ciphersuite) const;

      Client_Hello(Record_Writer& writer,
                   TLS_Handshake_Hash& hash,
                   const TLS_Policy& policy,
                   RandomNumberGenerator& rng,
                   const MemoryRegion<byte>& reneg_info,
                   const std::string& hostname = "",
                   const std::string& srp_identifier = "");

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

      Version_Code c_version;
      MemoryVector<byte> sess_id, c_random;
      std::vector<u16bit> suites;
      std::vector<byte> comp_methods;
      std::string requested_hostname;
      std::string requested_srp_id;

      bool has_secure_renegotiation;
      MemoryVector<byte> renegotiation_info_bits;
   };

/**
* Server Hello Message
*/
class Server_Hello : public HandshakeMessage
   {
   public:
      Handshake_Type type() const { return SERVER_HELLO; }
      Version_Code version() { return s_version; }
      const MemoryVector<byte>& session_id() const { return sess_id; }
      u16bit ciphersuite() const { return suite; }
      byte compression_method() const { return comp_method; }

      std::vector<byte> session_id_vector() const
         {
         std::vector<byte> v;
         v.insert(v.begin(), &sess_id[0], &sess_id[sess_id.size()]);
         return v;
         }

      bool secure_renegotiation() const { return has_secure_renegotiation; }

      const MemoryVector<byte>& renegotiation_info()
         { return renegotiation_info_bits; }

      const MemoryVector<byte>& random() const { return s_random; }

      Server_Hello(Record_Writer& writer,
                   TLS_Handshake_Hash& hash,
                   const TLS_Policy& policies,
                   RandomNumberGenerator& rng,
                   bool client_has_secure_renegotiation,
                   const MemoryRegion<byte>& reneg_info,
                   const std::vector<X509_Certificate>& certs,
                   const Client_Hello& other,
                   const MemoryRegion<byte>& session_id,
                   Version_Code version);

      Server_Hello(Record_Writer& writer,
                   TLS_Handshake_Hash& hash,
                   RandomNumberGenerator& rng,
                   bool client_has_secure_renegotiation,
                   const MemoryRegion<byte>& reneg_info,
                   const MemoryRegion<byte>& session_id,
                   u16bit ciphersuite,
                   byte compression,
                   Version_Code ver);

      Server_Hello(const MemoryRegion<byte>& buf) { deserialize(buf); }
   private:
      MemoryVector<byte> serialize() const;
      void deserialize(const MemoryRegion<byte>&);

      Version_Code s_version;
      MemoryVector<byte> sess_id, s_random;
      u16bit suite;
      byte comp_method;

      bool has_secure_renegotiation;
      MemoryVector<byte> renegotiation_info_bits;
   };

/**
* Client Key Exchange Message
*/
class Client_Key_Exchange : public HandshakeMessage
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
                          const CipherSuite& suite,
                          Version_Code using_version);
   private:
      MemoryVector<byte> serialize() const;
      void deserialize(const MemoryRegion<byte>&);

      SecureVector<byte> key_material, pre_master;
      bool include_length;
   };

/**
* Certificate Message
*/
class Certificate : public HandshakeMessage
   {
   public:
      Handshake_Type type() const { return CERTIFICATE; }
      const std::vector<X509_Certificate>& cert_chain() const { return certs; }

      size_t count() const { return certs.size(); }
      bool empty() const { return certs.empty(); }

      Certificate(Record_Writer& writer,
                  TLS_Handshake_Hash& hash,
                  const std::vector<X509_Certificate>& certs);

      Certificate(const MemoryRegion<byte>& buf) { deserialize(buf); }
   private:
      MemoryVector<byte> serialize() const;
      void deserialize(const MemoryRegion<byte>&);
      std::vector<X509_Certificate> certs;
   };

/**
* Certificate Request Message
*/
class Certificate_Req : public HandshakeMessage
   {
   public:
      Handshake_Type type() const { return CERTIFICATE_REQUEST; }

      std::vector<Certificate_Type> acceptable_types() const { return types; }
      std::vector<X509_DN> acceptable_CAs() const { return names; }

      Certificate_Req(Record_Writer& writer,
                      TLS_Handshake_Hash& hash,
                      const std::vector<X509_Certificate>& allowed_cas,
                      const std::vector<Certificate_Type>& types =
                         std::vector<Certificate_Type>());

      Certificate_Req(const MemoryRegion<byte>& buf) { deserialize(buf); }
   private:
      MemoryVector<byte> serialize() const;
      void deserialize(const MemoryRegion<byte>&);

      std::vector<X509_DN> names;
      std::vector<Certificate_Type> types;
   };

/**
* Certificate Verify Message
*/
class Certificate_Verify : public HandshakeMessage
   {
   public:
      Handshake_Type type() const { return CERTIFICATE_VERIFY; }

      /**
      * Check the signature on a certificate verify message
      * @param cert the purported certificate
      * @param hash the running handshake message hash
      * @param version the version number we negotiated
      * @param master_secret the session key (only used if version is SSL_V3)
      */
      bool verify(const X509_Certificate& cert,
                  TLS_Handshake_Hash& hash,
                  Version_Code version,
                  const SecureVector<byte>& master_secret);

      Certificate_Verify(Record_Writer& writer,
                         TLS_Handshake_Hash& hash,
                         RandomNumberGenerator& rng,
                         const Private_Key* key);

      Certificate_Verify(const MemoryRegion<byte>& buf) { deserialize(buf); }
   private:
      MemoryVector<byte> serialize() const;
      void deserialize(const MemoryRegion<byte>&);

      MemoryVector<byte> signature;
   };

/**
* Finished Message
*/
class Finished : public HandshakeMessage
   {
   public:
      Handshake_Type type() const { return FINISHED; }

      MemoryVector<byte> verify_data() const
         { return verification_data; }

      bool verify(const MemoryRegion<byte>& buf,
                  Version_Code version,
                  const TLS_Handshake_Hash& hash,
                  Connection_Side side);

      Finished(Record_Writer& writer,
               TLS_Handshake_Hash& hash,
               Version_Code version,
               Connection_Side side,
               const MemoryRegion<byte>& master_secret);

      Finished(const MemoryRegion<byte>& buf) { deserialize(buf); }
   private:
      MemoryVector<byte> serialize() const;
      void deserialize(const MemoryRegion<byte>&);

      MemoryVector<byte> compute_verify(const MemoryRegion<byte>& master_secret,
                                        TLS_Handshake_Hash hash,
                                        Connection_Side side,
                                        Version_Code version);

      Connection_Side side;
      MemoryVector<byte> verification_data;
   };

/**
* Hello Request Message
*/
class Hello_Request : public HandshakeMessage
   {
   public:
      Handshake_Type type() const { return HELLO_REQUEST; }

      Hello_Request(Record_Writer& writer);
      Hello_Request(const MemoryRegion<byte>& buf) { deserialize(buf); }
   private:
      MemoryVector<byte> serialize() const;
      void deserialize(const MemoryRegion<byte>&);
   };

/**
* Server Key Exchange Message
*/
class Server_Key_Exchange : public HandshakeMessage
   {
   public:
      Handshake_Type type() const { return SERVER_KEX; }
      Public_Key* key() const;

      bool verify(const X509_Certificate& cert,
                  const MemoryRegion<byte>& c_random,
                  const MemoryRegion<byte>& s_random) const;

      Server_Key_Exchange(Record_Writer& writer,
                          TLS_Handshake_Hash& hash,
                          RandomNumberGenerator& rng,
                          const Public_Key* kex_key,
                          const Private_Key* priv_key,
                          const MemoryRegion<byte>& c_random,
                          const MemoryRegion<byte>& s_random);

      Server_Key_Exchange(const MemoryRegion<byte>& buf) { deserialize(buf); }
   private:
      MemoryVector<byte> serialize() const;
      MemoryVector<byte> serialize_params() const;
      void deserialize(const MemoryRegion<byte>&);

      std::vector<BigInt> params;
      MemoryVector<byte> signature;
   };

/**
* Server Hello Done Message
*/
class Server_Hello_Done : public HandshakeMessage
   {
   public:
      Handshake_Type type() const { return SERVER_HELLO_DONE; }

      Server_Hello_Done(Record_Writer& writer, TLS_Handshake_Hash& hash);
      Server_Hello_Done(const MemoryRegion<byte>& buf) { deserialize(buf); }
   private:
      MemoryVector<byte> serialize() const;
      void deserialize(const MemoryRegion<byte>&);
   };

}

#endif
