/*
* TLS Messages
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_MESSAGES_H__
#define BOTAN_TLS_MESSAGES_H__

#include <botan/tls_record.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/tls_policy.h>
#include <botan/bigint.h>
#include <botan/pkcs8.h>
#include <botan/x509cert.h>
#include <vector>

namespace Botan {

/**
* TLS Handshake Message Base Class
*/
class HandshakeMessage
   {
   public:
      void send(Record_Writer&, HandshakeHash&) const;

      virtual Handshake_Type type() const = 0;

      virtual ~HandshakeMessage() {}
   private:
      HandshakeMessage& operator=(const HandshakeMessage&) { return (*this); }
      virtual SecureVector<byte> serialize() const = 0;
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
      const SecureVector<byte>& session_id() const { return sess_id; }
      std::vector<u16bit> ciphersuites() const { return suites; }
      std::vector<byte> compression_algos() const { return comp_algos; }

      const SecureVector<byte>& random() const { return c_random; }

      std::string hostname() const { return requested_hostname; }

      std::string srp_identifier() const { return requested_srp_id; }

      bool offered_suite(u16bit) const;

      Client_Hello(RandomNumberGenerator& rng,
                   Record_Writer&, const TLS_Policy&, HandshakeHash&);

      Client_Hello(const MemoryRegion<byte>& buf,
                   Handshake_Type type)
         {
         if(type == CLIENT_HELLO)
            deserialize(buf);
         else
            deserialize_sslv2(buf);
         }

   private:
      SecureVector<byte> serialize() const;
      void deserialize(const MemoryRegion<byte>&);
      void deserialize_sslv2(const MemoryRegion<byte>&);

      Version_Code c_version;
      SecureVector<byte> sess_id, c_random;
      std::vector<u16bit> suites;
      std::vector<byte> comp_algos;
      std::string requested_hostname;
      std::string requested_srp_id;
   };

/**
* Client Key Exchange Message
*/
class Client_Key_Exchange : public HandshakeMessage
   {
   public:
      Handshake_Type type() const { return CLIENT_KEX; }

      SecureVector<byte> pre_master_secret() const;

      SecureVector<byte> pre_master_secret(RandomNumberGenerator& rng,
                                           const Private_Key* key,
                                           Version_Code version);

      Client_Key_Exchange(RandomNumberGenerator& rng,
                          Record_Writer& output,
                          HandshakeHash& hash,
                          const Public_Key* my_key,
                          Version_Code using_version,
                          Version_Code pref_version);

      Client_Key_Exchange(const MemoryRegion<byte>& buf,
                          const CipherSuite& suite,
                          Version_Code using_version);
   private:
      SecureVector<byte> serialize() const;
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
      std::vector<X509_Certificate> cert_chain() const { return certs; }

      Certificate(Record_Writer&, const std::vector<X509_Certificate>&,
                  HandshakeHash&);
      Certificate(const MemoryRegion<byte>& buf) { deserialize(buf); }
   private:
      SecureVector<byte> serialize() const;
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

      /* TODO
      Certificate_Req(Record_Writer&, HandshakeHash&,
                      const X509_Certificate&);
      */
      Certificate_Req(Record_Writer&, HandshakeHash&,
                      const std::vector<X509_Certificate>&);

      Certificate_Req(const MemoryRegion<byte>& buf) { deserialize(buf); }
   private:
      SecureVector<byte> serialize() const;
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

      bool verify(const X509_Certificate&, HandshakeHash&);

      Certificate_Verify(RandomNumberGenerator& rng,
                         Record_Writer&, HandshakeHash&,
                         const Private_Key*);

      Certificate_Verify(const MemoryRegion<byte>& buf) { deserialize(buf); }
   private:
      SecureVector<byte> serialize() const;
      void deserialize(const MemoryRegion<byte>&);

      SecureVector<byte> signature;
   };

/**
* Finished Message
*/
class Finished : public HandshakeMessage
   {
   public:
      Handshake_Type type() const { return FINISHED; }

      bool verify(const MemoryRegion<byte>&, Version_Code,
                  const HandshakeHash&, Connection_Side);

      Finished(Record_Writer&, Version_Code, Connection_Side,
               const MemoryRegion<byte>&, HandshakeHash&);
      Finished(const MemoryRegion<byte>& buf) { deserialize(buf); }
   private:
      SecureVector<byte> serialize() const;
      void deserialize(const MemoryRegion<byte>&);

      SecureVector<byte> compute_verify(const MemoryRegion<byte>&,
                                        HandshakeHash, Connection_Side,
                                        Version_Code);

      Connection_Side side;
      SecureVector<byte> verification_data;
   };

/**
* Hello Request Message
*/
class Hello_Request : public HandshakeMessage
   {
   public:
      Handshake_Type type() const { return HELLO_REQUEST; }

      Hello_Request(Record_Writer&);
      Hello_Request(const MemoryRegion<byte>& buf) { deserialize(buf); }
   private:
      SecureVector<byte> serialize() const;
      void deserialize(const MemoryRegion<byte>&);
   };

/**
* Server Hello Message
*/
class Server_Hello : public HandshakeMessage
   {
   public:
      Handshake_Type type() const { return SERVER_HELLO; }
      Version_Code version() { return s_version; }
      const SecureVector<byte>& session_id() const { return sess_id; }
      u16bit ciphersuite() const { return suite; }
      byte compression_algo() const { return comp_algo; }

      const SecureVector<byte>& random() const { return s_random; }

      Server_Hello(RandomNumberGenerator& rng,
                   Record_Writer&, const TLS_Policy&,
                   const std::vector<X509_Certificate>&,
                   const Client_Hello&, Version_Code, HandshakeHash&);

      Server_Hello(const MemoryRegion<byte>& buf) { deserialize(buf); }
   private:
      SecureVector<byte> serialize() const;
      void deserialize(const MemoryRegion<byte>&);

      Version_Code s_version;
      SecureVector<byte> sess_id, s_random;
      u16bit suite;
      byte comp_algo;
   };

/**
* Server Key Exchange Message
*/
class Server_Key_Exchange : public HandshakeMessage
   {
   public:
      Handshake_Type type() const { return SERVER_KEX; }
      Public_Key* key() const;

      bool verify(const X509_Certificate&, const MemoryRegion<byte>&,
                  const MemoryRegion<byte>&) const;

      Server_Key_Exchange(RandomNumberGenerator& rng,
                          Record_Writer&, const Public_Key*,
                          const Private_Key*, const MemoryRegion<byte>&,
                          const MemoryRegion<byte>&, HandshakeHash&);

      Server_Key_Exchange(const MemoryRegion<byte>& buf) { deserialize(buf); }
   private:
      SecureVector<byte> serialize() const;
      SecureVector<byte> serialize_params() const;
      void deserialize(const MemoryRegion<byte>&);

      std::vector<BigInt> params;
      SecureVector<byte> signature;
   };

/**
* Server Hello Done Message
*/
class Server_Hello_Done : public HandshakeMessage
   {
   public:
      Handshake_Type type() const { return SERVER_HELLO_DONE; }

      Server_Hello_Done(Record_Writer&, HandshakeHash&);
      Server_Hello_Done(const MemoryRegion<byte>& buf) { deserialize(buf); }
   private:
      SecureVector<byte> serialize() const;
      void deserialize(const MemoryRegion<byte>&);
   };

}

#endif
