/*
* TLS Messages
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_MESSAGES_12_H_
#define BOTAN_TLS_MESSAGES_12_H_

#include <botan/tls_messages.h>

namespace Botan::TLS {

/**
* Client Key Exchange Message
*/
class BOTAN_UNSTABLE_API Client_Key_Exchange final : public Handshake_Message {
   public:
      Handshake_Type type() const override { return Handshake_Type::ClientKeyExchange; }

      const secure_vector<uint8_t>& pre_master_secret() const { return m_pre_master; }

      /**
       * @returns the agreed upon PSK identity or std::nullopt if not applicable
       */
      const std::optional<std::string>& psk_identity() const { return m_psk_identity; }

      Client_Key_Exchange(Handshake_IO& io,
                          Handshake_State& state,
                          const Policy& policy,
                          Credentials_Manager& creds,
                          const Public_Key* server_public_key,
                          std::string_view hostname,
                          RandomNumberGenerator& rng);

      Client_Key_Exchange(const std::vector<uint8_t>& buf,
                          const Handshake_State& state,
                          const Private_Key* server_rsa_kex_key,
                          Credentials_Manager& creds,
                          const Policy& policy,
                          RandomNumberGenerator& rng);

   private:
      std::vector<uint8_t> serialize() const override { return m_key_material; }

      std::vector<uint8_t> m_key_material;
      secure_vector<uint8_t> m_pre_master;
      std::optional<std::string> m_psk_identity;
};

/**
* Certificate Message of TLS 1.2
*/
class BOTAN_UNSTABLE_API Certificate_12 final : public Handshake_Message {
   public:
      Handshake_Type type() const override { return Handshake_Type::Certificate; }

      const std::vector<X509_Certificate>& cert_chain() const { return m_certs; }

      size_t count() const { return m_certs.size(); }

      bool empty() const { return m_certs.empty(); }

      Certificate_12(Handshake_IO& io, Handshake_Hash& hash, const std::vector<X509_Certificate>& certs);

      Certificate_12(const std::vector<uint8_t>& buf, const Policy& policy);

      std::vector<uint8_t> serialize() const override;

   private:
      std::vector<X509_Certificate> m_certs;
};

/**
* Certificate Request Message (TLS 1.2)
*/
class BOTAN_UNSTABLE_API Certificate_Request_12 final : public Handshake_Message {
   public:
      Handshake_Type type() const override;

      const std::vector<std::string>& acceptable_cert_types() const;

      const std::vector<X509_DN>& acceptable_CAs() const;

      const std::vector<Signature_Scheme>& signature_schemes() const;

      Certificate_Request_12(Handshake_IO& io,
                             Handshake_Hash& hash,
                             const Policy& policy,
                             const std::vector<X509_DN>& allowed_cas);

      explicit Certificate_Request_12(const std::vector<uint8_t>& buf);

      std::vector<uint8_t> serialize() const override;

   private:
      std::vector<X509_DN> m_names;
      std::vector<std::string> m_cert_key_types;
      std::vector<Signature_Scheme> m_schemes;
};

/**
* Certificate Verify Message
*/
class BOTAN_UNSTABLE_API Certificate_Verify_12 final : public Certificate_Verify {
   public:
      using Certificate_Verify::Certificate_Verify;

      Certificate_Verify_12(Handshake_IO& io,
                            Handshake_State& state,
                            const Policy& policy,
                            RandomNumberGenerator& rng,
                            const Private_Key* key);

      /**
      * Check the signature on a certificate verify message
      * @param cert the purported certificate
      * @param state the handshake state
      * @param policy the TLS policy
      */
      bool verify(const X509_Certificate& cert, const Handshake_State& state, const Policy& policy) const;
};

/**
* Certificate Status (RFC 6066)
*/
class BOTAN_UNSTABLE_API Certificate_Status_12 final : public Certificate_Status {
   public:
      /*
       * Create a Certificate_Status message using an already DER encoded OCSP response.
       */
      Certificate_Status_12(Handshake_IO& io, Handshake_Hash& hash, std::vector<uint8_t> raw_response_bytes);
};

class BOTAN_UNSTABLE_API Finished_12 final : public Finished {
   public:
      using Finished::Finished;
      Finished_12(Handshake_IO& io, Handshake_State& state, Connection_Side side);

      bool verify(const Handshake_State& state, Connection_Side side) const;
};

/**
* Hello Request Message
*/
class BOTAN_UNSTABLE_API Hello_Request final : public Handshake_Message {
   public:
      Handshake_Type type() const override { return Handshake_Type::HelloRequest; }

      explicit Hello_Request(Handshake_IO& io);
      explicit Hello_Request(const std::vector<uint8_t>& buf);

   private:
      std::vector<uint8_t> serialize() const override;
};

/**
* Server Key Exchange Message
*/
class BOTAN_UNSTABLE_API Server_Key_Exchange final : public Handshake_Message {
   public:
      Handshake_Type type() const override { return Handshake_Type::ServerKeyExchange; }

      const std::vector<uint8_t>& params() const { return m_params; }

      bool verify(const Public_Key& server_key, const Handshake_State& state, const Policy& policy) const;

      // Only valid for certain kex types
      const PK_Key_Agreement_Key& server_kex_key() const;

      /**
       * @returns the agreed upon KEX group or std::nullopt if the KEX type does
       *          not depend on a group
       */
      const std::optional<Group_Params>& shared_group() const { return m_shared_group; }

      Server_Key_Exchange(Handshake_IO& io,
                          Handshake_State& state,
                          const Policy& policy,
                          Credentials_Manager& creds,
                          RandomNumberGenerator& rng,
                          const Private_Key* signing_key = nullptr);

      Server_Key_Exchange(const std::vector<uint8_t>& buf,
                          Kex_Algo kex_alg,
                          Auth_Method sig_alg,
                          Protocol_Version version);

   private:
      std::vector<uint8_t> serialize() const override;

      std::unique_ptr<PK_Key_Agreement_Key> m_kex_key;
      std::optional<Group_Params> m_shared_group;

      std::vector<uint8_t> m_params;

      std::vector<uint8_t> m_signature;
      Signature_Scheme m_scheme;
};

/**
* Server Hello Done Message
*/
class BOTAN_UNSTABLE_API Server_Hello_Done final : public Handshake_Message {
   public:
      Handshake_Type type() const override { return Handshake_Type::ServerHelloDone; }

      explicit Server_Hello_Done(Handshake_IO& io, Handshake_Hash& hash);
      explicit Server_Hello_Done(const std::vector<uint8_t>& buf);

   private:
      std::vector<uint8_t> serialize() const override;
};

/**
* New Session Ticket Message
*/
class BOTAN_UNSTABLE_API New_Session_Ticket_12 final : public Handshake_Message {
   public:
      Handshake_Type type() const override { return Handshake_Type::NewSessionTicket; }

      std::chrono::seconds ticket_lifetime_hint() const { return m_ticket_lifetime_hint; }

      const Session_Ticket& ticket() const { return m_ticket; }

      New_Session_Ticket_12(Handshake_IO& io,
                            Handshake_Hash& hash,
                            Session_Ticket ticket,
                            std::chrono::seconds lifetime);

      New_Session_Ticket_12(Handshake_IO& io, Handshake_Hash& hash);

      explicit New_Session_Ticket_12(const std::vector<uint8_t>& buf);

      std::vector<uint8_t> serialize() const override;

   private:
      std::chrono::seconds m_ticket_lifetime_hint{};
      Session_Ticket m_ticket;
};

/**
* Change Cipher Spec
*/
class BOTAN_UNSTABLE_API Change_Cipher_Spec final : public Handshake_Message {
   public:
      Handshake_Type type() const override { return Handshake_Type::HandshakeCCS; }

      std::vector<uint8_t> serialize() const override { return std::vector<uint8_t>(1, 1); }
};

}  // namespace Botan::TLS

#endif
