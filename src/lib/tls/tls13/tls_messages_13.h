/*
* TLS Messages
* (C) 2021-2022 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_MESSAGES_13_H_
#define BOTAN_TLS_MESSAGES_13_H_

#include <botan/tls_extensions.h>
#include <botan/tls_messages.h>
#include <botan/x509cert.h>
#include <chrono>

namespace Botan::TLS {

class BOTAN_UNSTABLE_API Client_Hello_13 final : public Client_Hello {
   public:
      /**
          * Creates a client hello which might optionally use the passed-in
          * @p session for resumption. In that case, this will "extract" the
          * master secret from the passed-in @p session.
          */
      Client_Hello_13(const Policy& policy,
                      Callbacks& cb,
                      RandomNumberGenerator& rng,
                      std::string_view hostname,
                      const std::vector<std::string>& next_protocols,
                      std::optional<Session_with_Handle>& session,
                      std::vector<ExternalPSK> psks);

      static std::variant<Client_Hello_13, Client_Hello_12> parse(const std::vector<uint8_t>& buf);

      void retry(const Hello_Retry_Request& hrr,
                 const Transcript_Hash_State& transcript_hash_state,
                 Callbacks& cb,
                 RandomNumberGenerator& rng);

      /**
          * Select the highest protocol version from the list of versions
          * supported by the client. If no such version can be determined this
          * returns std::nullopt.
          */
      std::optional<Protocol_Version> highest_supported_version(const Policy& policy) const;

      /**
          * This validates that a Client Hello received after sending a Hello
          * Retry Request was updated in accordance with RFC 8446 4.1.2. If issues
          * are found, this method throws accordingly.
          */
      void validate_updates(const Client_Hello_13& new_ch);

   private:
      explicit Client_Hello_13(std::unique_ptr<Client_Hello_Internal> data);

      /**
          * If the Client Hello contains a PSK extensions with identities this will
          * generate the PSK binders as described in RFC 8446 4.2.11.2.
          * Note that the passed in \p transcript_hash_state might be virgin for
          * the initial Client Hello and should be primed with ClientHello1 and
          * HelloRetryRequest for an updated Client Hello.
          */
      void calculate_psk_binders(Transcript_Hash_State transcript_hash_state);
};

class Hello_Retry_Request;

class BOTAN_UNSTABLE_API Server_Hello_13 : public Server_Hello {
   protected:
      static const struct Server_Hello_Tag {
      } as_server_hello;

      static const struct Hello_Retry_Request_Tag {
      } as_hello_retry_request;

      static const struct Hello_Retry_Request_Creation_Tag {
      } as_new_hello_retry_request;

      // These constructors are meant for instantiating Server Hellos
      // after parsing a peer's message. They perform basic validation
      // and are therefore not suitable for constructing a message to
      // be sent to a client.
      explicit Server_Hello_13(std::unique_ptr<Server_Hello_Internal> data, Server_Hello_Tag tag = as_server_hello);
      explicit Server_Hello_13(std::unique_ptr<Server_Hello_Internal> data, Hello_Retry_Request_Tag tag);
      void basic_validation() const;

      // Instantiate a Server Hello as response to a client's Client Hello
      // (called from Server_Hello_13::create())
      Server_Hello_13(const Client_Hello_13& ch,
                      std::optional<Named_Group> key_exchange_group,
                      Session_Manager& session_mgr,
                      Credentials_Manager& credentials_mgr,
                      RandomNumberGenerator& rng,
                      Callbacks& cb,
                      const Policy& policy);

      explicit Server_Hello_13(std::unique_ptr<Server_Hello_Internal> data, Hello_Retry_Request_Creation_Tag tag);

   public:
      static std::variant<Hello_Retry_Request, Server_Hello_13> create(const Client_Hello_13& ch,
                                                                       bool hello_retry_request_allowed,
                                                                       Session_Manager& session_mgr,
                                                                       Credentials_Manager& credentials_mgr,
                                                                       RandomNumberGenerator& rng,
                                                                       const Policy& policy,
                                                                       Callbacks& cb);

      static std::variant<Hello_Retry_Request, Server_Hello_13, Server_Hello_12> parse(const std::vector<uint8_t>& buf);

      /**
       * Return desired downgrade version indicated by hello random, if any.
       */
      std::optional<Protocol_Version> random_signals_downgrade() const;

      /**
       * @returns the selected version as indicated by the supported_versions extension
       */
      Protocol_Version selected_version() const final;
};

class BOTAN_UNSTABLE_API Hello_Retry_Request final : public Server_Hello_13 {
   protected:
      friend class Server_Hello_13;  // to allow construction by Server_Hello_13::parse() and ::create()
      explicit Hello_Retry_Request(std::unique_ptr<Server_Hello_Internal> data);
      Hello_Retry_Request(const Client_Hello_13& ch, Named_Group selected_group, const Policy& policy, Callbacks& cb);

   public:
      Handshake_Type type() const override { return Handshake_Type::HelloRetryRequest; }

      Handshake_Type wire_type() const override { return Handshake_Type::ServerHello; }
};

class BOTAN_UNSTABLE_API Encrypted_Extensions final : public Handshake_Message {
   public:
      explicit Encrypted_Extensions(const std::vector<uint8_t>& buf);
      Encrypted_Extensions(const Client_Hello_13& client_hello, const Policy& policy, Callbacks& cb);

      Handshake_Type type() const override { return Handshake_Type::EncryptedExtensions; }

      const Extensions& extensions() const { return m_extensions; }

      std::vector<uint8_t> serialize() const override;

   private:
      Extensions m_extensions;
};

class Certificate_Request_13;

/**
* Certificate Message of TLS 1.3
*/
class BOTAN_UNSTABLE_API Certificate_13 final : public Handshake_Message {
   public:
      class Certificate_Entry {
         public:
            Certificate_Entry(TLS_Data_Reader& reader, Connection_Side side, Certificate_Type cert_type);
            explicit Certificate_Entry(const X509_Certificate& cert);
            explicit Certificate_Entry(std::shared_ptr<Public_Key> raw_public_key);

            bool has_certificate() const { return m_certificate.has_value(); }

            const X509_Certificate& certificate() const;
            std::shared_ptr<const Public_Key> public_key() const;

            std::vector<uint8_t> serialize() const;

            Extensions& extensions() { return m_extensions; }

            const Extensions& extensions() const { return m_extensions; }

         private:
            std::optional<X509_Certificate> m_certificate;
            std::shared_ptr<Public_Key> m_raw_public_key;
            Extensions m_extensions;
      };

   public:
      Handshake_Type type() const override { return Handshake_Type::Certificate; }

      std::vector<X509_Certificate> cert_chain() const;

      bool has_certificate_chain() const;
      bool is_raw_public_key() const;

      size_t count() const { return m_entries.size(); }

      bool empty() const { return m_entries.empty(); }

      std::shared_ptr<const Public_Key> public_key() const;
      const X509_Certificate& leaf() const;

      const std::vector<uint8_t>& request_context() const { return m_request_context; }

      /**
       * Create a Client Certificate message
       * ... in response to a Certificate Request message.
       */
      Certificate_13(const Certificate_Request_13& cert_request,
                     std::string_view hostname,
                     Credentials_Manager& credentials_manager,
                     Callbacks& callbacks,
                     Certificate_Type cert_type);

      /**
       * Create a Server Certificate message
       * ... in response to a Client Hello indicating the need to authenticate
       *     with a server certificate.
       */
      Certificate_13(const Client_Hello_13& client_hello,
                     Credentials_Manager& credentials_manager,
                     Callbacks& callbacks,
                     Certificate_Type cert_type);

      /**
      * Deserialize a Certificate message
      * @param buf the serialized message
      * @param policy the TLS policy
      * @param side is this a Connection_Side::Server or Connection_Side::Client certificate message
      * @param cert_type is the certificate type that was negotiated during the handshake
      */
      Certificate_13(const std::vector<uint8_t>& buf,
                     const Policy& policy,
                     Connection_Side side,
                     Certificate_Type cert_type);

      /**
      * Validate a Certificate message regarding what extensions are expected based on
      * previous handshake messages. Also call the tls_examine_extensions() callback
      * for each entry.
      *
      * @param requested_extensions Extensions of Client_Hello or Certificate_Request messages
      * @param cb Callback that will be called for each extension.
      */
      void validate_extensions(const std::set<Extension_Code>& requested_extensions, Callbacks& cb) const;

      /**
       * Verify the certificate chain
       *
       * @throws if verification fails.
       */
      void verify(Callbacks& callbacks,
                  const Policy& policy,
                  Credentials_Manager& creds,
                  std::string_view hostname,
                  bool use_ocsp) const;

      std::vector<uint8_t> serialize() const override;

   private:
      void setup_entries(std::vector<X509_Certificate> cert_chain,
                         const Certificate_Status_Request* csr,
                         Callbacks& callbacks);
      void setup_entry(std::shared_ptr<Public_Key> raw_public_key, Callbacks& callbacks);

      void verify_certificate_chain(Callbacks& callbacks,
                                    const Policy& policy,
                                    Credentials_Manager& creds,
                                    std::string_view hostname,
                                    bool use_ocsp,
                                    Usage_Type usage_type) const;

   private:
      std::vector<uint8_t> m_request_context;
      std::vector<Certificate_Entry> m_entries;
      Connection_Side m_side;
};

class BOTAN_UNSTABLE_API Certificate_Request_13 final : public Handshake_Message {
   public:
      Handshake_Type type() const override;

      Certificate_Request_13(const std::vector<uint8_t>& buf, Connection_Side side);

      //! Creates a Certificate_Request message if it is required by the configuration
      //! @return std::nullopt if configuration does not require client authentication
      static std::optional<Certificate_Request_13> maybe_create(const Client_Hello_13& sni_hostname,
                                                                Credentials_Manager& cred_mgr,
                                                                Callbacks& callbacks,
                                                                const Policy& policy);

      std::vector<X509_DN> acceptable_CAs() const;
      const std::vector<Signature_Scheme>& signature_schemes() const;
      const std::vector<Signature_Scheme>& certificate_signature_schemes() const;

      const Extensions& extensions() const { return m_extensions; }

      std::vector<uint8_t> serialize() const override;

      const std::vector<uint8_t>& context() const { return m_context; }

   private:
      Certificate_Request_13(const std::vector<X509_DN>& acceptable_CAs, const Policy& policy, Callbacks& callbacks);

   private:
      std::vector<uint8_t> m_context;
      Extensions m_extensions;
};

/**
* Certificate Verify Message
*/
class BOTAN_UNSTABLE_API Certificate_Verify_13 final : public Certificate_Verify {
   public:
      /**
      * Deserialize a Certificate message
      * @param buf the serialized message
      * @param side is this a Connection_Side::Server or Connection_Side::Client certificate message
      */
      Certificate_Verify_13(const std::vector<uint8_t>& buf, Connection_Side side);

      Certificate_Verify_13(const Certificate_13& certificate_message,
                            const std::vector<Signature_Scheme>& peer_allowed_schemes,
                            std::string_view hostname,
                            const Transcript_Hash& hash,
                            Connection_Side whoami,
                            Credentials_Manager& creds_mgr,
                            const Policy& policy,
                            Callbacks& callbacks,
                            RandomNumberGenerator& rng);

      bool verify(const Public_Key& public_key, Callbacks& callbacks, const Transcript_Hash& transcript_hash) const;

   private:
      Connection_Side m_side;
};

class BOTAN_UNSTABLE_API Finished_13 final : public Finished {
   public:
      using Finished::Finished;
      Finished_13(Cipher_State* cipher_state, const Transcript_Hash& transcript_hash);

      bool verify(Cipher_State* cipher_state, const Transcript_Hash& transcript_hash) const;
};

class BOTAN_UNSTABLE_API New_Session_Ticket_13 final : public Handshake_Message {
   public:
      Handshake_Type type() const override { return Handshake_Type::NewSessionTicket; }

      New_Session_Ticket_13(Ticket_Nonce nonce,
                            const Session& session,
                            const Session_Handle& handle,
                            Callbacks& callbacks);

      New_Session_Ticket_13(const std::vector<uint8_t>& buf, Connection_Side from);

      std::vector<uint8_t> serialize() const override;

      const Extensions& extensions() const { return m_extensions; }

      const Opaque_Session_Handle& handle() const { return m_handle; }

      const Ticket_Nonce& nonce() const { return m_ticket_nonce; }

      uint32_t ticket_age_add() const { return m_ticket_age_add; }

      std::chrono::seconds lifetime_hint() const { return m_ticket_lifetime_hint; }

      /**
       * @return  the number of bytes allowed for early data or std::nullopt
       *          when early data is not allowed at all
       */
      std::optional<uint32_t> early_data_byte_limit() const;

   private:
      // RFC 8446 4.6.1
      //    Clients MUST NOT cache tickets for longer than 7 days, regardless of
      //    the ticket_lifetime, and MAY delete tickets earlier based on local
      //    policy.  A server MAY treat a ticket as valid for a shorter period
      //    of time than what is stated in the ticket_lifetime.
      //
      // ... hence we call it 'lifetime hint'.
      std::chrono::seconds m_ticket_lifetime_hint{};
      uint32_t m_ticket_age_add;
      Ticket_Nonce m_ticket_nonce;
      Opaque_Session_Handle m_handle;
      Extensions m_extensions;
};

class BOTAN_UNSTABLE_API Key_Update final : public Handshake_Message {
   public:
      Handshake_Type type() const override { return Handshake_Type::KeyUpdate; }

      explicit Key_Update(bool request_peer_update);
      explicit Key_Update(const std::vector<uint8_t>& buf);

      std::vector<uint8_t> serialize() const override;

      bool expects_reciprocation() const { return m_update_requested; }

   private:
      bool m_update_requested;
};

namespace detail {
template <typename T>
struct as_wrapped_references {};

template <typename... AlternativeTs>
struct as_wrapped_references<std::variant<AlternativeTs...>> {
      using type = std::variant<std::reference_wrapper<AlternativeTs>...>;
};

template <typename T>
using as_wrapped_references_t = typename as_wrapped_references<T>::type;
}  // namespace detail

// Handshake message types from RFC 8446 4.
using Handshake_Message_13 = std::variant<Client_Hello_13,
                                          Client_Hello_12,
                                          Server_Hello_13,
                                          Server_Hello_12,
                                          Hello_Retry_Request,
                                          // End_Of_Early_Data,
                                          Encrypted_Extensions,
                                          Certificate_13,
                                          Certificate_Request_13,
                                          Certificate_Verify_13,
                                          Finished_13>;
using Handshake_Message_13_Ref = detail::as_wrapped_references_t<Handshake_Message_13>;

using Post_Handshake_Message_13 = std::variant<New_Session_Ticket_13, Key_Update>;

// Key_Update is handled generically by the Channel. The messages assigned
// to those variants are the ones that need to be handled by the specific
// client and/or server implementations.
using Server_Post_Handshake_13_Message = std::variant<New_Session_Ticket_13, Key_Update>;
using Client_Post_Handshake_13_Message = std::variant<Key_Update>;

using Server_Handshake_13_Message = std::variant<Server_Hello_13,
                                                 Server_Hello_12,  // indicates a TLS version downgrade
                                                 Hello_Retry_Request,
                                                 Encrypted_Extensions,
                                                 Certificate_13,
                                                 Certificate_Request_13,
                                                 Certificate_Verify_13,
                                                 Finished_13>;
using Server_Handshake_13_Message_Ref = detail::as_wrapped_references_t<Server_Handshake_13_Message>;

using Client_Handshake_13_Message = std::variant<Client_Hello_13,
                                                 Client_Hello_12,  // indicates a TLS peer that does not offer TLS 1.3
                                                 Certificate_13,
                                                 Certificate_Verify_13,
                                                 Finished_13>;
using Client_Handshake_13_Message_Ref = detail::as_wrapped_references_t<Client_Handshake_13_Message>;

}  // namespace Botan::TLS

#endif
