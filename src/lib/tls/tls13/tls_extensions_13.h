/*
* TLS 1.3 Specific Extensions
* (C) 2011,2012,2016,2018,2019 Jack Lloyd
* (C) 2016 Juraj Somorovsky
* (C) 2016 Matthias Gierlings
* (C) 2021 Elektrobit Automotive GmbH
* (C) 2022 René Meusel, Hannes Rantzsch - neXenio GmbH
* (C) 2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
* (C) 2026 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_EXTENSIONS_13_H_
#define BOTAN_TLS_EXTENSIONS_13_H_

#include <botan/pkix_types.h>
#include <botan/tls_extensions.h>
#include <botan/tls_external_psk.h>
#include <botan/tls_session.h>

namespace Botan {

class RandomNumberGenerator;
class Credentials_Manager;

namespace TLS {

class Callbacks;
class Cipher_State;
class Ciphersuite;
class Policy;
class Session_Manager;
class TLS_Data_Reader;
class Transcript_Hash_State;

enum class PSK_Key_Exchange_Mode : uint8_t { PSK_KE = 0, PSK_DHE_KE = 1 };

/**
* Cookie from RFC 8446 4.2.2
*/
class BOTAN_UNSTABLE_API Cookie final : public Extension {
   public:
      static Extension_Code static_type() { return Extension_Code::Cookie; }

      Extension_Code type() const override { return static_type(); }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return m_cookie.empty(); }

      const std::vector<uint8_t>& get_cookie() const { return m_cookie; }

      explicit Cookie(const std::vector<uint8_t>& cookie);

      explicit Cookie(TLS_Data_Reader& reader, uint16_t extension_size);

   private:
      std::vector<uint8_t> m_cookie;
};

/**
* Pre-Shared Key Exchange Modes from RFC 8446 4.2.9
*/
class BOTAN_UNSTABLE_API PSK_Key_Exchange_Modes final : public Extension {
   public:
      static Extension_Code static_type() { return Extension_Code::PskKeyExchangeModes; }

      Extension_Code type() const override { return static_type(); }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return m_modes.empty(); }

      const std::vector<PSK_Key_Exchange_Mode>& modes() const { return m_modes; }

      explicit PSK_Key_Exchange_Modes(std::vector<PSK_Key_Exchange_Mode> modes) : m_modes(std::move(modes)) {}

      explicit PSK_Key_Exchange_Modes(TLS_Data_Reader& reader, uint16_t extension_size);

   private:
      std::vector<PSK_Key_Exchange_Mode> m_modes;
};

/**
 * Certificate Authorities Extension from RFC 8446 4.2.4
 */
class BOTAN_UNSTABLE_API Certificate_Authorities final : public Extension {
   public:
      static Extension_Code static_type() { return Extension_Code::CertificateAuthorities; }

      Extension_Code type() const override { return static_type(); }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return m_distinguished_names.empty(); }

      const std::vector<X509_DN>& distinguished_names() const { return m_distinguished_names; }

      Certificate_Authorities(TLS_Data_Reader& reader, uint16_t extension_size);
      explicit Certificate_Authorities(std::vector<X509_DN> acceptable_DNs);

   private:
      std::vector<X509_DN> m_distinguished_names;
};

/**
 * Pre-Shared Key extension from RFC 8446 4.2.11
 */
class BOTAN_UNSTABLE_API PSK final : public Extension /* NOLINT(*-special-member-functions) */ {
   public:
      static Extension_Code static_type() { return Extension_Code::PresharedKey; }

      Extension_Code type() const override { return static_type(); }

      std::vector<uint8_t> serialize(Connection_Side side) const override;

      /**
       * Returns the PSK identity (in case of an externally provided PSK) and
       * the cipher state representing the PSK selected by the server. Note that
       * this destructs the list of offered PSKs and its cipher states and must
       * therefore not be called more than once.
       *
       * @note Technically, PSKs used for resumption also carry an identity.
       *       Though, typically, this is an opaque value meaningful only to the
       *       peer and of no authoritative value for the user. We therefore
       *       report the identity of externally provided PSKs only.
       */
      std::pair<std::optional<std::string>, std::unique_ptr<Cipher_State>> take_selected_psk_info(
         const PSK& server_psk, const Ciphersuite& cipher);

      /**
       * Selects one of the offered PSKs that is compatible with \p cipher.
       * @retval PSK extension object that can be added to the Server Hello response
       * @retval std::nullptr if no PSK offered by the client is convenient
       */
      std::unique_ptr<PSK> select_offered_psk(std::string_view host,
                                              const Ciphersuite& cipher,
                                              Session_Manager& session_mgr,
                                              Credentials_Manager& credentials_mgr,
                                              Callbacks& callbacks,
                                              const Policy& policy);

      /**
       * Remove PSK identities from the list in \p m_psk that are not compatible
       * with the passed in \p cipher suite.
       * This is useful to react to Hello Retry Requests. See RFC 8446 4.1.4.
       */
      void filter(const Ciphersuite& cipher);

      /**
       * Pulls the preshared key or the Session to resume from a PSK extension
       * in Server Hello.
       */
      std::variant<Session, ExternalPSK> take_session_to_resume_or_psk();

      bool empty() const override;

      PSK(TLS_Data_Reader& reader, uint16_t extension_size, Handshake_Type message_type);

      /**
       * Creates a PSK extension with a TLS 1.3 session object containing a
       * master_secret. Note that it will extract that secret from the session,
       * and won't create a copy of it.
       *
       * @param session_to_resume  the session to be resumed; note that the
       *                           master secret will be taken away from the
       *                           session object.
       * @param psks               a list of non-resumption PSKs that should be
       *                           offered to the server
       * @param callbacks          the application's callbacks
       */
      PSK(std::optional<Session_with_Handle>& session_to_resume, std::vector<ExternalPSK> psks, Callbacks& callbacks);

      ~PSK() override;

      void calculate_binders(const Transcript_Hash_State& truncated_transcript_hash);
      bool validate_binder(const PSK& server_psk, const std::vector<uint8_t>& binder) const;

      // TODO: Implement pure PSK negotiation that is not used for session
      //       resumption.

   private:
      /**
       * Creates a PSK extension that specifies the server's selection of an
       * offered client PSK. The @p session_to_resume is kept internally
       * and used later for the initialization of the Cipher_State object.
       *
       * Note: This constructor is called internally in PSK::select_offered_psk().
       */
      PSK(Session session_to_resume, uint16_t psk_index);

      /**
       * Creates a PSK extension that specifies the server's selection of an
       * externally provided PSK offered by the client. The @p psk is kept
       * internally and used later for the initialization of the Cipher_State object.
       *
       * Note: This constructor is called internally in PSK::select_offered_psk().
       */
      PSK(ExternalPSK psk, uint16_t psk_index);

   private:
      class PSK_Internal;
      std::unique_ptr<PSK_Internal> m_impl;
};

/**
* Key_Share from RFC 8446 4.2.8
*/
class BOTAN_UNSTABLE_API Key_Share final : public Extension /* NOLINT(*-special-member-functions) */ {
   public:
      static Extension_Code static_type() { return Extension_Code::KeyShare; }

      Extension_Code type() const override { return static_type(); }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override;

      /**
       * Creates a Key_Share extension meant for the Server Hello that
       * performs a key encapsulation with the selected public key from
       * the client.
       *
       * @note This will retain the shared secret in the Key_Share extension
       *       until it is retrieved via take_shared_secret().
       */
      static std::unique_ptr<Key_Share> create_as_encapsulation(Group_Params selected_group,
                                                                const Key_Share& client_keyshare,
                                                                const Policy& policy,
                                                                Callbacks& cb,
                                                                RandomNumberGenerator& rng);

      /**
       * Decapsulate the shared secret with the peer's key share. This method
       * can be called on a ClientHello's Key_Share with a ServerHello's
       * Key_Share.
       *
       * @note After the decapsulation the client's private key is destroyed.
       *       Multiple calls will result in an exception.
       */
      secure_vector<uint8_t> decapsulate(const Key_Share& server_keyshare,
                                         const Policy& policy,
                                         Callbacks& cb,
                                         RandomNumberGenerator& rng);

      /**
       * Update a ClientHello's Key_Share to comply with a HelloRetryRequest.
       *
       * This will create new Key_Share_Entries and should only be called on a ClientHello Key_Share with a HelloRetryRequest Key_Share.
       */
      void retry_offer(const Key_Share& retry_request_keyshare,
                       const std::vector<Named_Group>& supported_groups,
                       Callbacks& cb,
                       RandomNumberGenerator& rng);

      /**
       * @return key exchange groups the peer offered key share entries for
       */
      std::vector<Named_Group> offered_groups() const;

      /**
       * @return key exchange group that was selected by a Hello Retry Request
       */
      Named_Group selected_group() const;

      /**
       * @returns the shared secret that was obtained by constructing this
       *          Key_Share object with the peer's.
       *
       * @note the shared secret value is std:move'd out. Multiple calls will
       *       result in an exception.
       */
      secure_vector<uint8_t> take_shared_secret();

      Key_Share(TLS_Data_Reader& reader, uint16_t extension_size, Handshake_Type message_type);

      // constructor used for ClientHello msg
      Key_Share(const Policy& policy, Callbacks& cb, RandomNumberGenerator& rng);

      // constructor used for HelloRetryRequest msg
      explicit Key_Share(Named_Group selected_group);

      // destructor implemented in .cpp to hide Key_Share_Impl
      ~Key_Share() override;

   private:
      // constructor used for ServerHello
      // (called via create_as_encapsulation())
      Key_Share(Group_Params selected_group,
                const Key_Share& client_keyshare,
                const Policy& policy,
                Callbacks& cb,
                RandomNumberGenerator& rng);

   private:
      class Key_Share_Impl;
      std::unique_ptr<Key_Share_Impl> m_impl;
};

/**
 * Indicates usage or support of early data as described in RFC 8446 4.2.10.
 */
class BOTAN_UNSTABLE_API EarlyDataIndication final : public Extension {
   public:
      static Extension_Code static_type() { return Extension_Code::EarlyData; }

      Extension_Code type() const override { return static_type(); }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override;

      std::optional<uint32_t> max_early_data_size() const { return m_max_early_data_size; }

      EarlyDataIndication(TLS_Data_Reader& reader, uint16_t extension_size, Handshake_Type message_type);

      /**
       * The max_early_data_size is exclusively provided by servers when using
       * this extension in the NewSessionTicket message! Otherwise it stays
       * std::nullopt and results in an empty extension. (RFC 8446 4.2.10).
       */
      explicit EarlyDataIndication(std::optional<uint32_t> max_early_data_size = std::nullopt) :
            m_max_early_data_size(max_early_data_size) {}

   private:
      std::optional<uint32_t> m_max_early_data_size;
};

}  // namespace TLS

}  // namespace Botan

#endif
