/*
* TLS 1.2 Specific Extensions
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

#ifndef BOTAN_TLS_EXTENSIONS_12_H_
#define BOTAN_TLS_EXTENSIONS_12_H_

#include <botan/tls_extensions.h>
#include <botan/tls_session.h>

#include <vector>

namespace Botan::TLS {

class TLS_Data_Reader;

/**
* Renegotiation Indication Extension (RFC 5746)
*/
class BOTAN_UNSTABLE_API Renegotiation_Extension final : public Extension {
   public:
      static Extension_Code static_type() { return Extension_Code::SafeRenegotiation; }

      Extension_Code type() const override { return static_type(); }

      Renegotiation_Extension() = default;

      explicit Renegotiation_Extension(const std::vector<uint8_t>& bits) : m_reneg_data(bits) {}

      Renegotiation_Extension(TLS_Data_Reader& reader, uint16_t extension_size);

      const std::vector<uint8_t>& renegotiation_info() const { return m_reneg_data; }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return false; }  // always send this

   private:
      std::vector<uint8_t> m_reneg_data;
};

/**
* Session Ticket Extension (RFC 5077)
*/
class BOTAN_UNSTABLE_API Session_Ticket_Extension final : public Extension {
   public:
      static Extension_Code static_type() { return Extension_Code::SessionTicket; }

      Extension_Code type() const override { return static_type(); }

      /**
      * @return contents of the session ticket
      */
      const Session_Ticket& contents() const { return m_ticket; }

      /**
      * Create empty extension, used by both client and server
      */
      Session_Ticket_Extension() = default;

      /**
      * Extension with ticket, used by client
      */
      explicit Session_Ticket_Extension(Session_Ticket session_ticket) : m_ticket(std::move(session_ticket)) {}

      /**
      * Deserialize a session ticket
      */
      Session_Ticket_Extension(TLS_Data_Reader& reader, uint16_t extension_size);

      std::vector<uint8_t> serialize(Connection_Side /*whoami*/) const override { return m_ticket.get(); }

      bool empty() const override { return false; }

   private:
      Session_Ticket m_ticket;
};

/**
* Supported Point Formats Extension (RFC 4492)
*/
class BOTAN_UNSTABLE_API Supported_Point_Formats final : public Extension {
   public:
      enum ECPointFormat : uint8_t /* NOLINT(*-use-enum-class) */ {
         UNCOMPRESSED = 0,
         ANSIX962_COMPRESSED_PRIME = 1,
         ANSIX962_COMPRESSED_CHAR2 = 2,  // don't support these curves
      };

      static Extension_Code static_type() { return Extension_Code::EcPointFormats; }

      Extension_Code type() const override { return static_type(); }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      explicit Supported_Point_Formats(bool prefer_compressed) : m_prefers_compressed(prefer_compressed) {}

      Supported_Point_Formats(TLS_Data_Reader& reader, uint16_t extension_size);

      bool empty() const override { return false; }

      bool prefers_compressed() const { return m_prefers_compressed; }

   private:
      bool m_prefers_compressed = false;
};

/**
* Extended Master Secret Extension (RFC 7627)
*/
class BOTAN_UNSTABLE_API Extended_Master_Secret final : public Extension {
   public:
      static Extension_Code static_type() { return Extension_Code::ExtendedMasterSecret; }

      Extension_Code type() const override { return static_type(); }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return false; }

      Extended_Master_Secret() = default;

      Extended_Master_Secret(TLS_Data_Reader& reader, uint16_t extension_size);
};

/**
* Encrypt-then-MAC Extension (RFC 7366)
*/
class BOTAN_UNSTABLE_API Encrypt_then_MAC final : public Extension {
   public:
      static Extension_Code static_type() { return Extension_Code::EncryptThenMac; }

      Extension_Code type() const override { return static_type(); }

      std::vector<uint8_t> serialize(Connection_Side whoami) const override;

      bool empty() const override { return false; }

      Encrypt_then_MAC() = default;

      Encrypt_then_MAC(TLS_Data_Reader& reader, uint16_t extension_size);
};

}  // namespace Botan::TLS

#endif
