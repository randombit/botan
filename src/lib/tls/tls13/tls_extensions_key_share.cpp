/*
* TLS Extension Key Share
* (C) 2011,2012,2015,2016 Jack Lloyd
*     2016 Juraj Somorovsky
*     2021 Elektrobit Automotive GmbH
*     2022 Hannes Rantzsch, René Meusel, neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_extensions.h>

#include <botan/rng.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_reader.h>

#include <functional>
#include <iterator>
#include <utility>

#if defined(BOTAN_HAS_X25519)
   #include <botan/x25519.h>
#endif

#if defined(BOTAN_HAS_X448)
   #include <botan/x448.h>
#endif

#include <botan/dh.h>
#include <botan/dl_group.h>
#include <botan/ecdh.h>

namespace Botan::TLS {

namespace {

class Key_Share_Entry {
   public:
      Key_Share_Entry(TLS_Data_Reader& reader) {
         // TODO check that the group actually exists before casting...
         m_group = static_cast<Named_Group>(reader.get_uint16_t());
         m_key_exchange = reader.get_tls_length_value(2);
      }

      // Create an empty Key_Share_Entry with the selected group
      // but don't pre-generate a keypair, yet.
      Key_Share_Entry(const TLS::Group_Params group) : m_group(group) {}

      Key_Share_Entry(const TLS::Group_Params group, Callbacks& cb, RandomNumberGenerator& rng) :
            m_group(group), m_private_key(cb.tls_kem_generate_key(group, rng)) {
         if(!m_private_key) {
            throw TLS_Exception(Alert::InternalError, "Application did not provide a suitable ephemeral key pair");
         }

         if(group.is_kem()) {
            m_key_exchange = m_private_key->public_key_bits();
         } else if(group.is_ecdh_named_curve()) {
            auto pkey = dynamic_cast<ECDH_PublicKey*>(m_private_key.get());
            if(!pkey) {
               throw TLS_Exception(Alert::InternalError, "Application did not provide a ECDH_PublicKey");
            }

            // RFC 8446 Ch. 4.2.8.2
            //
            //   Note: Versions of TLS prior to 1.3 permitted point format
            //   negotiation; TLS 1.3 removes this feature in favor of a single point
            //   format for each curve.
            //
            // Hence, we neither need to take Policy::use_ecc_point_compression() nor
            // ClientHello::prefers_compressed_ec_points() into account here.
            m_key_exchange = pkey->public_value(EC_Point_Format::Uncompressed);
         } else {
            auto pkey = dynamic_cast<PK_Key_Agreement_Key*>(m_private_key.get());
            if(!pkey) {
               throw TLS_Exception(Alert::InternalError, "Application did not provide a key-agreement key");
            }

            m_key_exchange = pkey->public_value();
         }
      }

      bool empty() const { return (m_group == Group_Params::NONE) && m_key_exchange.empty(); }

      std::vector<uint8_t> serialize() const {
         std::vector<uint8_t> result;
         result.reserve(m_key_exchange.size() + 4);

         const uint16_t named_curve_id = m_group.wire_code();
         result.push_back(get_byte<0>(named_curve_id));
         result.push_back(get_byte<1>(named_curve_id));
         append_tls_length_value(result, m_key_exchange, 2);

         return result;
      }

      Named_Group group() const { return m_group; }

      secure_vector<uint8_t> encapsulate(const Key_Share_Entry& client_share,
                                         const Policy& policy,
                                         Callbacks& cb,
                                         RandomNumberGenerator& rng) {
         auto [encapsulated_shared_key, shared_key] =
            KEM_Encapsulation::destructure(cb.tls_kem_encapsulate(m_group, client_share.m_key_exchange, rng, policy));
         m_key_exchange = std::move(encapsulated_shared_key);
         return std::move(shared_key);
      }

      /**
       * Perform KEM decapsulation with another Key_Share_Entry's public key
       *
       * The caller must ensure that both this and `received` have the same group.
       * This method must not be called on Key_Share_Entries without a private key.
       */
      secure_vector<uint8_t> decapsulate(const Key_Share_Entry& received,
                                         const Policy& policy,
                                         Callbacks& cb,
                                         RandomNumberGenerator& rng) {
         BOTAN_ASSERT_NOMSG(m_group == received.m_group);
         BOTAN_STATE_CHECK(m_private_key != nullptr);

         auto shared_secret = cb.tls_kem_decapsulate(m_group, *m_private_key, received.m_key_exchange, rng, policy);
         m_private_key.reset();

         // RFC 8422 - 5.11.
         //   With X25519 and X448, a receiving party MUST check whether the
         //   computed premaster secret is the all-zero value and abort the
         //   handshake if so, as described in Section 6 of [RFC7748].
         if((m_group == Named_Group::X25519 || m_group == Named_Group::X448) &&
            CT::all_zeros(shared_secret.data(), shared_secret.size()).as_bool()) {
            throw TLS_Exception(Alert::DecryptError, "Bad X25519 or X448 key exchange");
         }

         return shared_secret;
      }

   private:
      Named_Group m_group;
      std::vector<uint8_t> m_key_exchange;
      std::unique_ptr<Private_Key> m_private_key;
};

class Key_Share_ClientHello;

class Key_Share_ServerHello {
   public:
      Key_Share_ServerHello(TLS_Data_Reader& reader, uint16_t) : m_server_share(reader) {}

      Key_Share_ServerHello(Named_Group group,
                            const Key_Share_ClientHello& client_keyshare,
                            const Policy& policy,
                            Callbacks& cb,
                            RandomNumberGenerator& rng);

      ~Key_Share_ServerHello() = default;

      Key_Share_ServerHello(const Key_Share_ServerHello&) = delete;
      Key_Share_ServerHello& operator=(const Key_Share_ServerHello&) = delete;

      Key_Share_ServerHello(Key_Share_ServerHello&&) = default;
      Key_Share_ServerHello& operator=(Key_Share_ServerHello&&) = default;

      std::vector<uint8_t> serialize() const { return m_server_share.serialize(); }

      bool empty() const { return m_server_share.empty(); }

      Key_Share_Entry& get_singleton_entry() { return m_server_share; }

      const Key_Share_Entry& get_singleton_entry() const { return m_server_share; }

      std::vector<Named_Group> offered_groups() const { return {selected_group()}; }

      Named_Group selected_group() const { return m_server_share.group(); }

      secure_vector<uint8_t> take_shared_secret() {
         BOTAN_STATE_CHECK(!m_shared_secret.empty());
         return std::exchange(m_shared_secret, {});
      }

   private:
      Key_Share_Entry m_server_share;
      secure_vector<uint8_t> m_shared_secret;
};

class Key_Share_ClientHello {
   public:
      Key_Share_ClientHello(TLS_Data_Reader& reader, uint16_t /* extension_size */) {
         // This construction is a crutch to make working with the incoming
         // TLS_Data_Reader bearable. Currently, this reader spans the entire
         // Client_Hello message. Hence, if offset or length fields are skewed
         // or maliciously fabricated, it is possible to read further than the
         // bounds of the current extension.
         // Note that this aplies to many locations in the code base.
         //
         // TODO: Overhaul the TLS_Data_Reader to allow for cheap "sub-readers"
         //       that enforce read bounds of sub-structures while parsing.
         const auto client_key_share_length = reader.get_uint16_t();
         const auto read_bytes_so_far_begin = reader.read_so_far();
         auto remaining = [&] {
            const auto read_so_far = reader.read_so_far() - read_bytes_so_far_begin;
            BOTAN_STATE_CHECK(read_so_far <= client_key_share_length);
            return client_key_share_length - read_so_far;
         };

         while(reader.has_remaining() && remaining() > 0) {
            if(remaining() < 4) {
               throw TLS_Exception(Alert::DecodeError, "Not enough data to read another KeyShareEntry");
            }

            Key_Share_Entry new_entry(reader);

            // RFC 8446 4.2.8
            //    Clients MUST NOT offer multiple KeyShareEntry values for the same
            //    group. [...]
            //    Servers MAY check for violations of these rules and abort the
            //    handshake with an "illegal_parameter" alert if one is violated.
            if(std::find_if(m_client_shares.begin(), m_client_shares.end(), [&](const auto& entry) {
                  return entry.group() == new_entry.group();
               }) != m_client_shares.end()) {
               throw TLS_Exception(Alert::IllegalParameter, "Received multiple key share entries for the same group");
            }

            m_client_shares.emplace_back(std::move(new_entry));
         }

         if((reader.read_so_far() - read_bytes_so_far_begin) != client_key_share_length) {
            throw Decoding_Error("Read bytes are not equal client KeyShare length");
         }
      }

      Key_Share_ClientHello(const Policy& policy, Callbacks& cb, RandomNumberGenerator& rng) {
         const auto supported = policy.key_exchange_groups();
         const auto offers = policy.key_exchange_groups_to_offer();

         // RFC 8446 P. 48
         //
         //   This vector MAY be empty if the client is requesting a
         //   HelloRetryRequest.  Each KeyShareEntry value MUST correspond to a
         //   group offered in the "supported_groups" extension and MUST appear in
         //   the same order.  However, the values MAY be a non-contiguous subset
         //   of the "supported_groups" extension and MAY omit the most preferred
         //   groups.
         //
         // ... hence, we're going through the supported groups and find those that
         //     should be used to offer a key exchange. This will satisfy above spec.
         for(const auto group : supported) {
            if(std::find(offers.begin(), offers.end(), group) == offers.end()) {
               continue;
            }
            m_client_shares.emplace_back(group, cb, rng);
         }
      }

      ~Key_Share_ClientHello() = default;

      Key_Share_ClientHello(const Key_Share_ClientHello&) = delete;
      Key_Share_ClientHello& operator=(const Key_Share_ClientHello&) = delete;

      Key_Share_ClientHello(Key_Share_ClientHello&&) = default;
      Key_Share_ClientHello& operator=(Key_Share_ClientHello&&) = default;

      void retry_offer(const TLS::Group_Params to_offer, Callbacks& cb, RandomNumberGenerator& rng) {
         // RFC 8446 4.2.8
         //    The selected_group field [MUST] not correspond to a group which was provided
         //    in the "key_share" extension in the original ClientHello.
         if(std::find_if(m_client_shares.cbegin(), m_client_shares.cend(), [&](const auto& kse) {
               return kse.group() == to_offer;
            }) != m_client_shares.cend()) {
            throw TLS_Exception(Alert::IllegalParameter, "group was already offered");
         }

         m_client_shares.clear();
         m_client_shares.emplace_back(to_offer, cb, rng);
      }

      std::vector<Named_Group> offered_groups() const {
         std::vector<Named_Group> offered_groups;
         offered_groups.reserve(m_client_shares.size());
         for(const auto& share : m_client_shares) {
            offered_groups.push_back(share.group());
         }
         return offered_groups;
      }

      Named_Group selected_group() const { throw Invalid_Argument("Client Hello Key Share does not select a group"); }

      std::vector<uint8_t> serialize() const {
         std::vector<uint8_t> shares;
         for(const auto& share : m_client_shares) {
            const auto serialized_share = share.serialize();
            shares.insert(shares.end(), serialized_share.cbegin(), serialized_share.cend());
         }

         std::vector<uint8_t> result;
         append_tls_length_value(result, shares, 2);
         return result;
      }

      bool empty() const {
         // RFC 8446 4.2.8
         //    Clients MAY send an empty client_shares vector in order to request
         //    group selection from the server, at the cost of an additional round
         //    trip [...].
         return false;
      }

      secure_vector<uint8_t> encapsulate(Key_Share_ServerHello& server_share,
                                         const Policy& policy,
                                         Callbacks& cb,
                                         RandomNumberGenerator& rng) const {
         auto& server_selected = server_share.get_singleton_entry();

         // find the client offer that matches the server offer
         auto match = std::find_if(m_client_shares.begin(), m_client_shares.end(), [&](const auto& offered) {
            return offered.group() == server_selected.group();
         });

         // We validated that the selected group was indeed offered by the
         // client before even constructing the Server Hello that contains the
         // Key_Share_ServerHello extension.
         BOTAN_STATE_CHECK(match != m_client_shares.end());

         return server_selected.encapsulate(*match, policy, cb, rng);
      }

      secure_vector<uint8_t> decapsulate(const Key_Share_ServerHello& server_share,
                                         const Policy& policy,
                                         Callbacks& cb,
                                         RandomNumberGenerator& rng) {
         const auto& server_selected = server_share.get_singleton_entry();

         // find the client offer that matches the server offer
         auto match = std::find_if(m_client_shares.begin(), m_client_shares.end(), [&](const auto& offered) {
            return offered.group() == server_selected.group();
         });

         // RFC 8446 4.2.8:
         //   [The KeyShareEntry in the ServerHello] MUST be in the same group
         //   as the KeyShareEntry value offered by the client that the server
         //   has selected for the negotiated key exchange.
         if(match == m_client_shares.end()) {
            throw TLS_Exception(Alert::IllegalParameter, "Server selected a key exchange group we didn't offer.");
         }

         return match->decapsulate(server_selected, policy, cb, rng);
      }

   private:
      std::vector<Key_Share_Entry> m_client_shares;
};

Key_Share_ServerHello::Key_Share_ServerHello(Named_Group group,
                                             const Key_Share_ClientHello& client_keyshare,
                                             const Policy& policy,
                                             Callbacks& cb,
                                             RandomNumberGenerator& rng) :
      m_server_share(group) {
   m_shared_secret = client_keyshare.encapsulate(*this, policy, cb, rng);
}

class Key_Share_HelloRetryRequest {
   public:
      Key_Share_HelloRetryRequest(TLS_Data_Reader& reader, uint16_t extension_size) {
         constexpr auto sizeof_uint16_t = sizeof(uint16_t);

         if(extension_size != sizeof_uint16_t) {
            throw Decoding_Error("Size of KeyShare extension in HelloRetryRequest must be " +
                                 std::to_string(sizeof_uint16_t) + " bytes");
         }

         m_selected_group = static_cast<Named_Group>(reader.get_uint16_t());
      }

      Key_Share_HelloRetryRequest(Named_Group selected_group) : m_selected_group(selected_group) {}

      ~Key_Share_HelloRetryRequest() = default;

      Key_Share_HelloRetryRequest(const Key_Share_HelloRetryRequest&) = delete;
      Key_Share_HelloRetryRequest& operator=(const Key_Share_HelloRetryRequest&) = delete;

      Key_Share_HelloRetryRequest(Key_Share_HelloRetryRequest&&) = default;
      Key_Share_HelloRetryRequest& operator=(Key_Share_HelloRetryRequest&&) = default;

      std::vector<uint8_t> serialize() const {
         auto code = m_selected_group.wire_code();
         return {get_byte<0>(code), get_byte<1>(code)};
      }

      Named_Group selected_group() const { return m_selected_group; }

      std::vector<Named_Group> offered_groups() const {
         throw Invalid_Argument("Hello Retry Request never offers any key exchange groups");
      }

      bool empty() const { return m_selected_group == Group_Params::NONE; }

   private:
      Named_Group m_selected_group;
};

}  // namespace

class Key_Share::Key_Share_Impl {
   public:
      using Key_Share_Type = std::variant<Key_Share_ClientHello, Key_Share_ServerHello, Key_Share_HelloRetryRequest>;

      Key_Share_Impl(Key_Share_Type ks) : key_share(std::move(ks)) {}

      // NOLINTNEXTLINE(*-non-private-member-variables-in-classes)
      Key_Share_Type key_share;
};

Key_Share::Key_Share(TLS_Data_Reader& reader, uint16_t extension_size, Handshake_Type message_type) {
   if(message_type == Handshake_Type::ClientHello) {
      m_impl = std::make_unique<Key_Share_Impl>(Key_Share_ClientHello(reader, extension_size));
   } else if(message_type == Handshake_Type::HelloRetryRequest)  // Connection_Side::Server
   {
      m_impl = std::make_unique<Key_Share_Impl>(Key_Share_HelloRetryRequest(reader, extension_size));
   } else if(message_type == Handshake_Type::ServerHello)  // Connection_Side::Server
   {
      m_impl = std::make_unique<Key_Share_Impl>(Key_Share_ServerHello(reader, extension_size));
   } else {
      throw Invalid_Argument(std::string("cannot create a Key_Share extension for message of type: ") +
                             handshake_type_to_string(message_type));
   }
}

// ClientHello
Key_Share::Key_Share(const Policy& policy, Callbacks& cb, RandomNumberGenerator& rng) :
      m_impl(std::make_unique<Key_Share_Impl>(Key_Share_ClientHello(policy, cb, rng))) {}

// HelloRetryRequest
Key_Share::Key_Share(Named_Group selected_group) :
      m_impl(std::make_unique<Key_Share_Impl>(Key_Share_HelloRetryRequest(selected_group))) {}

// ServerHello
Key_Share::Key_Share(Group_Params selected_group,
                     const Key_Share& client_keyshare,
                     const Policy& policy,
                     Callbacks& cb,
                     RandomNumberGenerator& rng) :
      m_impl(std::make_unique<Key_Share_Impl>(Key_Share_ServerHello(
         selected_group, std::get<Key_Share_ClientHello>(client_keyshare.m_impl->key_share), policy, cb, rng))) {}

Key_Share::~Key_Share() = default;

std::vector<uint8_t> Key_Share::serialize(Connection_Side /*whoami*/) const {
   return std::visit([](const auto& key_share) { return key_share.serialize(); }, m_impl->key_share);
}

bool Key_Share::empty() const {
   return std::visit([](const auto& key_share) { return key_share.empty(); }, m_impl->key_share);
}

std::unique_ptr<Key_Share> Key_Share::create_as_encapsulation(Group_Params selected_group,
                                                              const Key_Share& client_keyshare,
                                                              const Policy& policy,
                                                              Callbacks& cb,
                                                              RandomNumberGenerator& rng) {
   return std::unique_ptr<Key_Share>(new Key_Share(selected_group, client_keyshare, policy, cb, rng));
}

secure_vector<uint8_t> Key_Share::decapsulate(const Key_Share& server_keyshare,
                                              const Policy& policy,
                                              Callbacks& cb,
                                              RandomNumberGenerator& rng) {
   return std::visit(overloaded{[&](Key_Share_ClientHello& ch, const Key_Share_ServerHello& sh) {
                                   return ch.decapsulate(sh, policy, cb, rng);
                                },
                                [](const auto&, const auto&) -> secure_vector<uint8_t> {
                                   throw Invalid_Argument(
                                      "can only decapsulate in ClientHello Key_Share with a ServerHello Key_Share");
                                }},
                     m_impl->key_share,
                     server_keyshare.m_impl->key_share);
}

std::vector<Named_Group> Key_Share::offered_groups() const {
   return std::visit([](const auto& keyshare) { return keyshare.offered_groups(); }, m_impl->key_share);
}

Named_Group Key_Share::selected_group() const {
   return std::visit([](const auto& keyshare) { return keyshare.selected_group(); }, m_impl->key_share);
}

secure_vector<uint8_t> Key_Share::take_shared_secret() {
   return std::visit(
      overloaded{[](Key_Share_ServerHello& server_keyshare) { return server_keyshare.take_shared_secret(); },
                 [](auto&) -> secure_vector<uint8_t> {
                    throw Invalid_Argument("Only the key share in Server Hello contains a shared secret");
                 }},
      m_impl->key_share);
}

void Key_Share::retry_offer(const Key_Share& retry_request_keyshare,
                            const std::vector<Named_Group>& supported_groups,
                            Callbacks& cb,
                            RandomNumberGenerator& rng) {
   std::visit(overloaded{[&](Key_Share_ClientHello& ch, const Key_Share_HelloRetryRequest& hrr) {
                            auto selected = hrr.selected_group();
                            // RFC 8446 4.2.8
                            //    [T]he selected_group field [MUST correspond] to a group which was provided in
                            //    the "supported_groups" extension in the original ClientHello
                            if(!value_exists(supported_groups, selected)) {
                               throw TLS_Exception(Alert::IllegalParameter, "group was not advertised as supported");
                            }

                            return ch.retry_offer(selected, cb, rng);
                         },
                         [](const auto&, const auto&) {
                            throw Invalid_Argument("can only retry with HelloRetryRequest on a ClientHello Key_Share");
                         }},
              m_impl->key_share,
              retry_request_keyshare.m_impl->key_share);
}

}  // namespace Botan::TLS
