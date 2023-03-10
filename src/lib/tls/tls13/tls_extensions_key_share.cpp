/*
* TLS Extension Key Share
* (C) 2011,2012,2015,2016 Jack Lloyd
*     2016 Juraj Somorovsky
*     2021 Elektrobit Automotive GmbH
*     2022 Hannes Rantzsch, René Meusel, neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <functional>
#include <iterator>

#include <botan/tls_extensions.h>
#include <botan/internal/tls_reader.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/tls_callbacks.h>
#include <botan/rng.h>
#include <botan/internal/stl_util.h>

#if defined(BOTAN_HAS_CURVE_25519)
   #include <botan/curve25519.h>
#endif

#include <botan/dh.h>
#include <botan/ecdh.h>
#include <botan/dl_group.h>

namespace Botan::TLS {

namespace {

class Key_Share_Entry
   {
   public:
      Key_Share_Entry(TLS_Data_Reader& reader)
         {
         // TODO check that the group actually exists before casting...
         m_group = static_cast<Named_Group>(reader.get_uint16_t());
         m_key_exchange = reader.get_tls_length_value(2);
         }

      Key_Share_Entry(const TLS::Group_Params group, Callbacks& cb, RandomNumberGenerator& rng)
         : m_group(group)
         , m_private_key(cb.tls_generate_ephemeral_key(group, rng))
         {
         if(!m_private_key)
            {
            throw TLS_Exception(Alert::InternalError,
                                "Application did not provide a suitable ephemeral key pair");
            }

         if(is_ecdh(group))
            {
            auto pkey = dynamic_cast<ECDH_PublicKey*>(m_private_key.get());
            if(!pkey)
               {
               throw TLS_Exception(Alert::InternalError,
                                 "Application did not provide a ECDH_PublicKey");
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
            }
         else
            {
            m_key_exchange = m_private_key->public_value();
            }
         }

      bool empty() const { return (m_group == Group_Params::NONE) && m_key_exchange.empty(); }

      std::vector<uint8_t> serialize() const
         {
         std::vector<uint8_t> result;
         result.reserve(m_key_exchange.size() + 2);

         const uint16_t named_curve_id = static_cast<uint16_t>(m_group);
         result.push_back(get_byte<0>(named_curve_id));
         result.push_back(get_byte<1>(named_curve_id));
         append_tls_length_value(result, m_key_exchange, 2);

         return result;
         }

      Named_Group group() const { return m_group; }

      /**
       * Perform key exchange with another Key_Share_Entry's public key
       *
       * The caller must ensure that both this and `received` have the same group.
       * This method must not be called on Key_Share_Entries without a private key.
       */
      secure_vector<uint8_t> exchange(const Key_Share_Entry& received, const Policy& policy, Callbacks& cb,
                                      RandomNumberGenerator& rng) const
         {
         BOTAN_ASSERT_NOMSG(m_private_key != nullptr);
         BOTAN_ASSERT_NOMSG(m_group == received.m_group);

         return cb.tls_ephemeral_key_agreement(m_group, *m_private_key, received.m_key_exchange, rng, policy);
         }

      void erase()
         {
         m_private_key.reset();
         }

   private:
      Named_Group                           m_group;
      std::vector<uint8_t>                  m_key_exchange;
      std::unique_ptr<PK_Key_Agreement_Key> m_private_key;
   };

class Key_Share_ClientHello;

class Key_Share_ServerHello
   {
   public:
      Key_Share_ServerHello(TLS_Data_Reader& reader, uint16_t)
         : m_server_share(reader) {}
      Key_Share_ServerHello(Named_Group group, Callbacks& cb, RandomNumberGenerator& rng)
         : m_server_share(group, cb, rng) {}

      ~Key_Share_ServerHello() = default;

      Key_Share_ServerHello(const Key_Share_ServerHello&) = delete;
      Key_Share_ServerHello& operator=(const Key_Share_ServerHello&) = delete;

      Key_Share_ServerHello(Key_Share_ServerHello&&) = default;
      Key_Share_ServerHello& operator=(Key_Share_ServerHello&&) = default;

      std::vector<uint8_t> serialize() const
         {
         return m_server_share.serialize();
         }

      bool empty() const
         {
         return m_server_share.empty();
         }

      const Key_Share_Entry& get_singleton_entry() const
         {
         return m_server_share;
         }

      secure_vector<uint8_t> exchange(const Key_Share_ClientHello& client_shares, const Policy& policy, Callbacks& cb,
                                      RandomNumberGenerator& rng) const;

      std::vector<Named_Group> offered_groups() const
         {
         return {selected_group()};
         }

      Named_Group selected_group() const
         {
         return m_server_share.group();
         }

      void erase()
         {
         m_server_share.erase();
         }

   private:
      Key_Share_Entry m_server_share;
   };

class Key_Share_ClientHello
   {
   public:
      Key_Share_ClientHello(TLS_Data_Reader& reader, uint16_t /* extension_size */)
         {
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
         auto remaining = [&]
            {
            const auto read_so_far = reader.read_so_far() - read_bytes_so_far_begin;
            BOTAN_STATE_CHECK(read_so_far <= client_key_share_length);
            return client_key_share_length - read_so_far;
            };

         while(reader.has_remaining() && remaining() > 0)
            {
            if(remaining() < 4)
               {
               throw TLS_Exception(Alert::DecodeError, "Not enough data to read another KeyShareEntry");
               }

            Key_Share_Entry new_entry(reader);

            // RFC 8446 4.2.8
            //    Clients MUST NOT offer multiple KeyShareEntry values for the same
            //    group. [...]
            //    Servers MAY check for violations of these rules and abort the
            //    handshake with an "illegal_parameter" alert if one is violated.
            if(std::find_if(m_client_shares.begin(), m_client_shares.end(),
                            [&](const auto& entry) { return entry.group() == new_entry.group(); } )
               != m_client_shares.end())
               {
               throw TLS_Exception(Alert::IllegalParameter,
                                   "Received multiple key share entries for the same group");
               }

            m_client_shares.emplace_back(std::move(new_entry));
            }

         if((reader.read_so_far() - read_bytes_so_far_begin) != client_key_share_length)
            {
            throw Decoding_Error("Read bytes are not equal client KeyShare length");
            }
         }

      Key_Share_ClientHello(const Policy& policy, Callbacks& cb, RandomNumberGenerator& rng)
         {
         const auto supported = policy.key_exchange_groups();
         const auto offers    = policy.key_exchange_groups_to_offer();

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
         for(const auto group : supported)
            {
            if(std::find(offers.begin(), offers.end(), group) == offers.end())
               {
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

      void retry_offer(const TLS::Group_Params to_offer, Callbacks& cb, RandomNumberGenerator& rng)
         {
         // RFC 8446 4.2.8
         //    The selected_group field [MUST] not correspond to a group which was provided
         //    in the "key_share" extension in the original ClientHello.
         if(std::find_if(m_client_shares.cbegin(), m_client_shares.cend(),
         [&](const auto& kse) { return kse.group() == to_offer; }) !=
         m_client_shares.cend())
            {
            throw TLS_Exception(Alert::IllegalParameter, "group was already offered");
            }

         m_client_shares.clear();
         m_client_shares.emplace_back(to_offer, cb, rng);
         }

      std::vector<Named_Group> offered_groups() const
         {
         std::vector<Named_Group> offered_groups;
         offered_groups.reserve(m_client_shares.size());
         for(const auto& share : m_client_shares)
            offered_groups.push_back(share.group());
         return offered_groups;
         }

      Named_Group selected_group() const
         {
         throw Invalid_Argument("Client Hello Key Share does not select a group");
         }

      std::optional<std::reference_wrapper<const Key_Share_Entry>>
            find_matching_keyshare(const Key_Share_Entry& server_share) const
         {
         auto match = std::find_if(m_client_shares.cbegin(), m_client_shares.cend(), [&](const auto& offered)
            {
            return offered.group() == server_share.group();
            });

         if(match == m_client_shares.end())
            {
            return std::nullopt;
            }

         return *match;
         }

      std::vector<uint8_t> serialize() const
         {
         std::vector<uint8_t> shares;
         for(const auto& share : m_client_shares)
            {
            const auto serialized_share = share.serialize();
            shares.insert(shares.end(), serialized_share.cbegin(), serialized_share.cend());
            }

         std::vector<uint8_t> result;
         append_tls_length_value(result, shares, 2);
         return result;
         }

      bool empty() const
         {
         // RFC 8446 4.2.8
         //    Clients MAY send an empty client_shares vector in order to request
         //    group selection from the server, at the cost of an additional round
         //    trip [...].
         return false;
         }

      secure_vector<uint8_t> exchange(const Key_Share_ServerHello& server_share, const Policy& policy, Callbacks& cb,
                                      RandomNumberGenerator& rng) const
         {
         const auto& server_selected = server_share.get_singleton_entry();

         // find the client offer that matches the server offer
         auto match = find_matching_keyshare(server_selected);

         // RFC 8446 4.2.8:
         //   [The KeyShareEntry in the ServerHello] MUST be in the same group
         //   as the KeyShareEntry value offered by the client that the server
         //   has selected for the negotiated key exchange.  Servers MUST NOT
         //   send a KeyShareEntry for any group not indicated in the client's
         //   "supported_groups" extension [...]
         if(!value_exists(policy.key_exchange_groups(), server_selected.group()) || !match.has_value())
            {
            throw TLS_Exception(Alert::IllegalParameter, "Server selected an unexpected key exchange group.");
            }

         return match->get().exchange(server_selected, policy, cb, rng);
         }

      void erase()
         {
         for(auto& s : m_client_shares)
            { s.erase(); }
         }

   private:
      std::vector<Key_Share_Entry> m_client_shares;
   };


secure_vector<uint8_t> Key_Share_ServerHello::exchange(const Key_Share_ClientHello& client_shares, const Policy& policy,
      Callbacks& cb,
      RandomNumberGenerator& rng) const
   {
   const auto client_share = client_shares.find_matching_keyshare(m_server_share);

   // The server hello was created based on the client hello's key share set.
   BOTAN_ASSERT_NOMSG(client_share.has_value());

   return m_server_share.exchange(client_share->get(), policy, cb, rng);
   }


class Key_Share_HelloRetryRequest
   {
   public:
      Key_Share_HelloRetryRequest(TLS_Data_Reader& reader,
                                  uint16_t extension_size)
         {
         constexpr auto sizeof_uint16_t = sizeof(uint16_t);

         if(extension_size != sizeof_uint16_t)
            {
            throw Decoding_Error("Size of KeyShare extension in HelloRetryRequest must be " +
                                 std::to_string(sizeof_uint16_t) + " bytes");
            }

         m_selected_group = static_cast<Named_Group>(reader.get_uint16_t());
         }
      Key_Share_HelloRetryRequest(Named_Group selected_group) :
         m_selected_group(selected_group) {}

      ~Key_Share_HelloRetryRequest() = default;

      Key_Share_HelloRetryRequest(const Key_Share_HelloRetryRequest&) = delete;
      Key_Share_HelloRetryRequest& operator=(const Key_Share_HelloRetryRequest&) = delete;

      Key_Share_HelloRetryRequest(Key_Share_HelloRetryRequest&&) = default;
      Key_Share_HelloRetryRequest& operator=(Key_Share_HelloRetryRequest&&) = default;

      std::vector<uint8_t> serialize() const
         {
         return { get_byte<0>(static_cast<uint16_t>(m_selected_group)),
                  get_byte<1>(static_cast<uint16_t>(m_selected_group)) };
         }

      Named_Group selected_group() const
         {
         return m_selected_group;
         }

      std::vector<Named_Group> offered_groups() const
         {
         throw Invalid_Argument("Hello Retry Request never offers any key exchange groups");
         }

      bool empty() const
         {
         return m_selected_group == Group_Params::NONE;
         }

      void erase() {}

   private:
      Named_Group m_selected_group;
   };

}  // namespace

class Key_Share::Key_Share_Impl
   {
   public:
      using Key_Share_Type = std::variant<Key_Share_ClientHello, Key_Share_ServerHello, Key_Share_HelloRetryRequest>;

      Key_Share_Impl(Key_Share_Type ks) : key_share(std::move(ks)) {}

      Key_Share_Type key_share;
   };

Key_Share::Key_Share(TLS_Data_Reader& reader,
                     uint16_t extension_size,
                     Handshake_Type message_type)
   {
   if(message_type == Handshake_Type::ClientHello)
      {
      m_impl = std::make_unique<Key_Share_Impl>(Key_Share_ClientHello(reader, extension_size));
      }
   else if(message_type == Handshake_Type::HelloRetryRequest)  // Connection_Side::Server
      {
      m_impl = std::make_unique<Key_Share_Impl>(Key_Share_HelloRetryRequest(reader, extension_size));
      }
   else if(message_type == Handshake_Type::ServerHello)  // Connection_Side::Server
      {
      m_impl = std::make_unique<Key_Share_Impl>(Key_Share_ServerHello(reader, extension_size));
      }
   else
      {
      throw Invalid_Argument(std::string("cannot create a Key_Share extension for message of type: ") +
                             handshake_type_to_string(message_type));
      }
   }

// ClientHello
Key_Share::Key_Share(const Policy& policy, Callbacks& cb, RandomNumberGenerator& rng) :
   m_impl(std::make_unique<Key_Share_Impl>(Key_Share_ClientHello(policy, cb, rng))) {}

// ServerHello
Key_Share::Key_Share(Named_Group group, Callbacks& cb, RandomNumberGenerator& rng) :
   m_impl(std::make_unique<Key_Share_Impl>(Key_Share_ServerHello(group, cb, rng))) {}

// HelloRetryRequest
Key_Share::Key_Share(Named_Group selected_group) :
   m_impl(std::make_unique<Key_Share_Impl>(Key_Share_HelloRetryRequest(selected_group))) {}

Key_Share::~Key_Share() = default;

std::vector<uint8_t> Key_Share::serialize(Connection_Side /*whoami*/) const
   {
   return std::visit([](const auto& key_share) { return key_share.serialize(); }, m_impl->key_share);
   }

bool Key_Share::empty() const
   {
   return std::visit([](const auto& key_share) { return key_share.empty(); }, m_impl->key_share);
   }

secure_vector<uint8_t> Key_Share::exchange(const Key_Share& peer_keyshare,
      const Policy& policy,
      Callbacks& cb,
      RandomNumberGenerator& rng) const
   {
   return std::visit(overloaded
      {
      [&](const Key_Share_ClientHello& ch, const Key_Share_ServerHello& sh)
         {
         return ch.exchange(sh, policy, cb, rng);
         },
      [&](const Key_Share_ServerHello& sh, const Key_Share_ClientHello& ch)
         {
         return sh.exchange(ch, policy, cb, rng);
         },
      [](const auto&, const auto&) -> secure_vector<uint8_t>
         {
         throw Invalid_Argument("can only exchange with ServerHello and ClientHello Key_Share");
         }
      }, m_impl->key_share, peer_keyshare.m_impl->key_share);
   }

std::vector<Named_Group> Key_Share::offered_groups() const
   {
   return std::visit([](const auto& keyshare)
         { return keyshare.offered_groups(); },
         m_impl->key_share);
   }


Named_Group Key_Share::selected_group() const
   {
   return std::visit([](const auto& keyshare)
         { return keyshare.selected_group(); },
         m_impl->key_share);
   }

void Key_Share::retry_offer(const Key_Share& retry_request_keyshare,
                            const std::vector<Named_Group>& supported_groups,
                            Callbacks& cb,
                            RandomNumberGenerator& rng)
   {
   std::visit(overloaded
      {
      [&](Key_Share_ClientHello& ch, const Key_Share_HelloRetryRequest& hrr)
         {
         auto selected = hrr.selected_group();
         // RFC 8446 4.2.8
         //    [T]he selected_group field [MUST correspond] to a group which was provided in
         //    the "supported_groups" extension in the original ClientHello
         if(!value_exists(supported_groups, selected))
            { throw TLS_Exception(Alert::IllegalParameter, "group was not advertised as supported"); }

         return ch.retry_offer(selected, cb, rng);
         },
      [](const auto&, const auto&)
         {
         throw Invalid_Argument("can only retry with HelloRetryRequest on a ClientHello Key_Share");
         }
      }, m_impl->key_share, retry_request_keyshare.m_impl->key_share);
   }

void Key_Share::erase()
   {
   std::visit([](auto& key_share) { key_share.erase(); }, m_impl->key_share);
   }

}  // Botan::TLS
