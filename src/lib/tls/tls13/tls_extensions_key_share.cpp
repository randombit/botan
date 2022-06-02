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

namespace Botan::TLS {

namespace {

[[maybe_unused]] constexpr bool is_x25519(const Group_Params group)
   {
   return group == Group_Params::X25519;
   }

[[maybe_unused]] constexpr bool is_ecdh(const Group_Params group)
   {
   return
      group == Group_Params::SECP256R1      ||
      group == Group_Params::SECP384R1      ||
      group == Group_Params::SECP521R1      ||
      group == Group_Params::BRAINPOOL256R1 ||
      group == Group_Params::BRAINPOOL384R1 ||
      group == Group_Params::BRAINPOOL512R1;
   }

[[maybe_unused]] constexpr bool is_dh(const Group_Params group)
   {
   return
      group == Group_Params::FFDHE_2048 ||
      group == Group_Params::FFDHE_3072 ||
      group == Group_Params::FFDHE_4096 ||
      group == Group_Params::FFDHE_6144 ||
      group == Group_Params::FFDHE_8192;
   }

class Key_Share_Entry
   {
   public:
      Key_Share_Entry(TLS_Data_Reader& reader)
         {
         // TODO check that the group actually exists before casting...
         m_group = static_cast<Named_Group>(reader.get_uint16_t());
         const auto key_exchange_length = reader.get_uint16_t();
         m_key_exchange = reader.get_fixed<uint8_t>(key_exchange_length);
         }

      Key_Share_Entry(Named_Group group, std::vector<uint8_t> key_exchange)
         : m_group(group)
         , m_key_exchange(std::move(key_exchange))
         {
         if(m_key_exchange.empty())
            {
            throw Decoding_Error("Size of key_exchange in KeyShareEntry must be at least 1 byte.");
            }
         }

      Key_Share_Entry(const TLS::Group_Params group, Callbacks& cb, RandomNumberGenerator& rng)
         : m_group(group)
         {
         if(is_ecdh(group))
            {
            const EC_Group ec_group(cb.tls_decode_group_param(group));
            auto skey = std::make_unique<ECDH_PrivateKey>(rng, ec_group);

            // RFC 8446 Ch. 4.2.8.2
            //
            //   Note: Versions of TLS prior to 1.3 permitted point format
            //   negotiation; TLS 1.3 removes this feature in favor of a single point
            //   format for each curve.
            //
            // Hence, we neither need to take Policy::use_ecc_point_compression() nor
            // ClientHello::prefers_compressed_ec_points() into account here.
            m_key_exchange = skey->public_value(PointGFp::UNCOMPRESSED);
            m_private_key = std::move(skey);
            }
         else if(is_dh(group))
            {
            // RFC 8446 Ch. 4.2.8.1
            //
            //   The opaque value contains the Diffie-Hellman
            //   public value (Y = g^X mod p) for the specified group (see [RFC7919]
            //   for group definitions) encoded as a big-endian integer and padded to
            //   the left with zeros to the size of p in bytes.
            auto skey = std::make_unique<DH_PrivateKey>(rng, DL_Group(cb.tls_decode_group_param(group)));
            m_key_exchange = skey->public_value();
            m_private_key = std::move(skey);
            }
#if defined(BOTAN_HAS_CURVE_25519)
         else if(is_x25519(group))
            {
            auto skey = std::make_unique<X25519_PrivateKey>(rng);
            m_key_exchange = skey->public_value();
            m_private_key = std::move(skey);
            }
#endif
         else
            {
            throw Decoding_Error("cannot create a key offering without a group definition");
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

         PK_Key_Agreement ka(*m_private_key, rng, "Raw");

         if(is_ecdh(m_group))
            {
            const EC_Group ec_group(cb.tls_decode_group_param(m_group));
            ECDH_PublicKey peer_key(ec_group, ec_group.OS2ECP(received.m_key_exchange));
            policy.check_peer_key_acceptable(peer_key);

            return ka.derive_key(0, peer_key.public_value()).bits_of();
            }

         if(is_dh(m_group))
            {
            const DL_Group dl_group(cb.tls_decode_group_param(m_group));

            if(!dl_group.verify_group(rng, false))
               { throw TLS_Exception(Alert::INSUFFICIENT_SECURITY, "DH group validation failed"); }

            DH_PublicKey peer_key(dl_group, BigInt::decode(received.m_key_exchange));
            policy.check_peer_key_acceptable(peer_key);

            // Note: in contrast to TLS 1.2, no leading zeros are stripped here
            // cf. RFC 8446 7.4.1
            return ka.derive_key(0, peer_key.public_value()).bits_of();
            }

#if defined(BOTAN_HAS_CURVE_25519)
         if(is_x25519(m_group))
            {
            if(received.m_key_exchange.size() != 32)
               {
               throw TLS_Exception(Alert::HANDSHAKE_FAILURE, "Invalid X25519 key size");
               }

            Curve25519_PublicKey peer_key(received.m_key_exchange);
            policy.check_peer_key_acceptable(peer_key);

            return ka.derive_key(0, peer_key.public_value()).bits_of();
            }
#endif

         BOTAN_ASSERT_NOMSG(false);
         }

      void erase()
         {
         m_private_key.reset();
         }

   private:
      Named_Group                  m_group;
      std::vector<uint8_t>         m_key_exchange;
      std::unique_ptr<Private_Key> m_private_key;
   };

class Key_Share_ServerHello
   {
   public:
      Key_Share_ServerHello(TLS_Data_Reader& reader, uint16_t)
         : m_server_share(reader) {}
      ~Key_Share_ServerHello() = default;

      Key_Share_ServerHello(const Key_Share_ServerHello&) = delete;
      Key_Share_ServerHello& operator=(const Key_Share_ServerHello&) = delete;

      Key_Share_ServerHello(Key_Share_ServerHello&&) = default;
      Key_Share_ServerHello& operator=(Key_Share_ServerHello&&) = default;

      std::vector<uint8_t> serialize() const
         {
         std::vector<uint8_t> buf;

         const auto server_share_serialized = m_server_share.serialize();
         buf.insert(buf.end(), server_share_serialized.cbegin(), server_share_serialized.cend());

         return buf;
         }

      bool empty() const
         {
         return m_server_share.empty();
         }

      const Key_Share_Entry& get_singleton_entry() const
         {
         return m_server_share;
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
         const auto client_key_share_length = reader.get_uint16_t();
         const auto read_bytes_so_far_begin = reader.read_so_far();

         while(reader.has_remaining() && ((reader.read_so_far() - read_bytes_so_far_begin) < client_key_share_length))
            {
            const auto group = reader.get_uint16_t();
            const auto key_exchange_length = reader.get_uint16_t();

            if(key_exchange_length > reader.remaining_bytes())
               {
               throw Decoding_Error("Not enough bytes in the buffer to decode KeyShare (ClientHello) extension");
               }

            std::vector<uint8_t> client_share;
            client_share.reserve(key_exchange_length);

            for(auto i = 0u; i < key_exchange_length; ++i)
               {
               client_share.push_back(reader.get_byte());
               }

            m_client_shares.emplace_back(static_cast<Named_Group>(group), client_share);
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
            throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "group was already offered");
            }

         m_client_shares.clear();
         m_client_shares.emplace_back(to_offer, cb, rng);
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
         auto match = std::find_if(m_client_shares.cbegin(), m_client_shares.cend(), [&server_selected](const auto& offered)
            {
            return offered.group() == server_selected.group();
            });

         // RFC 8446 4.2.8:
         //   [The KeyShareEntry in the ServerHello] MUST be in the same group
         //   as the KeyShareEntry value offered by the client that the server
         //   has selected for the negotiated key exchange.  Servers MUST NOT
         //   send a KeyShareEntry for any group not indicated in the client's
         //   "supported_groups" extension [...]
         if(!value_exists(policy.key_exchange_groups(), server_selected.group()) ||
               match == m_client_shares.cend())
            {
            throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "Server selected an unexpected key exchange group.");
            }

         return match->exchange(server_selected, policy, cb, rng);
         }

      void erase()
         {
         for(auto& s : m_client_shares)
            { s.erase(); }
         }

   private:
      std::vector<Key_Share_Entry> m_client_shares;
   };

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

      Named_Group get_selected_group() const
         {
         return m_selected_group;
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
   if(message_type == CLIENT_HELLO)
      {
      m_impl = std::make_unique<Key_Share_Impl>(Key_Share_ClientHello(reader, extension_size));
      }
   else if(message_type == HELLO_RETRY_REQUEST)  // Connection_Side::SERVER
      {
      m_impl = std::make_unique<Key_Share_Impl>(Key_Share_HelloRetryRequest(reader, extension_size));
      }
   else if(message_type == SERVER_HELLO)  // Connection_Side::SERVER
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

Key_Share::~Key_Share() {}

std::vector<uint8_t> Key_Share::serialize(Connection_Side /*whoami*/) const
   {
   return std::visit([](const auto& key_share) { return key_share.serialize(); }, m_impl->key_share);
   }

bool Key_Share::empty() const
   {
   return std::visit([](const auto& key_share) { return key_share.empty(); }, m_impl->key_share);
   }

namespace {
// This is a helper utility to emulate pattern matching with std::visit.
// See https://en.cppreference.com/w/cpp/utility/variant/visit for more info.
template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
// explicit deduction guide (not needed as of C++20)
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;
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
         return ch.exchange(sh, policy, cb, rng);
         },
      [](const auto&, const auto&) -> secure_vector<uint8_t>
         {
         throw Botan::Invalid_Argument("can only exchange with ServerHello and ClientHello Key_Share");
         }
      }, m_impl->key_share, peer_keyshare.m_impl->key_share);
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
         auto selected = hrr.get_selected_group();
         // RFC 8446 4.2.8
         //    [T]he selected_group field [MUST correspond] to a group which was provided in
         //    the "supported_groups" extension in the original ClientHello
         if(!value_exists(supported_groups, selected))
            { throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "group was not advertised as supported"); }

         return ch.retry_offer(selected, cb, rng);
         },
      [](const auto&, const auto&)
         {
         throw Botan::Invalid_Argument("can only retry with HelloRetryRequest on a ClientHello Key_Share");
         }
      }, m_impl->key_share, retry_request_keyshare.m_impl->key_share);
   }

void Key_Share::erase()
   {
   std::visit([](auto& key_share) { key_share.erase(); }, m_impl->key_share);
   }

}  // Botan::TLS
