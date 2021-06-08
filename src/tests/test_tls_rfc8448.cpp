/*
* (C) 2021 Jack Lloyd
* (C) 2021 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <memory>
#include <utility>
// Since RFC 8448 uses a specific set of cipher suites we can only run this
// test if all of them are enabled.
#if defined(BOTAN_HAS_TLS_13) && \
   defined(BOTAN_HAS_AEAD_CHACHA20_POLY1305) && \
   defined(BOTAN_HAS_AEAD_GCM) && \
   defined(BOTAN_HAS_AES) && \
   defined(BOTAN_HAS_CURVE_25519) && \
   defined(BOTAN_HAS_SHA2_32) && \
   defined(BOTAN_HAS_SHA2_64)
   #define BOTAN_CAN_RUN_TEST_TLS_RFC8448
#endif

#if defined(BOTAN_CAN_RUN_TEST_TLS_RFC8448)
   #include "test_rng.h"
   #include "test_tls_utils.h"

   #include <botan/auto_rng.h>  // TODO: replace me, otherwise we depend on auto_rng module
   #include <botan/credentials_manager.h>
   #include <botan/rsa.h>
   #include <botan/tls_alert.h>
   #include <botan/tls_callbacks.h>
   #include <botan/tls_client.h>
   #include <botan/tls_policy.h>
   #include <botan/tls_messages.h>
   #include <botan/internal/tls_reader.h>
   #include <botan/tls_server.h>
   #include <botan/tls_server_info.h>
   #include <botan/tls_session.h>
   #include <botan/tls_session_manager.h>
   #include <botan/tls_version.h>

   #include <botan/assert.h>
   #include <botan/internal/stl_util.h>

   #include <botan/internal/loadstor.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_CAN_RUN_TEST_TLS_RFC8448)

namespace {
constexpr size_t RECORD_HEADER_SIZE = 5;

template <typename Itr>
decltype(auto) slice(Itr begin, Itr end)
   {
   return std::vector<uint8_t>(begin, end);
   }

void add_entropy(Botan_Tests::Fixed_Output_RNG& rng, const std::string& hex)
   {
   std::vector<uint8_t> in = Botan::hex_decode(hex);
   rng.add_entropy(in.data(), in.size());
   }

Botan::RSA_PrivateKey server_private_key()
   {
   return
      {
      Botan::BigInt("0xE435FB7CC83737756DACEA96AB7F59A2CC1069DB7DEB190E17E33A532B273F30A327AA0AAABC58CD67466AF9845FADC675FE094AF92C4BD1F2C1BC33DD2E0515"),
      Botan::BigInt("0xCABD3BC0E0438664C8D4CC9F99977A94D9BBFEAD8E43870ABAE3F7EB8B4E0EEE8AF1D9B4719BA6196CF2CBBAEEEBF8B3490AFE9E9FFA74A88AA51FC645629303"),
      Botan::BigInt("0x010001")
      };
   }

Botan::X509_Certificate server_certificate()
   {
   // self-signed certificate with an RSA1024 public key
   //
   //   [...]
   //   Issuer: CN=rsa
   //   Validity
   //       Not Before: Jul 30 01:23:59 2016 GMT
   //       Not After : Jul 30 01:23:59 2026 GMT
   //   Subject: CN=rsa
   //   [...]
   //   X509v3 extensions:
   //        X509v3 Basic Constraints:
   //            CA:FALSE
   //        X509v3 Key Usage:
   //            Digital Signature, Key Encipherment
   //   [...]
   return Botan::X509_Certificate(
             Botan::hex_decode(
                "308201ac30820115a003020102020102300d06092a864886f70d01010b050030"
                "0e310c300a06035504031303727361301e170d3136303733303031323335395a"
                "170d3236303733303031323335395a300e310c300a0603550403130372736130"
                "819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f"
                "8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91"
                "d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b"
                "1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbf"
                "ae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f02030100"
                "01a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06"
                "092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a726717"
                "0618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6"
                "c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a4"
                "2a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d"
                "402dcc0cc8f8961229ac9187b42b4de10000")
          );
   }


/**
* Simple version of the Padding extension (RFC 7685) to reproduce the
* 2nd Client_Hello in RFC8448 Section 5 (HelloRetryRequest)
*/
class Padding final : public Botan::TLS::Extension
   {
   public:
      static Botan::TLS::Handshake_Extension_Type static_type()
         { return Botan::TLS::Handshake_Extension_Type(21); }

      Botan::TLS::Handshake_Extension_Type type() const override { return static_type(); }

      explicit Padding(const size_t padding_bytes) :
         m_padding_bytes(padding_bytes) {}

      std::vector<uint8_t> serialize(Botan::TLS::Connection_Side) const override
         {
         return std::vector<uint8_t>(m_padding_bytes, 0x00);
         }

      bool empty() const override { return m_padding_bytes == 0; }
   private:
      size_t m_padding_bytes;
   };

using namespace Botan;
using namespace Botan::TLS;

using Modify_Exts_Fn = std::function<void(Botan::TLS::Extensions&, Botan::TLS::Connection_Side)>;
class Test_TLS_13_Callbacks : public Botan::TLS::Callbacks
   {
   public:
      Test_TLS_13_Callbacks(Modify_Exts_Fn modify_exts_cb) :
         session_activated_called(false), m_modify_exts(std::move(modify_exts_cb))
         {}

      void tls_emit_data(const uint8_t data[], size_t size) override
         {
         count_callback_invocation("tls_emit_data");
         send_buffer.insert(send_buffer.end(), data, data + size);
         }

      void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override
         {
         count_callback_invocation("tls_record_received");
         received_seq_no = seq_no;
         receive_buffer.insert(receive_buffer.end(), data, data + size);
         }

      void tls_alert(Botan::TLS::Alert alert) override
         {
         count_callback_invocation("tls_alert");
         BOTAN_UNUSED(alert);
         // handle a tls alert received from the tls server
         }

      bool tls_session_established(const Botan::TLS::Session& session) override
         {
         count_callback_invocation("tls_session_established");
         BOTAN_UNUSED(session);
         // the session with the tls client was established
         // return false to prevent the session from being cached, true to
         // cache the session in the configured session manager
         return false;
         }

      void tls_session_activated() override
         {
         count_callback_invocation("tls_session_activated");
         session_activated_called = true;
         }

      void tls_verify_cert_chain(
         const std::vector<Botan::X509_Certificate>& cert_chain,
         const std::vector<std::optional<Botan::OCSP::Response>>&,
         const std::vector<Botan::Certificate_Store*>&,
         Botan::Usage_Type,
         const std::string&,
         const Botan::TLS::Policy&) override
         {
         count_callback_invocation("tls_verify_cert_chain");
         certificate_chain = cert_chain;
         }

      std::chrono::milliseconds tls_verify_cert_chain_ocsp_timeout() const override
         {
         count_callback_invocation("tls_verify_cert_chain");
         return std::chrono::milliseconds(0);
         }

      std::vector<uint8_t> tls_provide_cert_status(const std::vector<X509_Certificate>& chain,
            const Certificate_Status_Request& csr) override
         {
         count_callback_invocation("tls_provide_cert_status");
         return Callbacks::tls_provide_cert_status(chain, csr);
         }

      std::vector<uint8_t> tls_sign_message(
         const Private_Key& key,
         RandomNumberGenerator& rng,
         const std::string& emsa,
         Signature_Format format,
         const std::vector<uint8_t>& msg) override
         {
         count_callback_invocation("tls_sign_message");
         return Callbacks::tls_sign_message(key, rng, emsa, format, msg);
         }


      bool tls_verify_message(
         const Public_Key& key,
         const std::string& emsa,
         Signature_Format format,
         const std::vector<uint8_t>& msg,
         const std::vector<uint8_t>& sig) override
         {
         count_callback_invocation("tls_verify_message");
         return Callbacks::tls_verify_message(key, emsa, format, msg, sig);
         }

      std::pair<secure_vector<uint8_t>, std::vector<uint8_t>> tls_dh_agree(
               const std::vector<uint8_t>& modulus,
               const std::vector<uint8_t>& generator,
               const std::vector<uint8_t>& peer_public_value,
               const Policy& policy,
               RandomNumberGenerator& rng) override
         {
         count_callback_invocation("tls_dh_agree");
         return Callbacks::tls_dh_agree(modulus, generator, peer_public_value, policy, rng);
         }

      std::pair<secure_vector<uint8_t>, std::vector<uint8_t>> tls_ecdh_agree(
               const std::string& curve_name,
               const std::vector<uint8_t>& peer_public_value,
               const Policy& policy,
               RandomNumberGenerator& rng,
               bool compressed) override
         {
         count_callback_invocation("tls_ecdh_agree");
         return Callbacks::tls_ecdh_agree(curve_name, peer_public_value, policy, rng, compressed);
         }

      void tls_inspect_handshake_msg(const Handshake_Message& message) override
         {
         count_callback_invocation("tls_inspect_handshake_msg_" + message.type_string());
         return Callbacks::tls_inspect_handshake_msg(message);
         }

      std::string tls_server_choose_app_protocol(const std::vector<std::string>& client_protos) override
         {
         count_callback_invocation("tls_server_choose_app_protocol");
         return Callbacks::tls_server_choose_app_protocol(client_protos);
         }

      void tls_modify_extensions(Botan::TLS::Extensions& exts, Botan::TLS::Connection_Side side) override
         {
         count_callback_invocation("tls_modify_extensions");
         m_modify_exts(exts, side);
         }

      void tls_examine_extensions(const Botan::TLS::Extensions& extn, Connection_Side which_side) override
         {
         count_callback_invocation("tls_examine_extensions");
         return Callbacks::tls_examine_extensions(extn, which_side);
         }

      std::string tls_decode_group_param(Group_Params group_param) override
         {
         count_callback_invocation("tls_decode_group_param");
         return Callbacks::tls_decode_group_param(group_param);
         }

      std::string tls_peer_network_identity() override
         {
         count_callback_invocation("tls_peer_network_identity");
         return Callbacks::tls_peer_network_identity();
         }

      std::vector<uint8_t> pull_send_buffer()
         {
         return std::exchange(send_buffer, std::vector<uint8_t>());
         }

      std::vector<uint8_t> pull_receive_buffer()
         {
         return std::exchange(receive_buffer, std::vector<uint8_t>());
         }

      uint64_t last_received_seq_no() const { return received_seq_no; }

      const std::map<std::string, unsigned int>& callback_invocations() const
         {
         return m_callback_invocations;
         }

      void reset_callback_invocation_counters()
         {
         m_callback_invocations.clear();
         }

   private:
      void count_callback_invocation(const std::string& callback_name) const
         {
         if(m_callback_invocations.count(callback_name) == 0)
            { m_callback_invocations[callback_name] = 0; }

         m_callback_invocations[callback_name]++;
         }

   public:
      bool session_activated_called;

      std::vector<Botan::X509_Certificate> certificate_chain;

   private:
      std::vector<uint8_t> send_buffer;
      std::vector<uint8_t> receive_buffer;
      uint64_t             received_seq_no;
      Modify_Exts_Fn       m_modify_exts;

      mutable std::map<std::string, unsigned int> m_callback_invocations;
   };

class Test_Server_Credentials : public Botan::Credentials_Manager
   {
   public:
      Test_Server_Credentials() : m_key(server_private_key()) {}

      std::vector<Botan::Certificate_Store*>
      trusted_certificate_authorities(const std::string& type, const std::string& context) override
         {
         BOTAN_UNUSED(type, context);
         return {};
         }

      std::vector<Botan::X509_Certificate> cert_chain(
         const std::vector<std::string>& cert_key_types,
         const std::string& type,
         const std::string& context) override
         {
         BOTAN_UNUSED(cert_key_types, type, context);
         return { server_certificate() };
         }

      Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert,
                                          const std::string& type,
                                          const std::string& context) override
         {
         BOTAN_UNUSED(cert, type, context);
         // return the private key associated with the leaf certificate,
         // in this case the one associated with "botan.randombit.net.crt"
         return &m_key;
         }

   private:
      Botan::RSA_PrivateKey m_key;
   };

class RFC8448_Text_Policy : public Botan::TLS::Text_Policy
   {
   public:
      RFC8448_Text_Policy(const Botan::TLS::Text_Policy& other)
         : Text_Policy(other) {}

      std::vector<Botan::TLS::Signature_Scheme> allowed_signature_schemes() const override
         {
         return
            {
            Botan::TLS::Signature_Scheme::ECDSA_SHA256,
            Botan::TLS::Signature_Scheme::ECDSA_SHA384,
            Botan::TLS::Signature_Scheme::ECDSA_SHA512,
            Botan::TLS::Signature_Scheme::ECDSA_SHA1,       // not actually supported
            Botan::TLS::Signature_Scheme::RSA_PSS_SHA256,
            Botan::TLS::Signature_Scheme::RSA_PSS_SHA384,
            Botan::TLS::Signature_Scheme::RSA_PSS_SHA512,
            Botan::TLS::Signature_Scheme::RSA_PKCS1_SHA256,
            Botan::TLS::Signature_Scheme::RSA_PKCS1_SHA384,
            Botan::TLS::Signature_Scheme::RSA_PKCS1_SHA512,
            Botan::TLS::Signature_Scheme::RSA_PKCS1_SHA1,   // not actually supported
            Botan::TLS::Signature_Scheme::DSA_SHA256,       // not actually supported
            Botan::TLS::Signature_Scheme::DSA_SHA384,       // not actually supported
            Botan::TLS::Signature_Scheme::DSA_SHA512,       // not actually supported
            Botan::TLS::Signature_Scheme::DSA_SHA1          // not actually supported
            };
         }
   };

class TLS_Context
   {
   protected:
      TLS_Context(std::unique_ptr<Botan::RandomNumberGenerator> rng_in,
                  RFC8448_Text_Policy policy,
                  Modify_Exts_Fn modify_exts_cb)
         : m_callbacks(std::move(modify_exts_cb))
         , m_rng(std::move(rng_in))
         , m_session_mgr(*m_rng)
         , m_policy(std::move(policy))
         {}

   public:
      virtual ~TLS_Context() = default;

      TLS_Context(TLS_Context&) = delete;
      TLS_Context& operator=(const TLS_Context&) = delete;

      TLS_Context(TLS_Context&&) = delete;
      TLS_Context& operator=(TLS_Context&&) = delete;

      std::vector<uint8_t> pull_send_buffer()
         {
         return m_callbacks.pull_send_buffer();
         }

      std::vector<uint8_t> pull_receive_buffer()
         {
         return m_callbacks.pull_receive_buffer();
         }

      uint64_t last_received_seq_no() const { return m_callbacks.last_received_seq_no(); }

      /**
       * Checks that all of the listed callbacks were called at least once, no other
       * callbacks were called in addition to the expected ones. After the checks are
       * done, the callback invocation counters are reset.
       */
      void check_callback_invocations(Test::Result& result, const std::string& context,
                                      const std::vector<std::string>& callback_names)
         {
         const auto& invokes = m_callbacks.callback_invocations();
         for(const auto& cbn : callback_names)
            {
            result.confirm(cbn + " was invoked (Context: " + context + ")", invokes.count(cbn) > 0 && invokes.at(cbn) > 0);
            }

         for(const auto& invoke : invokes)
            {
            if(invoke.second == 0)
               { continue; }
            result.confirm(invoke.first + " was expected (Context: " + context + ")", std::find(callback_names.cbegin(),
                           callback_names.cend(), invoke.first) != callback_names.cend());
            }

         m_callbacks.reset_callback_invocation_counters();
         }

      const std::vector<Botan::X509_Certificate>& certs_verified() const
         {
         return m_callbacks.certificate_chain;
         }

      virtual void send(const std::vector<uint8_t>& data) = 0;

   protected:
      Test_TLS_13_Callbacks   m_callbacks;
      Test_Server_Credentials m_creds;

      std::unique_ptr<Botan::RandomNumberGenerator> m_rng;
      Botan::TLS::Session_Manager_In_Memory         m_session_mgr;
      RFC8448_Text_Policy                           m_policy;
   };

class Server_Context : public TLS_Context
   {
   public:
      Server_Context(std::unique_ptr<Botan::RandomNumberGenerator> rng_in,
                     RFC8448_Text_Policy policy,
                     Modify_Exts_Fn modify_exts_cb)
         : TLS_Context(std::move(rng_in), std::move(policy), std::move(modify_exts_cb))
         , server(m_callbacks, m_session_mgr, m_creds, m_policy, *m_rng)
         {}

      void send(const std::vector<uint8_t>& data) override
         {
         server.send(data.data(), data.size());
         }

      Botan::TLS::Server server;
   };

class Client_Context : public TLS_Context
   {
   public:
      Client_Context(std::unique_ptr<Botan::RandomNumberGenerator> rng_in,
                     RFC8448_Text_Policy policy,
                     Modify_Exts_Fn modify_exts_cb)
         : TLS_Context(std::move(rng_in), std::move(policy), std::move(modify_exts_cb))
         , client(m_callbacks, m_session_mgr, m_creds, m_policy, *m_rng,
                  Botan::TLS::Server_Information("server"),
                  Botan::TLS::Protocol_Version::TLS_V13)
         {}

      void send(const std::vector<uint8_t>& data) override
         {
         client.send(data.data(), data.size());
         }

      Botan::TLS::Client client;
   };

void sort_extensions(Botan::TLS::Extensions& exts, Botan::TLS::Connection_Side side)
   {
   if(side == Botan::TLS::Connection_Side::CLIENT)
      {
      const std::vector<Botan::TLS::Handshake_Extension_Type> expected_order =
         {
         Botan::TLS::Handshake_Extension_Type::TLSEXT_SERVER_NAME_INDICATION,
         Botan::TLS::Handshake_Extension_Type::TLSEXT_SAFE_RENEGOTIATION,
         Botan::TLS::Handshake_Extension_Type::TLSEXT_SUPPORTED_GROUPS,
         Botan::TLS::Handshake_Extension_Type::TLSEXT_SESSION_TICKET,
         Botan::TLS::Handshake_Extension_Type::TLSEXT_KEY_SHARE,
         Botan::TLS::Handshake_Extension_Type::TLSEXT_SUPPORTED_VERSIONS,
         Botan::TLS::Handshake_Extension_Type::TLSEXT_SIGNATURE_ALGORITHMS,
         Botan::TLS::Handshake_Extension_Type::TLSEXT_COOKIE,
         Botan::TLS::Handshake_Extension_Type::TLSEXT_PSK_KEY_EXCHANGE_MODES,
         Botan::TLS::Handshake_Extension_Type::TLSEXT_RECORD_SIZE_LIMIT,
         Padding::static_type()
         };

      for(const auto ext_type : expected_order)
         {
         auto ext = exts.take(ext_type);
         if(ext != nullptr)
            {
            exts.add(std::move(ext));
            }
         }
      }
   }

void add_psk_exchange_modes(Botan::TLS::Extensions& exts)
   {
   // Currently we do not support PSK and session resumption in TLS 1.3.
   // Hence, we add this extension to please the test vector. The actual
   // resumption is not exercised in this test, though. Once PSK is
   // implemented, this should be removed and added in Client_Hello_13.
   exts.add(new PSK_Key_Exchange_Modes({PSK_Key_Exchange_Mode::PSK_DHE_KE}));
   }

void add_renegotiation_extension(Botan::TLS::Extensions& exts)
   {
   // Renegotiation is not possible in TLS 1.3. Nevertheless, RFC 8448 requires
   // to add this to the Client Hello for reasons.
   exts.add(new Renegotiation_Extension());
   }

}  // namespace

class Test_TLS_RFC8448 final : public Test
   {
   private:
      static Test::Result simple_1_rtt_client_hello()
         {
         Test::Result result("Simple 1-RTT (Client side)");

         // TODO: fixed output RNG is probably not needed as we cannot get the "right"
         //       client hello anyway -- revert
         auto rng = std::make_unique<Botan_Tests::Fixed_Output_RNG>("");
         rng->add_entropy(std::vector<uint8_t>(32).data(), 32);  // used by session mgr for session key
         add_entropy(*rng, "cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7"); // for client hello random

         // for KeyShare extension (RFC 8448: "{client} create an ephemeral x25519 key pair")
         add_entropy(*rng, "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005");

         auto add_extensions_and_sort = [](Botan::TLS::Extensions& exts, Botan::TLS::Connection_Side side)
            {
            // For some reason, presumably checking compatibility, the RFC 8448 Client
            // Hello includes a (TLS 1.2) Session_Ticket extension. We don't normally add
            // this obsoleted extension in a TLS 1.3 client.
            exts.add(new Botan::TLS::Session_Ticket());

            add_psk_exchange_modes(exts);
            add_renegotiation_extension(exts);
            sort_extensions(exts, side);
            };

         Client_Context ctx(std::move(rng), read_tls_policy("rfc8448_1rtt"), add_extensions_and_sort);
         result.confirm("client not closed", !ctx.client.is_closed());
         ctx.check_callback_invocations(result, "client hello prepared", { "tls_emit_data", "tls_inspect_handshake_msg_client_hello", "tls_modify_extensions" });

         const auto client_hello_record = ctx.pull_send_buffer();
         result.test_gte("client hello written", client_hello_record.size(), RECORD_HEADER_SIZE);

         const auto client_hello_msg = slice(client_hello_record.begin() + RECORD_HEADER_SIZE, client_hello_record.end());

         const auto expected_hello = Botan::hex_decode(
                                        "16 03 01 00 c4 01 00 00 c0 03 03 cb"
                                        "34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12"
                                        "ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00"
                                        "00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01"
                                        "00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02"
                                        "01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d"
                                        "e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d"
                                        "54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e"
                                        "04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02"
                                        "01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01");

         result.test_eq("TLS client hello", client_hello_record, expected_hello);

         // header
         //   type: handshake, version: Tls12, len: 90
         // message
         //   version: Tls12, rand_time: 2796488356, rand_data: [...],
         //   session_id: None, cipher: 0x1301(AES_128_GCM_SHA256),
         //   compression: Null, ext: [...]
         const auto server_hello_a = Botan::hex_decode(
                                        "16 03 03 00 5a 02 00 00 56 03 03 a6"
                                        "af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14");
         ctx.client.received_data(server_hello_a);
         ctx.check_callback_invocations(result, "server hello partially received", { });

         // splitting the input data to test partial reads
         const auto server_hello_b = Botan::hex_decode(
                                        "34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00"
                                        "1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6"
                                        "cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04");
         ctx.client.received_data(server_hello_b);
         ctx.check_callback_invocations(result, "server hello received", { "tls_inspect_handshake_msg_server_hello", "tls_examine_extensions" });

         result.confirm("client is not yet active", !ctx.client.is_active());

         const auto server_handshake_messages = Botan::hex_decode(
               "17 03 03 02 a2 d1 ff 33 4a 56 f5 bf"
               "f6 59 4a 07 cc 87 b5 80 23 3f 50 0f 45 e4 89 e7 f3 3a f3 5e df"
               "78 69 fc f4 0a a4 0a a2 b8 ea 73 f8 48 a7 ca 07 61 2e f9 f9 45"
               "cb 96 0b 40 68 90 51 23 ea 78 b1 11 b4 29 ba 91 91 cd 05 d2 a3"
               "89 28 0f 52 61 34 aa dc 7f c7 8c 4b 72 9d f8 28 b5 ec f7 b1 3b"
               "d9 ae fb 0e 57 f2 71 58 5b 8e a9 bb 35 5c 7c 79 02 07 16 cf b9"
               "b1 18 3e f3 ab 20 e3 7d 57 a6 b9 d7 47 76 09 ae e6 e1 22 a4 cf"
               "51 42 73 25 25 0c 7d 0e 50 92 89 44 4c 9b 3a 64 8f 1d 71 03 5d"
               "2e d6 5b 0e 3c dd 0c ba e8 bf 2d 0b 22 78 12 cb b3 60 98 72 55"
               "cc 74 41 10 c4 53 ba a4 fc d6 10 92 8d 80 98 10 e4 b7 ed 1a 8f"
               "d9 91 f0 6a a6 24 82 04 79 7e 36 a6 a7 3b 70 a2 55 9c 09 ea d6"
               "86 94 5b a2 46 ab 66 e5 ed d8 04 4b 4c 6d e3 fc f2 a8 94 41 ac"
               "66 27 2f d8 fb 33 0e f8 19 05 79 b3 68 45 96 c9 60 bd 59 6e ea"
               "52 0a 56 a8 d6 50 f5 63 aa d2 74 09 96 0d ca 63 d3 e6 88 61 1e"
               "a5 e2 2f 44 15 cf 95 38 d5 1a 20 0c 27 03 42 72 96 8a 26 4e d6"
               "54 0c 84 83 8d 89 f7 2c 24 46 1a ad 6d 26 f5 9e ca ba 9a cb bb"
               "31 7b 66 d9 02 f4 f2 92 a3 6a c1 b6 39 c6 37 ce 34 31 17 b6 59"
               "62 22 45 31 7b 49 ee da 0c 62 58 f1 00 d7 d9 61 ff b1 38 64 7e"
               "92 ea 33 0f ae ea 6d fa 31 c7 a8 4d c3 bd 7e 1b 7a 6c 71 78 af"
               "36 87 90 18 e3 f2 52 10 7f 24 3d 24 3d c7 33 9d 56 84 c8 b0 37"
               "8b f3 02 44 da 8c 87 c8 43 f5 e5 6e b4 c5 e8 28 0a 2b 48 05 2c"
               "f9 3b 16 49 9a 66 db 7c ca 71 e4 59 94 26 f7 d4 61 e6 6f 99 88"
               "2b d8 9f c5 08 00 be cc a6 2d 6c 74 11 6d bd 29 72 fd a1 fa 80"
               "f8 5d f8 81 ed be 5a 37 66 89 36 b3 35 58 3b 59 91 86 dc 5c 69"
               "18 a3 96 fa 48 a1 81 d6 b6 fa 4f 9d 62 d5 13 af bb 99 2f 2b 99"
               "2f 67 f8 af e6 7f 76 91 3f a3 88 cb 56 30 c8 ca 01 e0 c6 5d 11"
               "c6 6a 1e 2a c4 c8 59 77 b7 c7 a6 99 9b bf 10 dc 35 ae 69 f5 51"
               "56 14 63 6c 0b 9b 68 c1 9e d2 e3 1c 0b 3b 66 76 30 38 eb ba 42"
               "f3 b3 8e dc 03 99 f3 a9 f2 3f aa 63 97 8c 31 7f c9 fa 66 a7 3f"
               "60 f0 50 4d e9 3b 5b 84 5e 27 55 92 c1 23 35 ee 34 0b bc 4f dd"
               "d5 02 78 40 16 e4 b3 be 7e f0 4d da 49 f4 b4 40 a3 0c b5 d2 af"
               "93 98 28 fd 4a e3 79 4e 44 f9 4d f5 a6 31 ed e4 2c 17 19 bf da"
               "bf 02 53 fe 51 75 be 89 8e 75 0e dc 53 37 0d 2b");

         ctx.client.received_data(server_handshake_messages);

         ctx.check_callback_invocations(result, "encrypted handshake messages received",
            {
            "tls_inspect_handshake_msg_encrypted_extensions",
            "tls_inspect_handshake_msg_certificate",
            "tls_inspect_handshake_msg_certificate_verify",
            "tls_inspect_handshake_msg_finished",
            "tls_examine_extensions",
            "tls_emit_data",
            "tls_session_activated",
            "tls_verify_cert_chain",
            "tls_verify_message"
            });
         result.confirm("correct certificate", ctx.certs_verified().front() == server_certificate());
         result.confirm("client is active", ctx.client.is_active());

         const auto expected_handshake_finished = Botan::hex_decode(
                  "17 03 03 00 35 75 ec 4d c2 38 cc e6"
                  "0b 29 80 44 a7 1e 21 9c 56 cc 77 b0 51 7f e9 b9 3c 7a 4b fc 44"
                  "d8 7f 38 f8 03 38 ac 98 fc 46 de b3 84 bd 1c ae ac ab 68 67 d7"
                  "26 c4 05 46");

         const auto client_handshake_finished = ctx.pull_send_buffer();
         result.test_gte("client handshake finished written", client_handshake_finished.size(),
                         RECORD_HEADER_SIZE);

         result.test_eq("correct handshake finished", client_handshake_finished,
                        expected_handshake_finished);

         const auto server_new_session_ticket = Botan::hex_decode(
               "17 03 03 00 de 3a 6b 8f 90 41 4a 97"
               "d6 95 9c 34 87 68 0d e5 13 4a 2b 24 0e 6c ff ac 11 6e 95 d4 1d"
               "6a f8 f6 b5 80 dc f3 d1 1d 63 c7 58 db 28 9a 01 59 40 25 2f 55"
               "71 3e 06 1d c1 3e 07 88 91 a3 8e fb cf 57 53 ad 8e f1 70 ad 3c"
               "73 53 d1 6d 9d a7 73 b9 ca 7f 2b 9f a1 b6 c0 d4 a3 d0 3f 75 e0"
               "9c 30 ba 1e 62 97 2a c4 6f 75 f7 b9 81 be 63 43 9b 29 99 ce 13"
               "06 46 15 13 98 91 d5 e4 c5 b4 06 f1 6e 3f c1 81 a7 7c a4 75 84"
               "00 25 db 2f 0a 77 f8 1b 5a b0 5b 94 c0 13 46 75 5f 69 23 2c 86"
               "51 9d 86 cb ee ac 87 aa c3 47 d1 43 f9 60 5d 64 f6 50 db 4d 02"
               "3e 70 e9 52 ca 49 fe 51 37 12 1c 74 bc 26 97 68 7e 24 87 46 d6"
               "df 35 30 05 f3 bc e1 86 96 12 9c 81 53 55 6b 3b 6c 67 79 b3 7b"
               "f1 59 85 68 4f");

         ctx.client.received_data(server_new_session_ticket);

         // TODO: once we implement session resumption, this should probably expect some callback
         ctx.check_callback_invocations(result, "new session ticket received", { });

         const auto client_application_payload = Botan::hex_decode(
               "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e"
               "0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23"
               "24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31");
         ctx.send(client_application_payload);

         const auto expected_encrypted_application_data = Botan::hex_decode(
                  "17 03 03 00 43 a2 3f 70 54 b6 2c 94"
                  "d0 af fa fe 82 28 ba 55 cb ef ac ea 42 f9 14 aa 66 bc ab 3f 2b"
                  "98 19 a8 a5 b4 6b 39 5b d5 4a 9a 20 44 1e 2b 62 97 4e 1f 5a 62"
                  "92 a2 97 70 14 bd 1e 3d ea e6 3a ee bb 21 69 49 15 e4");

         const auto encrypted_application_data = ctx.pull_send_buffer();
         result.test_gte("client application data written", encrypted_application_data.size(),
                         RECORD_HEADER_SIZE);

         ctx.check_callback_invocations(result, "application data sent", { "tls_emit_data" });

         result.test_eq("correct client application data", encrypted_application_data,
                        expected_encrypted_application_data);

         const auto server_encrypted_payload = Botan::hex_decode(
               "17 03 03 00 43 2e 93 7e 11 ef 4a c7"
               "40 e5 38 ad 36 00 5f c4 a4 69 32 fc 32 25 d0 5f 82 aa 1b 36 e3"
               "0e fa f9 7d 90 e6 df fc 60 2d cb 50 1a 59 a8 fc c4 9c 4b f2 e5"
               "f0 a2 1c 00 47 c2 ab f3 32 54 0d d0 32 e1 67 c2 95 5d");

         ctx.client.received_data(server_encrypted_payload);

         ctx.check_callback_invocations(result, "application data sent", { "tls_record_received" });

         const auto rcvd = ctx.pull_receive_buffer();
         result.test_eq("decrypted application traffic", rcvd, client_application_payload /* echoed */);
         result.test_is_eq("sequence number", ctx.last_received_seq_no(), uint64_t(1));

         ctx.client.close();

         const auto client_expected_alert = Botan::hex_decode(
                                               "17 03 03 00 13 c9 87 27 60 65 56 66"
                                               "b7 4d 7f f1 15 3e fd 6d b6 d0 b0 e3");
         const auto produced_alert = ctx.pull_send_buffer();
         result.test_eq("close payload", produced_alert, client_expected_alert);

         ctx.check_callback_invocations(result, "CLOSE_NOTIFY sent", { "tls_emit_data" });

         const auto server_close_notify = Botan::hex_decode(
                                             "17 03 03 00 13 b5 8f d6 71 66 eb f5"
                                             "99 d2 47 20 cf be 7e fa 7a 88 64 a9");
         ctx.client.received_data(server_close_notify);

         ctx.check_callback_invocations(result, "CLOSE_NOTIFY received", { "tls_alert" });

         result.confirm("connection is closed", ctx.client.is_closed());

         return result;
         }

      static Test::Result hello_retry_request()
         {
         Test::Result result("Handshake involving Hello Retry Request (Client side)");

         auto add_extensions_and_sort = [flights = 0](Botan::TLS::Extensions& exts, Botan::TLS::Connection_Side side) mutable
            {
            ++flights;

            if(flights == 1)
               {
               add_psk_exchange_modes(exts);
               add_renegotiation_extension(exts);
               }

            // For some reason RFC8448 decided to require this (fairly obscure) extension
            // in the second flight of the Client_Hello.
            if(flights == 2)
               {
               exts.add(new Padding(175));
               }

            sort_extensions(exts, side);
            };

         // Fallback RNG is required to for blinding in ECDH with P-256
         auto& fallback_rng = Test::rng();
         auto rng = std::make_unique<Botan_Tests::Fixed_Output_RNG>(fallback_rng);

         rng->add_entropy(std::vector<uint8_t>(32).data(), 32);  // used by session mgr for session key
         add_entropy(*rng, "b0b1c5a5aa37c5919f2ed1d5c6fff7fcb7849716945a2b8cee9258a346677b6f"); // for client hello random

         // for KeyShare extension (RFC 8448: "{client} create an ephemeral x25519 key pair")
         add_entropy(*rng, "0ed02f8e8117efc75ca7ac32aa7e34eda64cdc0ddad154a5e85289f959f63204");

         // for KeyShare extension (RFC 8448: "{client} create an ephemeral P-256 key pair")
         add_entropy(*rng, "ab5473467e19346ceb0a0414e41da21d4d2445bc3025afe97c4e8dc8d513da39");

         Client_Context ctx(std::move(rng), read_tls_policy("rfc8448_hrr"), add_extensions_and_sort);
         result.confirm("client not closed", !ctx.client.is_closed());

         const auto client_hello_record = ctx.pull_send_buffer();
         result.test_gte("client hello written", client_hello_record.size(), RECORD_HEADER_SIZE);

         ctx.check_callback_invocations(result, "client hello prepared", { "tls_emit_data", "tls_inspect_handshake_msg_client_hello", "tls_modify_extensions" });

         const auto client_hello_msg = slice(client_hello_record.begin() + RECORD_HEADER_SIZE, client_hello_record.end());

         const auto expected_hello_1 = Botan::hex_decode(
                                          "16 03 01 00 b4 01 00 00 b0 03 03 b0"
                                          "b1 c5 a5 aa 37 c5 91 9f 2e d1 d5 c6 ff f7 fc b7 84 97 16 94 5a"
                                          "2b 8c ee 92 58 a3 46 67 7b 6f 00 00 06 13 01 13 03 13 02 01 00"
                                          "00 81 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01"
                                          "00 00 0a 00 08 00 06 00 1d 00 17 00 18 00 33 00 26 00 24 00 1d"
                                          "00 20 e8 e8 e3 f3 b9 3a 25 ed 97 a1 4a 7d ca cb 8a 27 2c 62 88"
                                          "e5 85 c6 48 4d 05 26 2f ca d0 62 ad 1f 00 2b 00 03 02 03 04 00"
                                          "0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01"
                                          "05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00"
                                          "1c 00 02 40 01");

         result.test_eq("TLS client hello (1)", client_hello_record, expected_hello_1);

         const auto server_retry_request = Botan::hex_decode(
                                              "16 03 03 00 b0 02 00 00 ac 03 03 cf"
                                              "21 ad 74 e5 9a 61 11 be 1d 8c 02 1e 65 b8 91 c2 a2 11 16 7a bb"
                                              "8c 5e 07 9e 09 e2 c8 a8 33 9c 00 13 01 00 00 84 00 33 00 02 00"
                                              "17 00 2c 00 74 00 72 71 dc d0 4b b8 8b c3 18 91 19 39 8a 00 00"
                                              "00 00 ee fa fc 76 c1 46 b8 23 b0 96 f8 aa ca d3 65 dd 00 30 95"
                                              "3f 4e df 62 56 36 e5 f2 1b b2 e2 3f cc 65 4b 1b 5b 40 31 8d 10"
                                              "d1 37 ab cb b8 75 74 e3 6e 8a 1f 02 5f 7d fa 5d 6e 50 78 1b 5e"
                                              "da 4a a1 5b 0c 8b e7 78 25 7d 16 aa 30 30 e9 e7 84 1d d9 e4 c0"
                                              "34 22 67 e8 ca 0c af 57 1f b2 b7 cf f0 f9 34 b0 00 2b 00 02 03"
                                              "04");
         ctx.client.received_data(server_retry_request);

         ctx.check_callback_invocations(result, "hello retry request received",
            {
            "tls_emit_data",
            "tls_inspect_handshake_msg_hello_retry_request",
            "tls_examine_extensions",
            "tls_inspect_handshake_msg_client_hello",
            "tls_modify_extensions",
            "tls_decode_group_param"
            });

         const auto client_hello_2_record = ctx.pull_send_buffer();
         const auto expected_hello_2 = Botan::hex_decode(
                                          "16 03 03 02 00 01 00 01 fc 03 03 b0"
                                          "b1 c5 a5 aa 37 c5 91 9f 2e d1 d5 c6 ff f7 fc b7 84 97 16 94 5a"
                                          "2b 8c ee 92 58 a3 46 67 7b 6f 00 00 06 13 01 13 03 13 02 01 00"
                                          "01 cd 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01"
                                          "00 00 0a 00 08 00 06 00 1d 00 17 00 18 00 33 00 47 00 45 00 17"
                                          "00 41 04 a6 da 73 92 ec 59 1e 17 ab fd 53 59 64 b9 98 94 d1 3b"
                                          "ef b2 21 b3 de f2 eb e3 83 0e ac 8f 01 51 81 26 77 c4 d6 d2 23"
                                          "7e 85 cf 01 d6 91 0c fb 83 95 4e 76 ba 73 52 83 05 34 15 98 97"
                                          "e8 06 57 80 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03"
                                          "06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05"
                                          "02 06 02 02 02 00 2c 00 74 00 72 71 dc d0 4b b8 8b c3 18 91 19"
                                          "39 8a 00 00 00 00 ee fa fc 76 c1 46 b8 23 b0 96 f8 aa ca d3 65"
                                          "dd 00 30 95 3f 4e df 62 56 36 e5 f2 1b b2 e2 3f cc 65 4b 1b 5b"
                                          "40 31 8d 10 d1 37 ab cb b8 75 74 e3 6e 8a 1f 02 5f 7d fa 5d 6e"
                                          "50 78 1b 5e da 4a a1 5b 0c 8b e7 78 25 7d 16 aa 30 30 e9 e7 84"
                                          "1d d9 e4 c0 34 22 67 e8 ca 0c af 57 1f b2 b7 cf f0 f9 34 b0 00"
                                          "2d 00 02 01 01 00 1c 00 02 40 01 00 15 00 af 00 00 00 00 00 00"
                                          "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                                          "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                                          "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                                          "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                                          "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                                          "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                                          "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                                          "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                                          "00");
         result.test_eq("TLS client hello (2)", client_hello_2_record, expected_hello_2);

         const auto server_hello = Botan::hex_decode(
                                      "16 03 03 00 7b 02 00 00 77 03 03 bb"
                                      "34 1d 84 7f d7 89 c4 7c 38 71 72 dc 0c 9b f1 47 fc ca cb 50 43"
                                      "d8 6c a4 c5 98 d3 ff 57 1b 98 00 13 01 00 00 4f 00 33 00 45 00"
                                      "17 00 41 04 58 3e 05 4b 7a 66 67 2a e0 20 ad 9d 26 86 fc c8 5b"
                                      "5a d4 1a 13 4a 0f 03 ee 72 b8 93 05 2b d8 5b 4c 8d e6 77 6f 5b"
                                      "04 ac 07 d8 35 40 ea b3 e3 d9 c5 47 bc 65 28 c4 31 7d 29 46 86"
                                      "09 3a 6c ad 7d 00 2b 00 02 03 04");
         ctx.client.received_data(server_hello);

         ctx.check_callback_invocations(result, "server hello received", { "tls_inspect_handshake_msg_server_hello", "tls_examine_extensions", "tls_decode_group_param" });

         const auto server_encrypted_handshake_messages = Botan::hex_decode(
                  "17 03 03 02 96 99 be e2 0b af 5b 7f"
                  "c7 27 bf ab 62 23 92 8a 38 1e 6d 0c f9 c4 da 65 3f 9d 2a 7b 23"
                  "f7 de 11 cc e8 42 d5 cf 75 63 17 63 45 0f fb 8b 0c c1 d2 38 e6"
                  "58 af 7a 12 ad c8 62 43 11 4a b1 4a 1d a2 fa e4 26 21 ce 48 3f"
                  "b6 24 2e ab fa ad 52 56 6b 02 b3 1d 2e dd ed ef eb 80 e6 6a 99"
                  "00 d5 f9 73 b4 0c 4f df 74 71 9e cf 1b 68 d7 f9 c3 b6 ce b9 03"
                  "ca 13 dd 1b b8 f8 18 7a e3 34 17 e1 d1 52 52 2c 58 22 a1 a0 3a"
                  "d5 2c 83 8c 55 95 3d 61 02 22 87 4c ce 8e 17 90 b2 29 a2 aa 0b"
                  "53 c8 d3 77 ee 72 01 82 95 1d c6 18 1d c5 d9 0b d1 f0 10 5e d1"
                  "e8 4a a5 f7 59 57 c6 66 18 97 07 9e 5e a5 00 74 49 e3 19 7b dc"
                  "7c 9b ee ed dd ea fd d8 44 af a5 c3 15 ec fe 65 e5 76 af e9 09"
                  "81 28 80 62 0e c7 04 8b 42 d7 f5 c7 8d 76 f2 99 d6 d8 25 34 bd"
                  "d8 f5 12 fe bc 0e d3 81 4a ca 47 0c d8 00 0d 3e 1c b9 96 2b 05"
                  "2f bb 95 0d f6 83 a5 2c 2b a7 7e d3 71 3b 12 29 37 a6 e5 17 09"
                  "64 e2 ab 79 69 dc d9 80 b3 db 9b 45 8d a7 60 31 24 d6 dc 00 5e"
                  "4d 6e 04 b4 d0 c4 ba f3 27 5d b8 27 db ba 0a 6d b0 96 72 17 1f"
                  "c0 57 b3 85 1d 7e 02 68 41 e2 97 8f bd 23 46 bb ef dd 03 76 bb"
                  "11 08 fe 9a cc 92 18 9f 56 50 aa 5e 85 d8 e8 c7 b6 7a c5 10 db"
                  "a0 03 d3 d7 e1 63 50 bb 66 d4 50 13 ef d4 4c 9b 60 7c 0d 31 8c"
                  "4c 7d 1a 1f 5c bc 57 e2 06 11 80 4e 37 87 d7 b4 a4 b5 f0 8e d8"
                  "fd 70 bd ae ad e0 22 60 b1 2a b8 42 ef 69 0b 4a 3e e7 91 1e 84"
                  "1b 37 4e cd 5e bb bc 2a 54 d0 47 b6 00 33 6d d7 d0 c8 8b 4b c1"
                  "0e 58 ee 6c b6 56 de 72 47 fa 20 d8 e9 1d eb 84 62 86 08 cf 80"
                  "61 5b 62 e9 6c 14 91 c7 ac 37 55 eb 69 01 40 5d 34 74 fe 1a c7"
                  "9d 10 6a 0c ee 56 c2 57 7f c8 84 80 f9 6c b6 b8 c6 81 b7 b6 8b"
                  "53 c1 46 09 39 08 f3 50 88 81 75 bd fb 0b 1e 31 ad 61 e3 0b a0"
                  "ad fe 6d 22 3a a0 3c 07 83 b5 00 1a 57 58 7c 32 8a 9a fc fc fb"
                  "97 8d 1c d4 32 8f 7d 9d 60 53 0e 63 0b ef d9 6c 0c 81 6e e2 0b"
                  "01 00 76 8a e2 a6 df 51 fc 68 f1 72 74 0a 79 af 11 39 8e e3 be"
                  "12 52 49 1f a9 c6 93 47 9e 87 7f 94 ab 7c 5f 8c ad 48 02 03 e6"
                  "ab 7b 87 dd 71 e8 a0 72 91 13 df 17 f5 ee e8 6c e1 08 d1 d7 20"
                  "07 ec 1c d1 3c 85 a6 c1 49 62 1e 77 b7 d7 8d 80 5a 30 f0 be 03"
                  "0c 31 5e 54");
         ctx.client.received_data(server_encrypted_handshake_messages);

         ctx.check_callback_invocations(result, "encrypted handshake messages received",
            {
            "tls_inspect_handshake_msg_encrypted_extensions",
            "tls_inspect_handshake_msg_certificate",
            "tls_inspect_handshake_msg_certificate_verify",
            "tls_inspect_handshake_msg_finished",
            "tls_examine_extensions",
            "tls_emit_data",
            "tls_session_activated",
            "tls_verify_cert_chain",
            "tls_verify_message"
            });

         const auto expected_client_finished = Botan::hex_decode(
               "17 03 03 00 35 d7 4f 19 23 c6 62 fd"
               "34 13 7c 6f 50 2f 3d d2 b9 3d 95 1d 1b 3b c9 7e 42 af e2 3c 31"
               "ab ea 92 fe 91 b4 74 99 9e 85 e3 b7 91 ce 25 2f e8 c3 e9 f9 39"
               "a4 12 0c b2");

         const auto client_finished = ctx.pull_send_buffer();
         result.test_eq("client finished", client_finished, expected_client_finished);

         const auto expected_client_close_notify = Botan::hex_decode(
                  "17 03 03 00 13 2e a6 cd f7 49 19 60 23 e2 b3 a4 94 91 69 55 36 42 60 47");

         ctx.client.close();

         ctx.check_callback_invocations(result, "encrypted handshake messages received", { "tls_emit_data" });

         result.test_eq("client close notify", ctx.pull_send_buffer(), expected_client_close_notify);

         const auto server_close_notify = Botan::hex_decode(
                                             "17 03 03 00 13 51 9f c5 07 5c b0 88 43 49 75 9f f9 ef 6f 01 1b b4 c6 f2");

         ctx.client.received_data(server_close_notify);

         ctx.check_callback_invocations(result, "encrypted handshake messages received", { "tls_alert" });

         result.confirm("connection is closed", ctx.client.is_closed());

         return result;
         }

      static Test::Result middlebox_compatibility()
         {
         Test::Result result("Middlebox Compatibility Mode (Client side)");

         auto rng = std::make_unique<Botan_Tests::Fixed_Output_RNG>("");
         rng->add_entropy(std::vector<uint8_t>(32).data(), 32);  // used by session mgr for session key

         // for client hello random
         add_entropy(*rng, "4e640a3f2c2738f09c9418bd78edccd7559d0531199276d4d92a0e9ee9d77d09");

         // for legacy session ID
         add_entropy(*rng, "a80c165581a8e0d06c0018d54d3a06dd32cfd4051eb026fad3fd0ba99269e6ef");

         // for KeyShare extension (x25519 private key)
         add_entropy(*rng, "dea00b45695dc781f19d34a62c1afd31ab4369af1e855a3bbb258d8442cde6d7");

         auto add_extensions_and_sort = [&](Botan::TLS::Extensions& exts, Botan::TLS::Connection_Side side)
            {
            add_renegotiation_extension(exts);
            add_psk_exchange_modes(exts);
            sort_extensions(exts, side);
            };

         Client_Context ctx(std::move(rng), read_tls_policy("rfc8448_compat"), add_extensions_and_sort);

         const auto client_hello = Botan::hex_decode(
                                      "16 03 01 00 e0 01 00 00 dc 03 03 4e"
                                      "64 0a 3f 2c 27 38 f0 9c 94 18 bd 78 ed cc d7 55 9d 05 31 19 92"
                                      "76 d4 d9 2a 0e 9e e9 d7 7d 09 20 a8 0c 16 55 81 a8 e0 d0 6c 00"
                                      "18 d5 4d 3a 06 dd 32 cf d4 05 1e b0 26 fa d3 fd 0b a9 92 69 e6"
                                      "ef 00 06 13 01 13 03 13 02 01 00 00 8d 00 00 00 0b 00 09 00 00"
                                      "06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00"
                                      "17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 33 00 26 00 24"
                                      "00 1d 00 20 8e 72 92 cf 30 56 db b0 d2 5f cb e5 5c 10 7d c9 bb"
                                      "f8 3d d9 70 8f 39 20 3b a3 41 24 9a 7d 9b 63 00 2b 00 03 02 03"
                                      "04 00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06"
                                      "04 01 05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01"
                                      "01 00 1c 00 02 40 01");

         result.test_eq("Client Hello", ctx.pull_send_buffer(), client_hello);

         const auto server_hello = Botan::hex_decode(
                                      "16 03 03 00 7a 02 00 00 76 03 03 e5"
                                      "dd 59 48 c4 35 f7 a3 8f 0f 01 30 70 8d c3 22 d9 df 09 ab d4 83"
                                      "81 17 c1 83 a7 bb 6d 99 4f 2c 20 a8 0c 16 55 81 a8 e0 d0 6c 00"
                                      "18 d5 4d 3a 06 dd 32 cf d4 05 1e b0 26 fa d3 fd 0b a9 92 69 e6"
                                      "ef 13 01 00 00 2e 00 33 00 24 00 1d 00 20 3e 30 f0 f4 ba 55 1a"
                                      "fd 62 76 83 41 17 5f 52 65 e4 da f0 c8 84 16 17 aa 4f af dd 21"
                                      "42 32 0c 22 00 2b 00 02 03 04");
         const auto change_cipher_spec = Botan::hex_decode("14 03 03 00 01 01");
         const auto encrypted_server_handshake = Botan::hex_decode(
               "17 03 03 02 a2 48 de 89 1d 9c 36 24"
               "a6 7a 6c 6f 06 01 ab 7a c2 0c 1f 6a 9e 14 d2 e6 00 7e 99 9e 13"
               "03 67 a8 af 1b cf ea 94 98 fb ce 19 df 45 05 ee ce 3a 25 da 52"
               "3c be 55 ea 1b 3b da 4e 91 99 5e 45 5d 50 0a 4f aa 62 27 b7 11"
               "1e 1c 85 47 e2 d7 c1 79 db 21 53 03 d2 58 27 f3 cd 18 f4 8f 64"
               "91 32 8c f5 c0 f8 14 d3 88 15 0b d9 e9 26 4a ae 49 1d b6 99 50"
               "69 be a1 76 65 d5 e0 c8 17 28 4d 4a c2 18 80 05 4c 36 57 33 1e"
               "23 a9 30 4d c8 8a 15 c0 4e c8 0b d3 85 2b f7 f9 d3 c6 61 5b 15"
               "fa c8 3b bc a0 31 c6 d2 31 0d 9f 5d 7a 4b 02 0a 4f 7c 19 06 2b"
               "65 c0 5a 1d 32 64 b5 57 ec 9d 8e 0f 7c ee 27 e3 6f 79 30 39 de"
               "8d d9 6e df ca 90 09 e0 65 10 34 bf f3 1d 7f 34 9e ec e0 1d 99"
               "fc b5 fc ab 84 0d 77 07 c7 22 99 c3 b5 d0 45 64 e8 80 a3 3c 5e"
               "84 6c 76 2e 3d 92 2b b5 53 03 d1 d8 7c c0 f0 65 73 f1 7d cb 9b"
               "8f fd 35 bb d8 83 c1 cb 3a a2 4f cc 32 50 05 f7 68 ce 2f b6 24"
               "ca 97 b6 c4 d9 8e 17 f3 5b c2 c7 94 0a 06 10 0c 2d 44 8d b7 18"
               "0b 2d 86 21 64 43 5c 9c 21 0e 98 60 39 4e 05 aa b2 3f f1 b0 20"
               "3f 66 2c 58 8d a5 bc 44 11 47 7a 30 b4 11 36 c4 88 a0 a6 3f ca"
               "b5 c1 5a c6 13 22 6d ae 82 7a 1d 1f e9 5e ce 6b 30 bc ee 15 60"
               "a8 d4 08 d2 64 55 5e 76 0f 9b fc 62 4c 2c 87 fd 04 56 c9 bf b4"
               "1b cd 1a 7b 21 27 86 d2 b6 7f d5 78 04 fa cf a1 ee f7 cf 29 19"
               "d8 b9 98 c9 78 9f 76 3b 4d 9c aa 09 3a 9d ed 43 17 5d 46 a7 6b"
               "4d 54 f0 ce 0c 5d 22 59 b6 07 e3 0a 9d 24 12 63 87 4f a5 9d 6f"
               "57 0d c4 0d 83 a2 d8 3b f9 e9 85 0d 45 4c 57 80 65 35 a8 99 8a"
               "e0 35 7d f9 2f 00 b9 66 73 44 c2 41 14 cc c9 ef 53 91 24 b2 04"
               "e7 e6 e7 48 c3 0a 28 a3 d1 d1 83 99 72 43 ea cc bb d3 3b 0c 11"
               "15 a0 32 71 06 a1 e6 a7 52 71 d4 98 30 86 f6 32 ff 0e b8 b4 c6"
               "31 02 cb ce f5 bb 72 da e1 27 9d 5d e8 eb 19 09 6d 8c db 07 fa"
               "8e a9 89 78 8f ac 23 e6 6e 04 88 c1 93 f3 f3 fe a8 c8 83 88 96"
               "bf 3a e4 b6 84 8d 42 ce d4 bd f4 1a be 6f c3 31 b4 42 25 e7 a1"
               "f7 d3 56 41 47 d5 45 8e 71 aa 90 9c b0 2b e9 58 bb c4 2e 3a a5"
               "a2 7c c6 ea f4 b6 fe 51 ae 44 95 69 4d 8a b6 32 0a ab 92 01 83"
               "fd 5b 31 a3 59 04 2f bd 67 39 1e c5 e4 d1 89 2a 2e 52 10 14 1a"
               "49 4e 93 01 b2 4a 11 3c 47 4c 7f 2a 73 45 78 47");
         ctx.client.received_data(Botan::concat(server_hello,
                                                change_cipher_spec,
                                                encrypted_server_handshake));

         const auto encrypted_client_handshake = Botan::hex_decode(
               "17 03 03 00 35 32 d0 30 e2 73 77 3a"
               "86 96 c7 99 98 1a f6 ce d0 7f 87 48 2e 81 56 5e 39 4e 87 c8 67"
               "f3 3d f3 d6 5b 75 06 f1 a6 26 af 91 d4 82 1d 5f 7a 1f 21 0e f8"
               "dd 3c 6d 16");

         result.test_eq("CCS + Client Finished", ctx.pull_send_buffer(),
                        Botan::concat(change_cipher_spec,
                                      encrypted_client_handshake));

         result.confirm("client is ready to send application traffic", ctx.client.is_active());

         ctx.client.close();

         const auto client_close_notify = Botan::hex_decode(
                                             "17 03 03 00 13 0f 62 91 55 38 2d ba"
                                             "23 c4 e2 c5 f7 f8 4e 6f 2e d3 08 3d");
         result.test_eq("Client close_notify", ctx.pull_send_buffer(), client_close_notify);

         result.confirm("client cannot send application traffic anymore", !ctx.client.is_active());
         result.confirm("client is not fully closed yet", !ctx.client.is_closed());

         const auto server_close_notify = Botan::hex_decode(
                                             "17 03 03 00 13 b7 25 7b 0f ec af 69"
                                             "d4 f0 9e 3f 89 1e 2a 25 d1 e2 88 45");
         ctx.client.received_data(server_close_notify);

         result.confirm("client connection was terminated", ctx.client.is_closed());

         return result;
         }

   public:
      std::vector<Test::Result> run() override
         {
         return
            {
            simple_1_rtt_client_hello(),
            hello_retry_request(),
            middlebox_compatibility()
            };
         }
   };

BOTAN_REGISTER_TEST("tls", "tls_rfc8448", Test_TLS_RFC8448);

#endif

}
