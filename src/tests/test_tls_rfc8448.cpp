/*
* (C) 2021 Jack Lloyd
* (C) 2021 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <memory>
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

class Test_TLS_13_Callbacks : public Botan::TLS::Callbacks
   {
   public:
      Test_TLS_13_Callbacks(Test::Result& result)
         : session_activated_called(false), m_result(result) {}

      void tls_emit_data(const uint8_t data[], size_t size) override
         {
         send_buffer.insert(send_buffer.end(), data, data + size);
         }

      void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override
         {
         received_seq_no = seq_no;
         receive_buffer.insert(receive_buffer.end(), data, data + size);
         }

      void tls_alert(Botan::TLS::Alert alert) override
         {
         BOTAN_UNUSED(alert);
         // handle a tls alert received from the tls server
         }

      bool tls_session_established(const Botan::TLS::Session& session) override
         {
         BOTAN_UNUSED(session);
         // the session with the tls client was established
         // return false to prevent the session from being cached, true to
         // cache the session in the configured session manager
         return false;
         }

      void tls_modify_extensions(Botan::TLS::Extensions& exts, Botan::TLS::Connection_Side side) override
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
               Botan::TLS::Handshake_Extension_Type::TLSEXT_PSK_KEY_EXCHANGE_MODES,
               Botan::TLS::Handshake_Extension_Type::TLSEXT_RECORD_SIZE_LIMIT
               };

            m_result.test_eq("number of extensions", exts.size(), expected_order.size());

            for(const auto ext_type : expected_order)
               {
               auto ext = exts.take(ext_type);
               if(m_result.confirm("extension was produced", ext != nullptr))
                  {
                  exts.add(std::move(ext));
                  }
               }
            }
         }

      void tls_session_activated() override
         {
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
         certificate_chain = cert_chain;
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

   public:
      bool session_activated_called;

      std::vector<Botan::X509_Certificate> certificate_chain;

   private:
      std::vector<uint8_t> send_buffer;
      std::vector<uint8_t> receive_buffer;
      uint64_t             received_seq_no;
      Test::Result&        m_result;
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
      TLS_Context(Test::Result& result,
                  std::unique_ptr<Botan::RandomNumberGenerator> rng_in)
         : callbacks(result)
         , rng(std::move(rng_in))
         , session_mgr(*rng)
         , policy(read_tls_policy("rfc8448"))
         {}

   public:
      virtual ~TLS_Context() = default;

      std::vector<uint8_t> pull_send_buffer()
         {
         return callbacks.pull_send_buffer();
         }

      std::vector<uint8_t> pull_receive_buffer()
         {
         return callbacks.pull_receive_buffer();
         }

      uint64_t last_received_seq_no() const { return callbacks.last_received_seq_no(); }

      bool session_activated_called() const { return callbacks.session_activated_called; }

      const std::vector<Botan::X509_Certificate>& certs_verified() const
         {
         return callbacks.certificate_chain;
         }

      virtual void send(const std::vector<uint8_t>& data) = 0;

   public:
      Test_TLS_13_Callbacks   callbacks;
      Test_Server_Credentials creds;

      std::unique_ptr<Botan::RandomNumberGenerator> rng;
      Botan::TLS::Session_Manager_In_Memory         session_mgr;
      RFC8448_Text_Policy                           policy;
   };

class Server_Context : public TLS_Context
   {
   public:
      Server_Context(Test::Result& result,
                     std::unique_ptr<Botan::RandomNumberGenerator> rng_in)
         : TLS_Context(result, std::move(rng_in))
         , server(callbacks, session_mgr, creds, policy, *rng)
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
      Client_Context(Test::Result& result,
                     std::unique_ptr<Botan::RandomNumberGenerator> rng_in)
         : TLS_Context(result, std::move(rng_in))
         , client(callbacks, session_mgr, creds, policy, *rng,
                  Botan::TLS::Server_Information("server"),
                  Botan::TLS::Protocol_Version::TLS_V13)
         {}

      void send(const std::vector<uint8_t>& data) override
         {
         client.send(data.data(), data.size());
         }

      Botan::TLS::Client client;
   };
}

class Test_TLS_RFC8448 final : public Test
   {
   private:
      Test::Result simple_1_rtt_client_hello()
         {
         Test::Result result("Simple 1-RTT (Client side)");

         // TODO: fixed output RNG is probably not needed as we cannot get the "right"
         //       client hello anyway -- revert
         auto rng = std::make_unique<Botan_Tests::Fixed_Output_RNG>("");
         rng->add_entropy(std::vector<uint8_t>(32).data(), 32);  // used by session mgr for session key
         add_entropy(*rng, "cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7"); // for client hello random

         // for KeyShare extension (RFC 8448: "{client} create an ephemeral x25519 key pair")
         add_entropy(*rng, "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005");

         Client_Context ctx(result, std::move(rng));
         result.confirm("client not closed", !ctx.client.is_closed());

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

         // RFC8446 5.1
         // legacy_record_version:  MUST be set to 0x0303 for all records
         //       generated by a TLS 1.3 implementation other than an initial
         //       ClientHello (i.e., one not generated after a HelloRetryRequest),
         //       where it MAY also be 0x0301 for compatibility purposes.
         result.test_eq("TLS client hello header",
                        slice(client_hello_msg.begin(), client_hello_msg.begin() + 1),
                        Botan::hex_decode("01"));

         auto client_hello_length_bytes = slice(client_hello_msg.begin() + 1, client_hello_msg.begin() + 4);
         client_hello_length_bytes.insert(client_hello_length_bytes.begin(), '\x00');
         const auto indicated_hello_length = Botan::load_be<uint32_t>(client_hello_length_bytes.data(), 0);

         const auto client_hello = slice(client_hello_msg.begin() + 4, client_hello_msg.end());
         result.test_eq("TLS client hello has indicated length",
                        client_hello.size(),
                        indicated_hello_length);

         Botan::TLS::Client_Hello hello(client_hello);
         if(result.test_eq("only one supported version", hello.supported_versions().size(), 1))
            {
            result.test_int_eq("Supported Version is 1.3",
                               hello.supported_versions().front().version_code(),
                               Botan::TLS::Protocol_Version::TLS_V13);
            }

         // ----

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

         // splitting the input data to test partial reads
         const auto server_hello_b = Botan::hex_decode(
                                        "34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00"
                                        "1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6"
                                        "cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04");
         ctx.client.received_data(server_hello_b);

         result.confirm("client is not yet active", !ctx.client.is_active());
         result.confirm("certificate verify callback was not yet called", ctx.certs_verified().empty());
         result.confirm("session activated callback was not yet called", !ctx.session_activated_called());

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

         result.confirm("certificate verify callback was called", !ctx.certs_verified().empty());
         result.confirm("correct certificate", ctx.certs_verified().front() == server_certificate());

         result.confirm("client is active", ctx.client.is_active());
         result.confirm("session activated callback was called", ctx.session_activated_called());

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

         result.test_eq("correct client application data", encrypted_application_data,
                        expected_encrypted_application_data);

         const auto server_encrypted_payload = Botan::hex_decode(
               "17 03 03 00 43 2e 93 7e 11 ef 4a c7"
               "40 e5 38 ad 36 00 5f c4 a4 69 32 fc 32 25 d0 5f 82 aa 1b 36 e3"
               "0e fa f9 7d 90 e6 df fc 60 2d cb 50 1a 59 a8 fc c4 9c 4b f2 e5"
               "f0 a2 1c 00 47 c2 ab f3 32 54 0d d0 32 e1 67 c2 95 5d");

         ctx.client.received_data(server_encrypted_payload);

         const auto rcvd = ctx.pull_receive_buffer();
         result.test_eq("decrypted application traffic", rcvd, client_application_payload /* echoed */);
         result.test_is_eq("sequence number", ctx.last_received_seq_no(), uint64_t(1));

         ctx.client.close();

         const auto client_expected_alert = Botan::hex_decode(
                                               "17 03 03 00 13 c9 87 27 60 65 56 66"
                                               "b7 4d 7f f1 15 3e fd 6d b6 d0 b0 e3");
         const auto produced_alert = ctx.pull_send_buffer();
         result.test_eq("close payload", produced_alert, client_expected_alert);

         const auto server_close_notify = Botan::hex_decode(
                                               "17 03 03 00 13 b5 8f d6 71 66 eb f5"
                                               "99 d2 47 20 cf be 7e fa 7a 88 64 a9");
         ctx.client.received_data(server_close_notify);
         // TODO handle appropriately

         return result;
         }

      Test::Result simple_1_rtt_server()
         {
         Test::Result result("Simple 1-RTT (Server side)");

         Server_Context ctx(result, std::make_unique<Botan::AutoSeeded_RNG>());

         // Cipher Suites in this client hello:
         //   AES_128_GCM_SHA256
         //   CHACHA20_POLY1305_SHA256
         //   AES_256_GCM_SHA384
         const auto client_hello = Botan::hex_decode(
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

         const size_t remaining = ctx.server.received_data(client_hello);

         result.test_int_eq(remaining, 0, "client hello was fully consumed");
         result.confirm("server not closed", !ctx.server.is_closed());

         const auto server_hello_record = ctx.pull_send_buffer();

         return result;
         }

   public:
      std::vector<Test::Result> run() override
         {
         return
            {
            simple_1_rtt_client_hello()
            // simple_1_rtt_server()
            };
         }
   };

BOTAN_REGISTER_TEST("tls", "tls_rfc8448", Test_TLS_RFC8448);

#endif

}
