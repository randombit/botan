/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "perf.h"
#include <cstring>

// Always available:
#include <botan/hex.h>

#if defined(BOTAN_HAS_BASE64_CODEC)
   #include <botan/base64.h>
#endif

#if defined(BOTAN_HAS_FPE_FE1)
   #include <botan/fpe_fe1.h>
#endif

#if defined(BOTAN_HAS_RFC3394_KEYWRAP)
   #include <botan/rfc3394.h>
#endif

#if defined(BOTAN_HAS_ZFEC)
   #include <botan/zfec.h>
#endif

namespace Botan_CLI {

class PerfTest_Hex final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         for(size_t buf_size : config.buffer_sizes()) {
            std::vector<uint8_t> ibuf(buf_size);
            std::vector<uint8_t> rbuf(buf_size);
            const size_t olen = 2 * buf_size;

            auto enc_timer = config.make_timer("hex", ibuf.size(), "encode", "", ibuf.size());

            auto dec_timer = config.make_timer("hex", olen, "decode", "", olen);

            const auto msec = config.runtime();

            while(enc_timer->under(msec) && dec_timer->under(msec)) {
               config.rng().randomize(ibuf);

               std::string hex = enc_timer->run([&]() { return Botan::hex_encode(ibuf); });

               dec_timer->run([&]() { Botan::hex_decode(rbuf.data(), hex); });
               BOTAN_ASSERT(rbuf == ibuf, "Encode/decode round trip ok");
            }

            config.record_result(*enc_timer);
            config.record_result(*dec_timer);
         }
      }
};

BOTAN_REGISTER_PERF_TEST("hex", PerfTest_Hex);

#if defined(BOTAN_HAS_BASE64_CODEC)
class PerfTest_Base64 final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         for(size_t buf_size : config.buffer_sizes()) {
            std::vector<uint8_t> ibuf(buf_size);
            std::vector<uint8_t> rbuf(buf_size);
            const size_t olen = Botan::base64_encode_max_output(ibuf.size());

            auto enc_timer = config.make_timer("base64", ibuf.size(), "encode", "", ibuf.size());

            auto dec_timer = config.make_timer("base64", olen, "decode", "", olen);

            const auto msec = config.runtime();

            while(enc_timer->under(msec) && dec_timer->under(msec)) {
               config.rng().randomize(ibuf);

               std::string b64 = enc_timer->run([&]() { return Botan::base64_encode(ibuf); });

               dec_timer->run([&]() { Botan::base64_decode(rbuf.data(), b64); });
               BOTAN_ASSERT(rbuf == ibuf, "Encode/decode round trip ok");
            }

            config.record_result(*enc_timer);
            config.record_result(*dec_timer);
         }
      }
};

BOTAN_REGISTER_PERF_TEST("base64", PerfTest_Base64);

#endif

#if defined(BOTAN_HAS_FPE_FE1)

class PerfTest_FpeFe1 final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         const auto n = Botan::BigInt::from_u64(1000000000000000);

         auto enc_timer = config.make_timer("FPE_FE1 encrypt");
         auto dec_timer = config.make_timer("FPE_FE1 decrypt");

         const Botan::SymmetricKey key(config.rng(), 32);
         const std::vector<uint8_t> tweak(8);  // 8 zeros

         auto x = Botan::BigInt::one();

         Botan::FPE_FE1 fpe_fe1(n);
         fpe_fe1.set_key(key);

         auto runtime = config.runtime();

         while(enc_timer->under(runtime)) {
            enc_timer->start();
            x = fpe_fe1.encrypt(x, tweak.data(), tweak.size());
            enc_timer->stop();
         }
         config.record_result(*enc_timer);

         for(size_t i = 0; i != enc_timer->events(); ++i) {
            dec_timer->start();
            x = fpe_fe1.decrypt(x, tweak.data(), tweak.size());
            dec_timer->stop();
         }
         config.record_result(*dec_timer);

         BOTAN_ASSERT(x == 1, "FPE works");
      }
};

BOTAN_REGISTER_PERF_TEST("fpe_fe1", PerfTest_FpeFe1);

#endif

#if defined(BOTAN_HAS_RFC3394_KEYWRAP)
class PerfTest_Rfc3394 final : public PerfTest {
      void go(const PerfConfig& config) override {
         auto wrap_timer = config.make_timer("RFC3394 AES-256 key wrap");
         auto unwrap_timer = config.make_timer("RFC3394 AES-256 key unwrap");

         const Botan::SymmetricKey kek(config.rng(), 32);
         Botan::secure_vector<uint8_t> key(64, 0);

         const auto runtime = config.runtime();

         while(wrap_timer->under(runtime)) {
            wrap_timer->start();
            key = Botan::rfc3394_keywrap(key, kek);
            wrap_timer->stop();

            unwrap_timer->start();
            key = Botan::rfc3394_keyunwrap(key, kek);
            unwrap_timer->stop();

            key[0] += 1;
         }

         config.record_result(*wrap_timer);
         config.record_result(*unwrap_timer);
      }
};

BOTAN_REGISTER_PERF_TEST("rfc3394", PerfTest_Rfc3394);

#endif

#if defined(BOTAN_HAS_ZFEC)

class PerfTest_Zfec final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         const size_t k = 4;
         const size_t n = 16;

         Botan::ZFEC zfec(k, n);

         const size_t share_size = 256 * 1024;

         std::vector<uint8_t> input(share_size * k);
         config.rng().randomize(input.data(), input.size());

         std::vector<uint8_t> output(share_size * n);

         auto enc_fn = [&](size_t share, const uint8_t buf[], size_t len) {
            std::memcpy(&output[share * share_size], buf, len);
         };

         const auto msec = config.runtime();

         const std::string alg = Botan::fmt("zfec {}/{}", k, n);

         auto enc_timer = config.make_timer(alg, input.size(), "encode", "", input.size());

         enc_timer->run_until_elapsed(msec, [&]() { zfec.encode(input.data(), input.size(), enc_fn); });

         config.record_result(*enc_timer);

         auto dec_timer = config.make_timer(alg, input.size(), "decode", "", input.size());

         std::map<size_t, const uint8_t*> shares;
         for(size_t i = 0; i != n; ++i) {
            shares[i] = &output[share_size * i];
         }

         // remove data shares to make decoding maximally expensive:
         while(shares.size() != k) {
            shares.erase(shares.begin());
         }

         std::vector<uint8_t> recovered(share_size * k);

         auto dec_fn = [&](size_t share, const uint8_t buf[], size_t len) {
            std::memcpy(&recovered[share * share_size], buf, len);
         };

         dec_timer->run_until_elapsed(msec, [&]() { zfec.decode_shares(shares, share_size, dec_fn); });

         config.record_result(*dec_timer);

         if(recovered != input) {
            config.error_output() << "ZFEC recovery failed\n";
         }
      }
};

BOTAN_REGISTER_PERF_TEST("zfec", PerfTest_Zfec);

#endif

}  // namespace Botan_CLI
