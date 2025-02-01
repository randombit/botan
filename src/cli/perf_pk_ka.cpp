/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "perf.h"

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
   #include <botan/pk_algs.h>
   #include <botan/pubkey.h>
#endif

namespace Botan_CLI {

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)

class PerfTest_PKKa : public PerfTest {
   public:
      virtual std::string algo() const = 0;

      virtual std::vector<std::string> keygen_params(const PerfConfig& config) const {
         BOTAN_UNUSED(config);
         return {""};
      }

      void go(const PerfConfig& config) override {
         const std::string alg = this->algo();

         const auto params = this->keygen_params(config);

         for(const auto& param : params) {
            const std::string nm = this->format_name(alg, param);
            bench_pk_ka(config, nm, alg, param);
         }
      }

      void bench_pk_ka(const PerfConfig& config,
                       const std::string& nm,
                       const std::string& algo,
                       const std::string& params,
                       const std::string& provider = "") {
         const auto msec = config.runtime();

         const std::string kdf = "KDF2(SHA-256)";  // arbitrary choice

         auto keygen_timer = config.make_timer(nm, 1, "keygen");

         auto& rng = config.rng();

         auto key1 = keygen_timer->run([&] { return Botan::create_private_key(algo, rng, params); });
         auto key2 = keygen_timer->run([&] { return Botan::create_private_key(algo, rng, params); });

         if(key1 && key2) {
            while(keygen_timer->under(msec)) {
               key2 = keygen_timer->run([&] { return Botan::create_private_key(algo, rng, params); });
            }

            config.record_result(*keygen_timer);

            const Botan::PK_Key_Agreement_Key& ka_key1 = dynamic_cast<const Botan::PK_Key_Agreement_Key&>(*key1);
            const Botan::PK_Key_Agreement_Key& ka_key2 = dynamic_cast<const Botan::PK_Key_Agreement_Key&>(*key2);

            Botan::PK_Key_Agreement ka1(ka_key1, rng, kdf, provider);
            Botan::PK_Key_Agreement ka2(ka_key2, rng, kdf, provider);

            const std::vector<uint8_t> ka1_pub = ka_key1.public_value();
            const std::vector<uint8_t> ka2_pub = ka_key2.public_value();

            auto ka_timer = config.make_timer(nm, 1, "key agreements");

            while(ka_timer->under(msec)) {
               auto k1 = ka_timer->run([&]() { return ka1.derive_key(32, ka2_pub); });
               auto k2 = ka_timer->run([&]() { return ka2.derive_key(32, ka1_pub); });

               if(k1 != k2) {
                  config.error_output() << "Key agreement mismatch in PK bench\n";
               }
            }

            config.record_result(*ka_timer);
         }
      }
};

#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)

class PerfTest_DH final : public PerfTest_PKKa {
   public:
      std::string algo() const override { return "DH"; }

      std::vector<std::string> keygen_params(const PerfConfig& config) const override {
         BOTAN_UNUSED(config);
         return {
            "ffdhe/ietf/2048",
            "ffdhe/ietf/3072",
            "ffdhe/ietf/4096",
            "ffdhe/ietf/6144",
            "ffdhe/ietf/8192",
         };
      }

      std::string format_name(const std::string& alg, const std::string& param) const override {
         return Botan::fmt("{}-{}", alg, param.substr(param.find_last_of('/') + 1));
      }
};

BOTAN_REGISTER_PERF_TEST("DH", PerfTest_DH);

#endif

#if defined(BOTAN_HAS_ECDH)

class PerfTest_ECDH final : public PerfTest_PKKa {
   public:
      std::string algo() const override { return "ECDH"; }

      std::vector<std::string> keygen_params(const PerfConfig& config) const override { return config.ecc_groups(); }
};

BOTAN_REGISTER_PERF_TEST("ECDH", PerfTest_ECDH);

#endif

#if defined(BOTAN_HAS_X25519)

class PerfTest_X25519 final : public PerfTest_PKKa {
   public:
      std::string algo() const override { return "X25519"; }
};

BOTAN_REGISTER_PERF_TEST("X25519", PerfTest_X25519);

#endif

#if defined(BOTAN_HAS_X448)

class PerfTest_X448 final : public PerfTest_PKKa {
   public:
      std::string algo() const override { return "X448"; }
};

BOTAN_REGISTER_PERF_TEST("X448", PerfTest_X448);

#endif

}  // namespace Botan_CLI
