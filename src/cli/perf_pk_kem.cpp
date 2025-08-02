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

class PerfTest_PK_KEM : public PerfTest {
   public:
      virtual std::string algo() const = 0;

      virtual std::vector<std::string> keygen_params(const PerfConfig& /*config*/) const { return {""}; }

      void go(const PerfConfig& config) override {
         const std::string alg = this->algo();

         const auto params = this->keygen_params(config);

         for(const auto& param : params) {
            const std::string nm = this->format_name(alg, param);
            bench_pk_kem(config, nm, alg, param);
         }
      }

      static void bench_pk_kem(const PerfConfig& config,
                               const std::string& nm,
                               const std::string& algo,
                               const std::string& params,
                               const std::string& provider = "") {
         const auto msec = config.runtime();
         auto& rng = config.rng();

         const std::string kdf = "KDF2(SHA-256)";  // arbitrary choice

         auto keygen_timer = config.make_timer(nm, 1, "keygen");

         auto sk = keygen_timer->run([&] { return Botan::create_private_key(algo, rng, params); });

         if(sk) {
            while(keygen_timer->under(msec)) {
               sk = keygen_timer->run([&] { return Botan::create_private_key(algo, rng, params); });
            }

            auto pk = sk->public_key();

            Botan::PK_KEM_Decryptor dec(*sk, rng, kdf, provider);
            Botan::PK_KEM_Encryptor enc(*pk, kdf, provider);

            auto kem_enc_timer = config.make_timer(nm, 1, "KEM encrypt");
            auto kem_dec_timer = config.make_timer(nm, 1, "KEM decrypt");

            while(kem_enc_timer->under(msec) && kem_dec_timer->under(msec)) {
               Botan::secure_vector<uint8_t> salt = rng.random_vec(16);

               kem_enc_timer->start();
               const auto kem_result = enc.encrypt(rng, 64, salt);
               kem_enc_timer->stop();

               kem_dec_timer->start();
               Botan::secure_vector<uint8_t> dec_shared_key =
                  dec.decrypt(kem_result.encapsulated_shared_key(), 64, salt);
               kem_dec_timer->stop();

               if(kem_result.shared_key() != dec_shared_key) {
                  config.error_output() << "KEM mismatch in PK bench\n";
               }
            }
            config.record_result(*keygen_timer);
            config.record_result(*kem_enc_timer);
            config.record_result(*kem_dec_timer);
         }
      }
};

#endif

#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S)

class PerfTest_Kyber final : public PerfTest_PK_KEM {
   public:
      std::string algo() const override { return "Kyber"; }

      std::vector<std::string> keygen_params(const PerfConfig& /*config*/) const override {
         return {
            "Kyber-512-r3",
            "Kyber-512-90s-r3",
            "Kyber-768-r3",
            "Kyber-768-90s-r3",
            "Kyber-1024-r3",
            "Kyber-1024-90s-r3",
         };
      }
};

BOTAN_REGISTER_PERF_TEST("Kyber", PerfTest_Kyber);

#endif

#if defined(BOTAN_HAS_ML_KEM)

class PerfTest_ML_KEM final : public PerfTest_PK_KEM {
   public:
      std::string algo() const override { return "ML-KEM"; }

      std::vector<std::string> keygen_params(const PerfConfig& /*config*/) const override {
         return {
            "ML-KEM-512",
            "ML-KEM-768",
            "ML-KEM-1024",
         };
      }
};

BOTAN_REGISTER_PERF_TEST("ML-KEM", PerfTest_ML_KEM);

#endif

#if defined(BOTAN_HAS_FRODOKEM)

class PerfTest_FrodoKEM final : public PerfTest_PK_KEM {
   public:
      std::string algo() const override { return "FrodoKEM"; }

      std::vector<std::string> keygen_params(const PerfConfig& /*config*/) const override {
         return {
            "FrodoKEM-640-SHAKE",
            "FrodoKEM-640-AES",
            "eFrodoKEM-640-SHAKE",
            "eFrodoKEM-640-AES",
            "FrodoKEM-976-SHAKE",
            "FrodoKEM-976-AES",
            "eFrodoKEM-976-SHAKE",
            "eFrodoKEM-976-AES",
            "FrodoKEM-1344-SHAKE",
            "FrodoKEM-1344-AES",
            "eFrodoKEM-1344-SHAKE",
            "eFrodoKEM-1344-AES",
         };
      }
};

BOTAN_REGISTER_PERF_TEST("FrodoKEM", PerfTest_FrodoKEM);

#endif

#if defined(BOTAN_HAS_CLASSICMCELIECE)

class PerfTest_Classic_McEliece final : public PerfTest_PK_KEM {
   public:
      std::string algo() const override { return "ClassicMcEliece"; }

      std::vector<std::string> keygen_params(const PerfConfig& /*config*/) const override {
         return {
            "348864",
            "348864f",
            "460896",
            "460896f",
            "6688128",
            "6688128f",
            "6688128pc",
            "6688128pcf",
            "6960119",
            "6960119f",
            "6960119pc",
            "6960119pcf",
            "8192128",
            "8192128f",
            "8192128pc",
            "8192128pcf",
         };
      }
};

BOTAN_REGISTER_PERF_TEST("ClassicMcEliece", PerfTest_Classic_McEliece);

#endif

}  // namespace Botan_CLI
