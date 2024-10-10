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

      virtual std::vector<std::string> keygen_params(const PerfConfig& config) const {
         BOTAN_UNUSED(config);
         return {""};
      }

      virtual std::string format_name(const std::string& alg, const std::string& param) const {
         return param.empty() ? alg : Botan::fmt("{}-{}", alg, param);
      }

      void go(const PerfConfig& config) override {
         const std::string alg = this->algo();

         const auto params = this->keygen_params(config);

         for(const auto& param : params) {
            const std::string nm = this->format_name(alg, param);
            bench_pk_kem(config, nm, alg, param);
         }
      }

      void bench_pk_kem(const PerfConfig& config,
                        const std::string& nm,
                        const std::string& algo,
                        const std::string& params,
                        const std::string& provider = "") {
         const auto msec = config.runtime();
         auto& rng = config.rng();

         const std::string kdf = "KDF2(SHA-256)";  // arbitrary choice

         auto keygen_timer = config.make_timer(nm, 1, "keygen");

         auto key = keygen_timer->run([&] { return Botan::create_private_key(algo, rng, params); });

         Botan::PK_KEM_Decryptor dec(*key, rng, kdf, provider);
         Botan::PK_KEM_Encryptor enc(*key, kdf, provider);

         auto kem_enc_timer = config.make_timer(nm, 1, "KEM encrypt");
         auto kem_dec_timer = config.make_timer(nm, 1, "KEM decrypt");

         while(kem_enc_timer->under(msec) && kem_dec_timer->under(msec)) {
            Botan::secure_vector<uint8_t> salt = rng.random_vec(16);

            kem_enc_timer->start();
            const auto kem_result = enc.encrypt(rng, 64, salt);
            kem_enc_timer->stop();

            kem_dec_timer->start();
            Botan::secure_vector<uint8_t> dec_shared_key = dec.decrypt(kem_result.encapsulated_shared_key(), 64, salt);
            kem_dec_timer->stop();

            if(kem_result.shared_key() != dec_shared_key) {
               config.error_output() << "KEM mismatch in PK bench\n";
            }
         }

         config.record_result(*kem_enc_timer);
         config.record_result(*kem_dec_timer);
      }
};

#endif

#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S)

class PerfTest_Kyber final : public PerfTest_PK_KEM {
   public:
      std::string algo() const override { return "Kyber"; }

      std::vector<std::string> keygen_params(const PerfConfig& config) const override {
         BOTAN_UNUSED(config);
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

#if defined(BOTAN_HAS_FRODOKEM)

class PerfTest_FrodoKEM final : public PerfTest_PK_KEM {
   public:
      std::string algo() const override { return "FrodoKEM"; }

      std::vector<std::string> keygen_params(const PerfConfig& config) const override {
         BOTAN_UNUSED(config);
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

}  // namespace Botan_CLI
