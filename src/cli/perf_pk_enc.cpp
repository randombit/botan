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

class PerfTest_PKEnc : public PerfTest {
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
         auto& rng = config.rng();
         const auto msec = config.runtime();

         std::vector<uint8_t> plaintext, ciphertext;

         auto keygen_timer = config.make_timer(nm, 1, "keygen");

         auto sk = keygen_timer->run([&] { return Botan::create_private_key(algo, rng, params); });

         if(sk) {
            while(keygen_timer->under(msec)) {
               sk = keygen_timer->run([&] { return Botan::create_private_key(algo, rng, params); });
            }

            auto pk = sk->public_key();

            // TODO this would have to be generalized for anything but RSA/ElGamal
            const std::string padding = "PKCS1v15";

            Botan::PK_Encryptor_EME enc(*pk, rng, padding, provider);
            Botan::PK_Decryptor_EME dec(*sk, rng, padding, provider);

            auto enc_timer = config.make_timer(nm + " " + padding, 1, "encrypt");
            auto dec_timer = config.make_timer(nm + " " + padding, 1, "decrypt");

            while(enc_timer->under(msec) || dec_timer->under(msec)) {
               // Generate a new random ciphertext to decrypt
               if(ciphertext.empty() || enc_timer->under(msec)) {
                  rng.random_vec(plaintext, enc.maximum_input_size());
                  ciphertext = enc_timer->run([&]() { return enc.encrypt(plaintext, rng); });
               }

               if(dec_timer->under(msec)) {
                  const auto dec_pt = dec_timer->run([&]() { return dec.decrypt(ciphertext); });

                  // sanity check
                  if(!(Botan::unlock(dec_pt) == plaintext)) {
                     config.error_output() << "Bad roundtrip in PK encrypt/decrypt bench\n";
                  }
               }
            }

            config.record_result(*keygen_timer);
            config.record_result(*enc_timer);
            config.record_result(*dec_timer);
         }
      }
};

#endif

#if defined(BOTAN_HAS_ELGAMAL)

class PerfTest_ElGamal final : public PerfTest_PKEnc {
   public:
      std::string algo() const override { return "ElGamal"; }

      std::vector<std::string> keygen_params(const PerfConfig& config) const override {
         BOTAN_UNUSED(config);
         return {
            "modp/ietf/1024",
            "modp/ietf/2048",
            "modp/ietf/3072",
            "modp/ietf/4096",
         };
      }

      std::string format_name(const std::string& alg, const std::string& param) const override {
         return Botan::fmt("{}-{}", alg, param.substr(param.find_last_of('/') + 1));
      }
};

BOTAN_REGISTER_PERF_TEST("ElGamal", PerfTest_ElGamal);

#endif

}  // namespace Botan_CLI
