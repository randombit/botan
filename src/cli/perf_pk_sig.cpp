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

class PerfTest_PKSig : public PerfTest {
   public:
      virtual std::string algo() const = 0;

      virtual std::string hash() const { return "SHA-256"; }

      virtual std::vector<std::string> keygen_params(const PerfConfig& config) const {
         BOTAN_UNUSED(config);
         return {""};
      }

      void go(const PerfConfig& config) override {
         const std::string alg = this->algo();
         const std::string padding = this->hash();

         const auto params = this->keygen_params(config);

         for(const auto& param : params) {
            const std::string nm = this->format_name(alg, param);
            bench_pk_sig(config, nm, alg, param, padding);
         }
      }

      void bench_pk_sig(const PerfConfig& config,
                        const std::string& nm,
                        const std::string& alg,
                        const std::string& param,
                        const std::string& padding,
                        const std::string& provider = "") {
         auto& rng = config.rng();
         const auto msec = config.runtime();

         auto keygen_timer = config.make_timer(nm, 1, "keygen");

         auto sk = keygen_timer->run([&] { return Botan::create_private_key(alg, rng, param); });

         if(sk != nullptr) {
            while(keygen_timer->under(msec)) {
               sk = keygen_timer->run([&] { return Botan::create_private_key(alg, rng, param); });
            }

            config.record_result(*keygen_timer);

            auto pk = sk->public_key();

            std::vector<uint8_t> message, signature, bad_signature;

            Botan::PK_Signer sig(*sk, rng, padding, Botan::Signature_Format::Standard, provider);
            Botan::PK_Verifier ver(*pk, padding, Botan::Signature_Format::Standard, provider);

            auto sig_timer = config.make_timer(nm, 1, "sign");
            auto ver_timer = config.make_timer(nm, 1, "verify");

            size_t invalid_sigs = 0;

            while(ver_timer->under(msec) || sig_timer->under(msec)) {
               if(signature.empty() || sig_timer->under(msec)) {
                  /*
                  Length here is kind of arbitrary, but 48 bytes fits into a single
                  hash block so minimizes hashing overhead versus the PK op itself.
                  */
                  rng.random_vec(message, 48);

                  signature = sig_timer->run([&]() { return sig.sign_message(message, rng); });

                  bad_signature = signature;
                  bad_signature[rng.next_byte() % bad_signature.size()] ^= rng.next_nonzero_byte();
               }

               if(ver_timer->under(msec)) {
                  const bool verified = ver_timer->run([&] { return ver.verify_message(message, signature); });

                  if(!verified) {
                     invalid_sigs += 1;
                  }

                  const bool verified_bad = ver_timer->run([&] { return ver.verify_message(message, bad_signature); });

                  if(verified_bad) {
                     config.error_output() << "Bad signature accepted in " << nm << " signature bench\n";
                  }
               }
            }

            if(invalid_sigs > 0) {
               config.error_output() << invalid_sigs << " generated signatures rejected in " << nm
                                     << " signature bench\n";
            }
            config.record_result(*sig_timer);
            config.record_result(*ver_timer);
         }
      }
};

#endif

#if defined(BOTAN_HAS_DSA)

class PerfTest_DSA final : public PerfTest_PKSig {
   public:
      std::string algo() const override { return "DSA"; }

      std::vector<std::string> keygen_params(const PerfConfig& config) const override {
         BOTAN_UNUSED(config);
         return {"dsa/jce/1024", "dsa/botan/2048", "dsa/botan/3072"};
      }

      std::string format_name(const std::string& alg, const std::string& param) const override {
         return Botan::fmt("{}-{}", alg, param.substr(param.find_last_of('/') + 1));
      }
};

BOTAN_REGISTER_PERF_TEST("DSA", PerfTest_DSA);

#endif

#if defined(BOTAN_HAS_RSA)

class PerfTest_RSA final : public PerfTest_PKSig {
   public:
      std::string algo() const override { return "RSA"; }

      std::string hash() const override { return "PKCS1v15(SHA-256)"; }

      std::vector<std::string> keygen_params(const PerfConfig& config) const override {
         BOTAN_UNUSED(config);
         return {"1024", "2048", "3072", "4096"};
      }
};

BOTAN_REGISTER_PERF_TEST("RSA", PerfTest_RSA);

#endif

#if defined(BOTAN_HAS_ECDSA)

class PerfTest_ECDSA final : public PerfTest_PKSig {
   public:
      std::string algo() const override { return "ECDSA"; }

      std::vector<std::string> keygen_params(const PerfConfig& config) const override { return config.ecc_groups(); }
};

BOTAN_REGISTER_PERF_TEST("ECDSA", PerfTest_ECDSA);

#endif

#if defined(BOTAN_HAS_ECKCDSA)

class PerfTest_ECKCDSA final : public PerfTest_PKSig {
   public:
      std::string algo() const override { return "ECKCDSA"; }

      std::vector<std::string> keygen_params(const PerfConfig& config) const override { return config.ecc_groups(); }
};

BOTAN_REGISTER_PERF_TEST("ECKCDSA", PerfTest_ECKCDSA);

#endif

#if defined(BOTAN_HAS_ECGDSA)

class PerfTest_ECGDSA final : public PerfTest_PKSig {
   public:
      std::string algo() const override { return "ECGDSA"; }

      std::vector<std::string> keygen_params(const PerfConfig& config) const override { return config.ecc_groups(); }
};

BOTAN_REGISTER_PERF_TEST("ECGDSA", PerfTest_ECGDSA);

#endif

#if defined(BOTAN_HAS_GOST_34_10_2001) && defined(BOTAN_HAS_GOST_34_11)

class PerfTest_Gost3410 final : public PerfTest_PKSig {
   public:
      std::string algo() const override { return "GOST-34.10"; }

      std::string hash() const override { return "GOST-34.11"; }

      std::vector<std::string> keygen_params(const PerfConfig& config) const override {
         BOTAN_UNUSED(config);
         return {"gost_256A"};
      }
};

BOTAN_REGISTER_PERF_TEST("GOST-34.10", PerfTest_Gost3410);

#endif

#if defined(BOTAN_HAS_SM2) && defined(BOTAN_HAS_SM3)

class PerfTest_SM2 final : public PerfTest_PKSig {
   public:
      std::string algo() const override { return "SM2"; }

      std::string hash() const override { return "SM3"; }

      std::vector<std::string> keygen_params(const PerfConfig& config) const override {
         BOTAN_UNUSED(config);
         return {"sm2p256v1"};
      }
};

BOTAN_REGISTER_PERF_TEST("SM2", PerfTest_SM2);

#endif

#if defined(BOTAN_HAS_ED25519)

class PerfTest_Ed25519 final : public PerfTest_PKSig {
   public:
      std::string algo() const override { return "Ed25519"; }

      std::string hash() const override { return "Pure"; }
};

BOTAN_REGISTER_PERF_TEST("Ed25519", PerfTest_Ed25519);

#endif

#if defined(BOTAN_HAS_ED448)

class PerfTest_Ed448 final : public PerfTest_PKSig {
   public:
      std::string algo() const override { return "Ed448"; }

      std::string hash() const override { return "Pure"; }
};

BOTAN_REGISTER_PERF_TEST("Ed448", PerfTest_Ed448);

#endif

#if defined(BOTAN_HAS_XMSS_RFC8391)

class PerfTest_XMSS final : public PerfTest_PKSig {
   public:
      std::string algo() const override { return "XMSS"; }

      std::string hash() const override { return ""; }

      std::vector<std::string> keygen_params(const PerfConfig& config) const override {
         BOTAN_UNUSED(config);

         /*
         We only test H10 signatures here since already they are quite slow (a
         few seconds per signature). On a fast machine, H16 signatures take 1-2
         minutes to generate and H20 signatures take 5-10 minutes to generate
         */
         return {
            "XMSS-SHA2_10_256",
            "XMSS-SHAKE_10_256",
            "XMSS-SHA2_10_512",
            "XMSS-SHAKE_10_512",
         };
      }
};

BOTAN_REGISTER_PERF_TEST("XMSS", PerfTest_XMSS);

#endif

#if defined(BOTAN_HAS_HSS_LMS)

class PerfTest_HSS_LMS final : public PerfTest_PKSig {
   public:
      std::string algo() const override { return "HSS-LMS"; }

      std::string hash() const override { return ""; }

      std::vector<std::string> keygen_params(const PerfConfig& config) const override {
         BOTAN_UNUSED(config);

         // At first we compare instances with multiple hash functions. LMS trees with
         // height 10 are suitable, since they can be used for enough signatures and are
         // fast enough for speed testing.
         // Afterward, setups with multiple HSS layers are tested
         return {"SHA-256,HW(10,1)",
                 "SHAKE-256(256),HW(10,1)",
                 "SHAKE-256(192),HW(10,1)",
                 "Truncated(SHA-256,192),HW(10,1)",
                 "SHA-256,HW(10,1),HW(10,1)",
                 "SHA-256,HW(10,1),HW(10,1),HW(10,1)"};
      }
};

BOTAN_REGISTER_PERF_TEST("HSS-LMS", PerfTest_HSS_LMS);

#endif

#if defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHA2) || defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHAKE)

class PerfTest_SPHINCSp final : public PerfTest_PKSig {
   public:
      std::string algo() const override { return "SPHINCS+"; }

      std::string hash() const override { return ""; }

      std::string format_name(const std::string& alg, const std::string& param) const override {
         return alg + param.substr(11);
      }

      std::vector<std::string> keygen_params(const PerfConfig& config) const override {
         BOTAN_UNUSED(config);

         return {"SphincsPlus-sha2-128s-r3.1",
                 "SphincsPlus-sha2-128f-r3.1",
                 "SphincsPlus-sha2-192s-r3.1",
                 "SphincsPlus-sha2-192f-r3.1",
                 "SphincsPlus-sha2-256s-r3.1",
                 "SphincsPlus-sha2-256f-r3.1",
                 "SphincsPlus-shake-128s-r3.1",
                 "SphincsPlus-shake-128f-r3.1",
                 "SphincsPlus-shake-192s-r3.1",
                 "SphincsPlus-shake-192f-r3.1",
                 "SphincsPlus-shake-256s-r3.1",
                 "SphincsPlus-shake-256f-r3.1"};
      }
};

BOTAN_REGISTER_PERF_TEST("SPHINCS+", PerfTest_SPHINCSp);

#endif

#if defined(BOTAN_HAS_SLH_DSA_WITH_SHA2) || defined(BOTAN_HAS_SLH_DSA_WITH_SHAKE)

class PerfTest_SLH_DSA final : public PerfTest_PKSig {
   public:
      std::string algo() const override { return "SLH-DSA"; }

      std::string hash() const override { return ""; }

      std::vector<std::string> keygen_params(const PerfConfig& config) const override {
         BOTAN_UNUSED(config);

         return {"SLH-DSA-SHA2-128s",
                 "SLH-DSA-SHA2-128f",
                 "SLH-DSA-SHA2-192s",
                 "SLH-DSA-SHA2-192f",
                 "SLH-DSA-SHA2-256s",
                 "SLH-DSA-SHA2-256f",
                 "SLH-DSA-SHAKE-128s",
                 "SLH-DSA-SHAKE-128f",
                 "SLH-DSA-SHAKE-192s",
                 "SLH-DSA-SHAKE-192f",
                 "SLH-DSA-SHAKE-256s",
                 "SLH-DSA-SHAKE-256f"};
      }
};

BOTAN_REGISTER_PERF_TEST("SLH-DSA", PerfTest_SLH_DSA);

#endif

#if defined(BOTAN_HAS_DILITHIUM) || defined(BOTAN_HAS_DILITHIUM_AES)

class PerfTest_Dilithium final : public PerfTest_PKSig {
   public:
      std::string algo() const override { return "Dilithium"; }

      std::string hash() const override { return ""; }

      std::vector<std::string> keygen_params(const PerfConfig& config) const override {
         BOTAN_UNUSED(config);

         return {
            "Dilithium-4x4-r3",
            "Dilithium-4x4-AES-r3",
            "Dilithium-6x5-r3",
            "Dilithium-6x5-AES-r3",
            "Dilithium-8x7-r3",
            "Dilithium-8x7-AES-r3",
         };
      }
};

BOTAN_REGISTER_PERF_TEST("Dilithium", PerfTest_Dilithium);

#endif

#if defined(BOTAN_HAS_ML_DSA)

class PerfTest_ML_DSA final : public PerfTest_PKSig {
   public:
      std::string algo() const override { return "ML-DSA"; }

      std::string hash() const override { return ""; }

      std::vector<std::string> keygen_params(const PerfConfig& config) const override {
         BOTAN_UNUSED(config);

         return {
            "ML-DSA-4x4",
            "ML-DSA-6x5",
            "ML-DSA-8x7",
         };
      }
};

BOTAN_REGISTER_PERF_TEST("ML-DSA", PerfTest_ML_DSA);

#endif

}  // namespace Botan_CLI
