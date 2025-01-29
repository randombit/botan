/*
* PK Key
* (C) 1999-2010,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pk_algs.h>

#include <botan/assert.h>
#include <botan/internal/fmt.h>
#include <botan/internal/parsing.h>

#if defined(BOTAN_HAS_RSA)
   #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_CLASSICMCELIECE)
   #include <botan/cmce.h>
#endif

#if defined(BOTAN_HAS_DSA)
   #include <botan/dsa.h>
#endif

#if defined(BOTAN_HAS_DL_GROUP)
   #include <botan/dl_group.h>
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   #include <botan/dh.h>
#endif

#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)
   #include <botan/ecc_key.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
   #include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_ECGDSA)
   #include <botan/ecgdsa.h>
#endif

#if defined(BOTAN_HAS_ECKCDSA)
   #include <botan/eckcdsa.h>
#endif

#if defined(BOTAN_HAS_ED25519)
   #include <botan/ed25519.h>
#endif

#if defined(BOTAN_HAS_ED448)
   #include <botan/ed448.h>
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
   #include <botan/gost_3410.h>
#endif

#if defined(BOTAN_HAS_ELGAMAL)
   #include <botan/elgamal.h>
#endif

#if defined(BOTAN_HAS_ECDH)
   #include <botan/ecdh.h>
#endif

#if defined(BOTAN_HAS_X25519)
   #include <botan/x25519.h>
#endif

#if defined(BOTAN_HAS_X448)
   #include <botan/x448.h>
#endif

#if defined(BOTAN_HAS_MCELIECE)
   #include <botan/mceliece.h>
#endif

#if defined(BOTAN_HAS_FRODOKEM)
   #include <botan/frodokem.h>
#endif

#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S)
   #include <botan/kyber.h>
#endif

#if defined(BOTAN_HAS_ML_KEM)
   #include <botan/ml_kem.h>
#endif

#if defined(BOTAN_HAS_HSS_LMS)
   #include <botan/hss_lms.h>
#endif

#if defined(BOTAN_HAS_XMSS_RFC8391)
   #include <botan/xmss.h>
#endif

#if defined(BOTAN_HAS_SM2)
   #include <botan/sm2.h>
#endif

#if defined(BOTAN_HAS_DILITHIUM) || defined(BOTAN_HAS_DILITHIUM_AES)
   #include <botan/dilithium.h>
#endif

#if defined(BOTAN_HAS_ML_DSA)
   #include <botan/ml_dsa.h>
#endif

#if defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHA2) || defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHAKE)
   #include <botan/sphincsplus.h>
#endif

#if defined(BOTAN_HAS_SLH_DSA_WITH_SHA2) || defined(BOTAN_HAS_SLH_DSA_WITH_SHAKE)
   #include <botan/slh_dsa.h>
#endif

namespace Botan {

std::unique_ptr<Public_Key> load_public_key(const AlgorithmIdentifier& alg_id,
                                            [[maybe_unused]] std::span<const uint8_t> key_bits) {
   const std::string oid_str = alg_id.oid().to_formatted_string();
   const std::vector<std::string> alg_info = split_on(oid_str, '/');
   std::string_view alg_name = alg_info[0];

#if defined(BOTAN_HAS_RSA)
   if(alg_name == "RSA") {
      return std::make_unique<RSA_PublicKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_X25519)
   if(alg_name == "X25519" || alg_name == "Curve25519") {
      return std::make_unique<X25519_PublicKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_X448)
   if(alg_name == "X448") {
      return std::make_unique<X448_PublicKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_MCELIECE)
   if(alg_name == "McEliece") {
      return std::make_unique<McEliece_PublicKey>(key_bits);
   }
#endif

#if defined(BOTAN_HAS_FRODOKEM)
   if(alg_name == "FrodoKEM" || alg_name.starts_with("FrodoKEM-") || alg_name.starts_with("eFrodoKEM-")) {
      return std::make_unique<FrodoKEM_PublicKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S)
   if(alg_name == "Kyber" || alg_name.starts_with("Kyber-")) {
      return std::make_unique<Kyber_PublicKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_ML_KEM)
   if(alg_name.starts_with("ML-KEM-")) {
      return std::make_unique<ML_KEM_PublicKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_ECDSA)
   if(alg_name == "ECDSA") {
      return std::make_unique<ECDSA_PublicKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_ECDH)
   if(alg_name == "ECDH") {
      return std::make_unique<ECDH_PublicKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   if(alg_name == "DH") {
      return std::make_unique<DH_PublicKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_DSA)
   if(alg_name == "DSA") {
      return std::make_unique<DSA_PublicKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_ELGAMAL)
   if(alg_name == "ElGamal") {
      return std::make_unique<ElGamal_PublicKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_ECGDSA)
   if(alg_name == "ECGDSA") {
      return std::make_unique<ECGDSA_PublicKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_ECKCDSA)
   if(alg_name == "ECKCDSA") {
      return std::make_unique<ECKCDSA_PublicKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_ED25519)
   if(alg_name == "Ed25519") {
      return std::make_unique<Ed25519_PublicKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_ED448)
   if(alg_name == "Ed448") {
      return std::make_unique<Ed448_PublicKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
   if(alg_name == "GOST-34.10" || alg_name == "GOST-34.10-2012-256" || alg_name == "GOST-34.10-2012-512") {
      return std::make_unique<GOST_3410_PublicKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_SM2)
   if(alg_name == "SM2" || alg_name == "SM2_Sig" || alg_name == "SM2_Enc") {
      return std::make_unique<SM2_PublicKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_XMSS_RFC8391)
   if(alg_name == "XMSS") {
      return std::make_unique<XMSS_PublicKey>(key_bits);
   }
#endif

#if defined(BOTAN_HAS_DILITHIUM) || defined(BOTAN_HAS_DILITHIUM_AES)
   if(alg_name == "Dilithium" || alg_name.starts_with("Dilithium-")) {
      return std::make_unique<Dilithium_PublicKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_ML_DSA)
   if(alg_name.starts_with("ML-DSA-")) {
      return std::make_unique<ML_DSA_PublicKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_HSS_LMS)
   if(alg_name == "HSS-LMS") {
      return std::make_unique<HSS_LMS_PublicKey>(key_bits);
   }
#endif

#if defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHA2) || defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHAKE)
   if(alg_name == "SPHINCS+" || alg_name.starts_with("SphincsPlus-")) {
      return std::make_unique<SphincsPlus_PublicKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_SLH_DSA_WITH_SHA2) || defined(BOTAN_HAS_SLH_DSA_WITH_SHAKE)
   if(alg_name.starts_with("SLH-DSA-") || alg_name.starts_with("Hash-SLH-DSA-")) {
      return std::make_unique<SLH_DSA_PublicKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_CLASSICMCELIECE)
   if(alg_name.starts_with("ClassicMcEliece")) {
      return std::make_unique<Classic_McEliece_PublicKey>(alg_id, key_bits);
   }
#endif

   throw Decoding_Error(fmt("Unknown or unavailable public key algorithm '{}'", alg_name));
}

std::unique_ptr<Private_Key> load_private_key(const AlgorithmIdentifier& alg_id,
                                              [[maybe_unused]] std::span<const uint8_t> key_bits) {
   const std::string oid_str = alg_id.oid().to_formatted_string();
   const std::vector<std::string> alg_info = split_on(oid_str, '/');
   std::string_view alg_name = alg_info[0];

#if defined(BOTAN_HAS_RSA)
   if(alg_name == "RSA") {
      return std::make_unique<RSA_PrivateKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_X25519)
   if(alg_name == "X25519" || alg_name == "Curve25519") {
      return std::make_unique<X25519_PrivateKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_X448)
   if(alg_name == "X448") {
      return std::make_unique<X448_PrivateKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_ECDSA)
   if(alg_name == "ECDSA") {
      return std::make_unique<ECDSA_PrivateKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_ECDH)
   if(alg_name == "ECDH") {
      return std::make_unique<ECDH_PrivateKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   if(alg_name == "DH") {
      return std::make_unique<DH_PrivateKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_DSA)
   if(alg_name == "DSA") {
      return std::make_unique<DSA_PrivateKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_FRODOKEM)
   if(alg_name == "FrodoKEM" || alg_name.starts_with("FrodoKEM-") || alg_name.starts_with("eFrodoKEM-")) {
      return std::make_unique<FrodoKEM_PrivateKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S)
   if(alg_name == "Kyber" || alg_name.starts_with("Kyber-")) {
      return std::make_unique<Kyber_PrivateKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_ML_KEM)
   if(alg_name.starts_with("ML-KEM-")) {
      return std::make_unique<ML_KEM_PrivateKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_MCELIECE)
   if(alg_name == "McEliece") {
      return std::make_unique<McEliece_PrivateKey>(key_bits);
   }
#endif

#if defined(BOTAN_HAS_ECGDSA)
   if(alg_name == "ECGDSA") {
      return std::make_unique<ECGDSA_PrivateKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_ECKCDSA)
   if(alg_name == "ECKCDSA") {
      return std::make_unique<ECKCDSA_PrivateKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_ED25519)
   if(alg_name == "Ed25519") {
      return std::make_unique<Ed25519_PrivateKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_ED448)
   if(alg_name == "Ed448") {
      return std::make_unique<Ed448_PrivateKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
   if(alg_name == "GOST-34.10" || alg_name == "GOST-34.10-2012-256" || alg_name == "GOST-34.10-2012-512") {
      return std::make_unique<GOST_3410_PrivateKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_SM2)
   if(alg_name == "SM2" || alg_name == "SM2_Sig" || alg_name == "SM2_Enc") {
      return std::make_unique<SM2_PrivateKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_ELGAMAL)
   if(alg_name == "ElGamal") {
      return std::make_unique<ElGamal_PrivateKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_XMSS_RFC8391)
   if(alg_name == "XMSS") {
      return std::make_unique<XMSS_PrivateKey>(key_bits);
   }
#endif

#if defined(BOTAN_HAS_DILITHIUM) || defined(BOTAN_HAS_DILITHIUM_AES)
   if(alg_name == "Dilithium" || alg_name.starts_with("Dilithium-")) {
      return std::make_unique<Dilithium_PrivateKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_ML_DSA)
   if(alg_name.starts_with("ML-DSA-")) {
      return std::make_unique<ML_DSA_PrivateKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_HSS_LMS)
   if(alg_name == "HSS-LMS-Private-Key") {
      return std::make_unique<HSS_LMS_PrivateKey>(key_bits);
   }
#endif

#if defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHA2) || defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHAKE)
   if(alg_name == "SPHINCS+" || alg_name.starts_with("SphincsPlus-")) {
      return std::make_unique<SphincsPlus_PrivateKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_SLH_DSA_WITH_SHA2) || defined(BOTAN_HAS_SLH_DSA_WITH_SHAKE)
   if(alg_name.starts_with("SLH-DSA-") || alg_name.starts_with("Hash-SLH-DSA-")) {
      return std::make_unique<SLH_DSA_PrivateKey>(alg_id, key_bits);
   }
#endif

#if defined(BOTAN_HAS_CLASSICMCELIECE)
   if(alg_name.starts_with("ClassicMcEliece")) {
      return std::make_unique<Classic_McEliece_PrivateKey>(alg_id, key_bits);
   }
#endif

   throw Decoding_Error(fmt("Unknown or unavailable public key algorithm '{}'", alg_name));
}

std::unique_ptr<Private_Key> create_ec_private_key(std::string_view alg_name,
                                                   const EC_Group& ec_group,
                                                   RandomNumberGenerator& rng) {
   // Potentially unused if all EC algorithms are disabled
   BOTAN_UNUSED(alg_name, ec_group, rng);

#if defined(BOTAN_HAS_ECDSA)
   if(alg_name == "ECDSA") {
      return std::make_unique<ECDSA_PrivateKey>(rng, ec_group);
   }
#endif

#if defined(BOTAN_HAS_ECDH)
   if(alg_name == "ECDH") {
      return std::make_unique<ECDH_PrivateKey>(rng, ec_group);
   }
#endif

#if defined(BOTAN_HAS_ECKCDSA)
   if(alg_name == "ECKCDSA") {
      return std::make_unique<ECKCDSA_PrivateKey>(rng, ec_group);
   }
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
   if(alg_name == "GOST-34.10" || alg_name == "GOST-34.10-2012-256" || alg_name == "GOST-34.10-2012-512") {
      return std::make_unique<GOST_3410_PrivateKey>(rng, ec_group);
   }
#endif

#if defined(BOTAN_HAS_SM2)
   if(alg_name == "SM2" || alg_name == "SM2_Sig" || alg_name == "SM2_Enc") {
      return std::make_unique<SM2_PrivateKey>(rng, ec_group);
   }
#endif

#if defined(BOTAN_HAS_ECGDSA)
   if(alg_name == "ECGDSA") {
      return std::make_unique<ECGDSA_PrivateKey>(rng, ec_group);
   }
#endif

   return nullptr;
}

std::unique_ptr<Private_Key> create_private_key(std::string_view alg_name,
                                                RandomNumberGenerator& rng,
                                                std::string_view params,
                                                std::string_view provider) {
   /*
   * Default paramaters are chosen for work factor > 2**128 where possible
   */

#if defined(BOTAN_HAS_X25519)
   if(alg_name == "X25519" || alg_name == "Curve25519") {
      return std::make_unique<X25519_PrivateKey>(rng);
   }
#endif

#if defined(BOTAN_HAS_X448)
   if(alg_name == "X448") {
      return std::make_unique<X448_PrivateKey>(rng);
   }
#endif

#if defined(BOTAN_HAS_RSA)
   if(alg_name == "RSA") {
      const size_t modulus_bits = params.empty() ? 3072 : to_u32bit(params);
      return std::make_unique<RSA_PrivateKey>(rng, modulus_bits);
   }
#endif

#if defined(BOTAN_HAS_MCELIECE)
   if(alg_name == "McEliece") {
      const auto [n, t] = [&]() -> std::pair<size_t, size_t> {
         if(params.empty()) {
            return {2960, 57};
         }

         const auto mce_params = split_on(params, ',');

         if(mce_params.size() != 2) {
            throw Invalid_Argument(fmt("create_private_key: invalid McEliece parameters '{}'", params));
         }

         const size_t mce_n = to_u32bit(mce_params[0]);
         const size_t mce_t = to_u32bit(mce_params[1]);
         return {mce_n, mce_t};
      }();

      return std::make_unique<McEliece_PrivateKey>(rng, n, t);
   }
#endif
#if defined(BOTAN_HAS_CLASSICMCELIECE)
   if(alg_name == "ClassicMcEliece") {
      auto cmce_params_set = params.empty() ? Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119f
                                            : Classic_McEliece_Parameter_Set::from_string(params);
      return std::make_unique<Classic_McEliece_PrivateKey>(rng, cmce_params_set);
   }
#endif

#if defined(BOTAN_HAS_FRODOKEM)
   if(alg_name == "FrodoKEM") {
      const auto mode = params.empty() ? FrodoKEMMode::FrodoKEM976_SHAKE : FrodoKEMMode(params);
      return std::make_unique<FrodoKEM_PrivateKey>(rng, mode);
   }
#endif

#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S)
   if(alg_name == "Kyber") {
      const auto mode = [&]() -> KyberMode {
         if(params.empty()) {
            return KyberMode::Kyber1024_R3;
         }
         return KyberMode(params);
      }();

      return std::make_unique<Kyber_PrivateKey>(rng, mode);
   }
#endif

#if defined(BOTAN_HAS_ML_KEM)
   if(alg_name == "ML-KEM") {
      const auto mode = [&]() -> ML_KEM_Mode {
         if(params.empty()) {
            return ML_KEM_Mode::ML_KEM_768;
         }
         return ML_KEM_Mode(params);
      }();

      return std::make_unique<ML_KEM_PrivateKey>(rng, mode);
   }
#endif

#if defined(BOTAN_HAS_DILITHIUM) || defined(BOTAN_HAS_DILITHIUM_AES)
   if(alg_name == "Dilithium" || alg_name.starts_with("Dilithium-")) {
      const auto mode = [&]() -> DilithiumMode {
         if(params.empty()) {
            return DilithiumMode::Dilithium6x5;
         }
         return DilithiumMode(params);
      }();

      return std::make_unique<Dilithium_PrivateKey>(rng, mode);
   }
#endif

#if defined(BOTAN_HAS_ML_DSA)
   if(alg_name == "ML-DSA") {
      const auto mode = [&]() -> ML_DSA_Mode {
         if(params.empty()) {
            return ML_DSA_Mode::ML_DSA_6x5;
         }
         return ML_DSA_Mode(params);
      }();

      return std::make_unique<ML_DSA_PrivateKey>(rng, mode);
   }
#endif

#if defined(BOTAN_HAS_HSS_LMS)
   if(alg_name == "HSS-LMS") {
      const auto hss_params = [&]() -> std::string {
         if(params.empty()) {
            return "SHA-256,HW(10,1)";
         } else {
            return std::string(params);
         }
      }();
      return std::make_unique<HSS_LMS_PrivateKey>(rng, hss_params);
   }
#endif

#if defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHA2) || defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHAKE)
   if(alg_name == "SPHINCS+" || alg_name == "SphincsPlus") {
      auto sphincs_params = Sphincs_Parameters::create(params);

      return std::make_unique<SphincsPlus_PrivateKey>(rng, sphincs_params);
   }
#endif

#if defined(BOTAN_HAS_SLH_DSA_WITH_SHA2) || defined(BOTAN_HAS_SLH_DSA_WITH_SHAKE)
   if(alg_name == "SLH-DSA") {
      auto slh_dsa_params = SLH_DSA_Parameters::create(params);

      return std::make_unique<SLH_DSA_PrivateKey>(rng, slh_dsa_params);
   }
#endif

#if defined(BOTAN_HAS_XMSS_RFC8391)
   if(alg_name == "XMSS") {
      const auto xmss_oid = [&]() -> XMSS_Parameters::xmss_algorithm_t {
         if(params.empty()) {
            return XMSS_Parameters::XMSS_SHA2_10_512;
         }
         return XMSS_Parameters(params).oid();
      }();

      return std::make_unique<XMSS_PrivateKey>(xmss_oid, rng);
   }
#endif

#if defined(BOTAN_HAS_ED25519)
   if(alg_name == "Ed25519") {
      return std::make_unique<Ed25519_PrivateKey>(rng);
   }
#endif

#if defined(BOTAN_HAS_ED448)
   if(alg_name == "Ed448") {
      return std::make_unique<Ed448_PrivateKey>(rng);
   }
#endif

   // ECC crypto
#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)

   if(alg_name == "ECDSA" || alg_name == "ECDH" || alg_name == "ECKCDSA" || alg_name == "ECGDSA" || alg_name == "SM2" ||
      alg_name == "SM2_Sig" || alg_name == "SM2_Enc" || alg_name == "GOST-34.10" || alg_name == "GOST-34.10-2012-256" ||
      alg_name == "GOST-34.10-2012-512") {
      const std::string group_id = [&]() -> std::string {
         if(!params.empty()) {
            return std::string(params);
         }
         if(alg_name == "SM2" || alg_name == "SM2_Enc" || alg_name == "SM2_Sig") {
            return "sm2p256v1";
         }
         if(alg_name == "GOST-34.10" || alg_name == "GOST-34.10-2012-256") {
            return "gost_256A";
         }
         if(alg_name == "GOST-34.10-2012-512") {
            return "gost_512A";
         }
         if(alg_name == "ECGDSA") {
            return "brainpool256r1";
         }
         return "secp256r1";
      }();

      if(EC_Group::supports_named_group(group_id)) {
         auto ec_group = EC_Group::from_name(group_id);
         return create_ec_private_key(alg_name, ec_group, rng);
      } else {
         return {};
      }
   }
#endif

   // DL crypto
#if defined(BOTAN_HAS_DL_GROUP)
   if(alg_name == "DH" || alg_name == "DSA" || alg_name == "ElGamal") {
      const std::string group_id = [&]() -> std::string {
         if(!params.empty()) {
            return std::string(params);
         }
         if(alg_name == "DSA") {
            return "dsa/botan/2048";
         }
         return "modp/ietf/2048";
      }();

      auto modp_group = DL_Group::from_name(group_id);

   #if defined(BOTAN_HAS_DIFFIE_HELLMAN)
      if(alg_name == "DH") {
         return std::make_unique<DH_PrivateKey>(rng, modp_group);
      }
   #endif

   #if defined(BOTAN_HAS_DSA)
      if(alg_name == "DSA") {
         return std::make_unique<DSA_PrivateKey>(rng, modp_group);
      }
   #endif

   #if defined(BOTAN_HAS_ELGAMAL)
      if(alg_name == "ElGamal") {
         return std::make_unique<ElGamal_PrivateKey>(rng, modp_group);
      }
   #endif
   }
#endif

   BOTAN_UNUSED(alg_name, rng, params, provider);

   return std::unique_ptr<Private_Key>();
}

std::vector<std::string> probe_provider_private_key(std::string_view alg_name,
                                                    const std::vector<std::string>& possible) {
   std::vector<std::string> providers;

   for(auto&& prov : possible) {
      if(prov == "base") {
         providers.push_back(prov);
      }
   }

   BOTAN_UNUSED(alg_name);

   return providers;
}
}  // namespace Botan
