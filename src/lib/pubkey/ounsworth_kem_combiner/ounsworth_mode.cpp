/**
* Ounsworth KEM Combiner Mode
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ounsworth_mode.h>

#ifdef BOTAN_HAS_ECDH
   #include <botan/ecdh.h>
#endif
#ifdef BOTAN_HAS_FRODOKEM
   #include <botan/xof.h>

   #include <botan/frodokem.h>
   #include <botan/internal/frodo_constants.h>
#endif
#ifdef BOTAN_HAS_KYBER
   #include <botan/kyber.h>
   #include <botan/internal/kyber_constants.h>
#endif
#ifdef BOTAN_HAS_X25519
   #include <botan/x25519.h>
#endif
#ifdef BOTAN_HAS_X448
   #include <botan/x448.h>
#endif

#include <botan/der_enc.h>
#include <botan/kdf.h>
#include <botan/pk_algs.h>
#include <botan/internal/fmt.h>
#include <botan/internal/kex_to_kem_adapter.h>
#include <botan/internal/parsing.h>
#include <botan/internal/stl_util.h>

namespace Botan::Ounsworth {
namespace {

std::pair<std::string, std::string> algo_name_and_params_for_sub_algo(Ounsworth::Sub_Algo_Type algo) {
   switch(algo) {
#ifdef BOTAN_HAS_KYBER
      case Ounsworth::Sub_Algo_Type::Kyber512_R3:
         return {"Kyber", "Kyber-512-r3"};
      case Ounsworth::Sub_Algo_Type::Kyber768_R3:
         return {"Kyber", "Kyber-768-r3"};
      case Ounsworth::Sub_Algo_Type::Kyber1024_R3:
         return {"Kyber", "Kyber-1024-r3"};
#endif
#ifdef BOTAN_HAS_FRODOKEM_SHAKE
      case Ounsworth::Sub_Algo_Type::FrodoKEM640_SHAKE:
         return {"FrodoKEM", "FrodoKEM-640-SHAKE"};
      case Ounsworth::Sub_Algo_Type::FrodoKEM976_SHAKE:
         return {"FrodoKEM", "FrodoKEM-976-SHAKE"};
      case Ounsworth::Sub_Algo_Type::FrodoKEM1344_SHAKE:
         return {"FrodoKEM", "FrodoKEM-1344-SHAKE"};
#endif
#ifdef BOTAN_HAS_FRODOKEM_AES
      case Ounsworth::Sub_Algo_Type::FrodoKEM640_AES:
         return {"FrodoKEM", "FrodoKEM-640-AES"};
      case Ounsworth::Sub_Algo_Type::FrodoKEM976_AES:
         return {"FrodoKEM", "FrodoKEM-976-AES"};
      case Ounsworth::Sub_Algo_Type::FrodoKEM1344_AES:
         return {"FrodoKEM", "FrodoKEM-1344-AES"};
#endif
#ifdef BOTAN_HAS_X25519
      case Ounsworth::Sub_Algo_Type::X25519:
         return {"X25519", ""};
#endif
#ifdef BOTAN_HAS_X448
      case Ounsworth::Sub_Algo_Type::X448:
         return {"X448", ""};
#endif
#ifdef BOTAN_HAS_ECDH
      case Ounsworth::Sub_Algo_Type::ECDH_Secp192R1:
         return {"ECDH", "secp192r1"};
      case Ounsworth::Sub_Algo_Type::ECDH_Secp224R1:
         return {"ECDH", "secp224r1"};
      case Ounsworth::Sub_Algo_Type::ECDH_Secp256R1:
         return {"ECDH", "secp256r1"};
      case Ounsworth::Sub_Algo_Type::ECDH_Secp384R1:
         return {"ECDH", "secp384r1"};
      case Ounsworth::Sub_Algo_Type::ECDH_Secp521R1:
         return {"ECDH", "secp521r1"};
      case Ounsworth::Sub_Algo_Type::ECDH_Brainpool256R1:
         return {"ECDH", "brainpool256r1"};
      case Ounsworth::Sub_Algo_Type::ECDH_Brainpool384R1:
         return {"ECDH", "brainpool384r1"};
      case Ounsworth::Sub_Algo_Type::ECDH_Brainpool512R1:
         return {"ECDH", "brainpool512r1"};
#endif
   }
   BOTAN_ASSERT_UNREACHABLE();
}

std::pair<size_t, size_t> sk_pk_size_for_algo(Ounsworth::Sub_Algo_Type algo) {
   [[maybe_unused]] const auto [algo_name, algo_params] = algo_name_and_params_for_sub_algo(algo);

#ifdef BOTAN_HAS_KYBER
   if(algo_name == "Kyber") {
      const KyberConstants kyber_const((KyberMode(algo_params)));
      return std::make_pair(kyber_const.expanded_private_key_bytes(), kyber_const.public_key_bytes());
   }
#endif
#ifdef BOTAN_HAS_FRODOKEM
   if(algo_name == "FrodoKEM") {
      const FrodoKEMConstants frodo_const((FrodoKEMMode(algo_params)));
      return std::make_pair(frodo_const.len_private_key_bytes(), frodo_const.len_public_key_bytes());
   }
#endif
#ifdef BOTAN_HAS_X25519
   if(algo_name == "X25519") {
      return std::make_pair(32, 32);
   }
#endif
#ifdef BOTAN_HAS_X448
   if(algo_name == "X448") {
      return std::make_pair(56, 56);
   }
#endif
#ifdef BOTAN_HAS_ECDH
   if(algo_name == "ECDH") {
      const EC_Group ec_group(algo_params);
      return std::make_pair(ec_group.get_order_bytes(), ec_group.point_size(EC_Point_Format::Uncompressed));
   }
#endif

   throw Not_Implemented(fmt("Algorithm {} not yet supported for Ounsworth KEM combiner", algo_name));
}

bool is_kem(Ounsworth::Sub_Algo_Type algo) {
   const auto [alg_name, alg_params] = algo_name_and_params_for_sub_algo(algo);
   return alg_name == "Kyber" || alg_name == "FrodoKEM";
}

std::function<std::unique_ptr<Private_Key>(RandomNumberGenerator&)> get_create_private_key_callback(
   Ounsworth::Sub_Algo_Type algo) {
   // Using std::tie instead of a direct assignment prevents a clang bug
   [[maybe_unused]] std::string algo_name, algo_params;
   std::tie(algo_name, algo_params) = algo_name_and_params_for_sub_algo(algo);

   if(is_kem(algo)) {
      return [=](RandomNumberGenerator& rng) { return ::Botan::create_private_key(algo_name, rng, algo_params); };
   }
   return [=](RandomNumberGenerator& rng) -> std::unique_ptr<Private_Key> {
      std::unique_ptr<Private_Key> sk = ::Botan::create_private_key(algo_name, rng, algo_params);
      if(auto kex_sk = std::unique_ptr<PK_Key_Agreement_Key>(dynamic_cast<PK_Key_Agreement_Key*>(sk.release()))) {
         return std::make_unique<KEX_to_KEM_Adapter_PrivateKey>(std::move(kex_sk));
      }
      throw Invalid_Argument(fmt("Algorithm {} is not listed as KEM and does not support key agreement", algo_name));
   };
}

std::function<std::unique_ptr<Private_Key>(std::span<const uint8_t>)> get_load_private_key_raw_callback(
   Ounsworth::Sub_Algo_Type algo) {
   // Using std::tie instead of a direct assignment prevents a clang bug
   [[maybe_unused]] std::string algo_name, algo_params;
   std::tie(algo_name, algo_params) = algo_name_and_params_for_sub_algo(algo);
#ifdef BOTAN_HAS_KYBER
   if(algo_name == "Kyber") {
      return [=](std::span<const uint8_t> key_data) -> std::unique_ptr<Private_Key> {
         return std::make_unique<Kyber_PrivateKey>(key_data, KyberMode(algo_params));
      };
   }
#endif
#ifdef BOTAN_HAS_FRODOKEM
   if(algo_name == "FrodoKEM") {
      return [=](std::span<const uint8_t> key_data) -> std::unique_ptr<Private_Key> {
         return std::make_unique<FrodoKEM_PrivateKey>(key_data, FrodoKEMMode(algo_params));
      };
   }
#endif
#ifdef BOTAN_HAS_X25519
   if(algo_name == "X25519") {
      return [=](std::span<const uint8_t> key_data) -> std::unique_ptr<Private_Key> {
         const secure_vector<uint8_t> sk(key_data.begin(), key_data.end());
         return std::make_unique<KEX_to_KEM_Adapter_PrivateKey>(std::make_unique<X25519_PrivateKey>(sk));
      };
   }
#endif
#ifdef BOTAN_HAS_X448
   if(algo_name == "X448") {
      return [=](std::span<const uint8_t> key_data) -> std::unique_ptr<Private_Key> {
         return std::make_unique<KEX_to_KEM_Adapter_PrivateKey>(std::make_unique<X448_PrivateKey>(key_data));
      };
   }
#endif
#ifdef BOTAN_HAS_ECDH
   if(algo_name == "ECDH") {
      return [=](std::span<const uint8_t> key_data) -> std::unique_ptr<Private_Key> {
         const secure_vector<uint8_t> sk(key_data.begin(), key_data.end());
         // Sadly the ECDH private key constructor only accepts a DER encoded key. Therefore we need to encode it first.
         const auto encoded_sk = DER_Encoder()
                                    .start_sequence()
                                    .encode(static_cast<size_t>(1) /* version ecPrivkeyVer1 */)
                                    .encode(sk, ASN1_Type::OctetString)
                                    .end_cons()
                                    .get_contents();

         const AlgorithmIdentifier alg_id(OID::from_string("ECDH"),
                                          EC_Group(algo_params).DER_encode(EC_Group_Encoding::Explicit));

         return std::make_unique<KEX_to_KEM_Adapter_PrivateKey>(std::make_unique<ECDH_PrivateKey>(alg_id, encoded_sk));
      };
   }
#endif
   throw Invalid_Argument(fmt("Algorithm {} is not listed as KEM and does not support key agreement", algo_name));
}

std::function<std::unique_ptr<Public_Key>(std::span<const uint8_t>)> get_load_public_key_callback(
   Ounsworth::Sub_Algo_Type algo) {
   // Using std::tie instead of a direct assignment prevents a clang bug
   [[maybe_unused]] std::string algo_name, algo_params;
   std::tie(algo_name, algo_params) = algo_name_and_params_for_sub_algo(algo);
#ifdef BOTAN_HAS_KYBER
   if(algo_name == "Kyber") {
      return [=](std::span<const uint8_t> key_data) -> std::unique_ptr<Public_Key> {
         return std::make_unique<Kyber_PublicKey>(key_data, KyberMode(algo_params));
      };
   }
#endif
#ifdef BOTAN_HAS_FRODOKEM
   if(algo_name == "FrodoKEM") {
      return [=](std::span<const uint8_t> key_data) -> std::unique_ptr<Public_Key> {
         return std::make_unique<FrodoKEM_PublicKey>(key_data, FrodoKEMMode(algo_params));
      };
   }
#endif
#ifdef BOTAN_HAS_X25519
   if(algo_name == "X25519") {
      return [=](std::span<const uint8_t> key_data) -> std::unique_ptr<Public_Key> {
         const secure_vector<uint8_t> pk(key_data.begin(), key_data.end());
         return std::make_unique<KEX_to_KEM_Adapter_PublicKey>(std::make_unique<X25519_PublicKey>(pk));
      };
   }
#endif
#ifdef BOTAN_HAS_X448
   if(algo_name == "X448") {
      return [=](std::span<const uint8_t> key_data) -> std::unique_ptr<Public_Key> {
         return std::make_unique<KEX_to_KEM_Adapter_PublicKey>(std::make_unique<X448_PublicKey>(key_data));
      };
   }
#endif
#ifdef BOTAN_HAS_ECDH
   if(algo_name == "ECDH") {
      return [=](std::span<const uint8_t> key_data) -> std::unique_ptr<Public_Key> {
         const AlgorithmIdentifier alg_id(OID::from_string("ECDH"),
                                          EC_Group(algo_params).DER_encode(EC_Group_Encoding::Explicit));

         return std::make_unique<KEX_to_KEM_Adapter_PublicKey>(std::make_unique<ECDH_PublicKey>(alg_id, key_data));
      };
   }
#endif
   throw Invalid_Argument(fmt("Algorithm {} is not listed as KEM and does not support key agreement", algo_name));
}

}  // namespace

std::unique_ptr<Botan::KDF> Ounsworth::Kdf::create_kdf_instance() const {
   switch(type()) {
      case Option::KMAC128:
         return KDF::create_or_throw("SP800-56A(KMAC-128)");
      case Option::KMAC256:
         return KDF::create_or_throw("SP800-56A(KMAC-256)");
      case Option::SHA3_256:
         return KDF::create_or_throw("SP800-56A(SHA-3(256))");
      case Option::SHA3_512:
         return KDF::create_or_throw("SP800-56A(SHA-3(512))");
   }
   BOTAN_ASSERT_UNREACHABLE();
}

PrivateKeyGenerationInfo::PrivateKeyGenerationInfo(Sub_Algo_Type algo) :
      m_create_private_key_callback(get_create_private_key_callback(algo)) {}

PrivateKeyImportInfo::PrivateKeyImportInfo(Sub_Algo_Type algo) :
      m_load_private_key_callback(get_load_private_key_raw_callback(algo)),
      m_raw_sk_length(sk_pk_size_for_algo(algo).first) {}

PublicKeyImportInfo::PublicKeyImportInfo(Sub_Algo_Type algo) :
      m_load_public_key_callback(get_load_public_key_callback(algo)),
      m_raw_pk_length(sk_pk_size_for_algo(algo).second) {}

}  // namespace Botan::Ounsworth
