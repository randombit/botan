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

#include <botan/kdf.h>
#include <botan/kex_to_kem_adapter.h>
#include <botan/pk_algs.h>
#include <botan/internal/fmt.h>
#include <botan/internal/parsing.h>
#include <botan/internal/stl_util.h>

namespace Botan {
namespace {

std::pair<size_t, size_t> sk_pk_size_for_algo([[maybe_unused]] std::string_view algo_name,
                                              [[maybe_unused]] std::string_view algo_params) {
#ifdef BOTAN_HAS_KYBER
   if(algo_name == "Kyber") {
      const KyberConstants kyber_const((KyberMode(algo_params)));
      return std::make_pair(kyber_const.private_key_byte_length(), kyber_const.public_key_byte_length());
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

bool is_kem(Ounsworth::Sub_Algo_Type algo) {
   const auto [alg_name, alg_params] = algo_name_and_params_for_sub_algo(algo);
   return alg_name == "Kyber" || alg_name == "FrodoKEM";
}

Ounsworth::Sub_Algo_Type sub_algo_type_from_string(std::string_view algo) {
#ifdef BOTAN_HAS_KYBER
   if(algo == "Kyber-512-r3") {
      return Ounsworth::Sub_Algo_Type::Kyber512_R3;
   }
   if(algo == "Kyber-768-r3") {
      return Ounsworth::Sub_Algo_Type::Kyber768_R3;
   }
   if(algo == "Kyber-1024-r3") {
      return Ounsworth::Sub_Algo_Type::Kyber1024_R3;
   }
#endif
#ifdef BOTAN_HAS_FRODOKEM_SHAKE
   if(algo == "FrodoKEM-640-SHAKE") {
      return Ounsworth::Sub_Algo_Type::FrodoKEM640_SHAKE;
   }
   if(algo == "FrodoKEM-976-SHAKE") {
      return Ounsworth::Sub_Algo_Type::FrodoKEM976_SHAKE;
   }
   if(algo == "FrodoKEM-1344-SHAKE") {
      return Ounsworth::Sub_Algo_Type::FrodoKEM1344_SHAKE;
   }
#endif
#ifdef BOTAN_HAS_FRODOKEM_AES
   if(algo == "FrodoKEM-640-AES") {
      return Ounsworth::Sub_Algo_Type::FrodoKEM640_AES;
   }
   if(algo == "FrodoKEM-976-AES") {
      return Ounsworth::Sub_Algo_Type::FrodoKEM976_AES;
   }
   if(algo == "FrodoKEM-1344-AES") {
      return Ounsworth::Sub_Algo_Type::FrodoKEM1344_AES;
   }
#endif
#ifdef BOTAN_HAS_X25519
   if(algo == "X25519") {
      return Ounsworth::Sub_Algo_Type::X25519;
   }
#endif
#ifdef BOTAN_HAS_X448
   if(algo == "X448") {
      return Ounsworth::Sub_Algo_Type::X448;
   }
#endif
#ifdef BOTAN_HAS_ECDH
   if(algo == "ECDH-secp192r1") {
      return Ounsworth::Sub_Algo_Type::ECDH_Secp192R1;
   }
   if(algo == "ECDH-secp224r1") {
      return Ounsworth::Sub_Algo_Type::ECDH_Secp224R1;
   }
   if(algo == "ECDH-secp256r1") {
      return Ounsworth::Sub_Algo_Type::ECDH_Secp256R1;
   }
   if(algo == "ECDH-secp384r1") {
      return Ounsworth::Sub_Algo_Type::ECDH_Secp384R1;
   }
   if(algo == "ECDH-secp521r1") {
      return Ounsworth::Sub_Algo_Type::ECDH_Secp521R1;
   }
   if(algo == "ECDH-brainpool256r1") {
      return Ounsworth::Sub_Algo_Type::ECDH_Brainpool256R1;
   }
   if(algo == "ECDH-brainpool384r1") {
      return Ounsworth::Sub_Algo_Type::ECDH_Brainpool384R1;
   }
   if(algo == "ECDH-brainpool512r1") {
      return Ounsworth::Sub_Algo_Type::ECDH_Brainpool512R1;
   }
#endif
   throw Invalid_Argument(fmt("Unknown Ounsworth sub-algorithm type '{}'", algo));
}

std::string sub_algo_type_to_string(Ounsworth::Sub_Algo_Type type) {
   switch(type) {
#ifdef BOTAN_HAS_KYBER
      case Ounsworth::Sub_Algo_Type::Kyber512_R3:
         return "Kyber-512-r3";
      case Ounsworth::Sub_Algo_Type::Kyber768_R3:
         return "Kyber-768-r3";
      case Ounsworth::Sub_Algo_Type::Kyber1024_R3:
         return "Kyber-1024-r3";
#endif
#ifdef BOTAN_HAS_FRODOKEM_SHAKE
      case Ounsworth::Sub_Algo_Type::FrodoKEM640_SHAKE:
         return "FrodoKEM-640-SHAKE";
      case Ounsworth::Sub_Algo_Type::FrodoKEM976_SHAKE:
         return "FrodoKEM-976-SHAKE";
      case Ounsworth::Sub_Algo_Type::FrodoKEM1344_SHAKE:
         return "FrodoKEM-1344-SHAKE";
#endif
#ifdef BOTAN_HAS_FRODOKEM_AES
      case Ounsworth::Sub_Algo_Type::FrodoKEM640_AES:
         return "FrodoKEM-640-AES";
      case Ounsworth::Sub_Algo_Type::FrodoKEM976_AES:
         return "FrodoKEM-976-AES";
      case Ounsworth::Sub_Algo_Type::FrodoKEM1344_AES:
         return "FrodoKEM-1344-AES";
#endif
#ifdef BOTAN_HAS_X25519
      case Ounsworth::Sub_Algo_Type::X25519:
         return "X25519";
#endif
#ifdef BOTAN_HAS_X448
      case Ounsworth::Sub_Algo_Type::X448:
         return "X448";
#endif
#ifdef BOTAN_HAS_ECDH
      case Ounsworth::Sub_Algo_Type::ECDH_Secp192R1:
         return "ECDH-secp192R1";
      case Ounsworth::Sub_Algo_Type::ECDH_Secp224R1:
         return "ECDH-secp224R1";
      case Ounsworth::Sub_Algo_Type::ECDH_Secp256R1:
         return "ECDH-secp256r1";
      case Ounsworth::Sub_Algo_Type::ECDH_Secp384R1:
         return "ECDH-secp384r1";
      case Ounsworth::Sub_Algo_Type::ECDH_Secp521R1:
         return "ECDH-secp521r1";
      case Ounsworth::Sub_Algo_Type::ECDH_Brainpool256R1:
         return "ECDH-brainpool256r1";
      case Ounsworth::Sub_Algo_Type::ECDH_Brainpool384R1:
         return "ECDH-brainpool384r1";
      case Ounsworth::Sub_Algo_Type::ECDH_Brainpool512R1:
         return "ECDH-brainpool512r1";
#endif
   }
   BOTAN_ASSERT_UNREACHABLE();
}

Ounsworth::Kdf_Type kdf_type_from_string(std::string_view type) {
   if(type == "KMAC-128") {
      return Ounsworth::Kdf_Type::KMAC128;
   }
   if(type == "KMAC-256") {
      return Ounsworth::Kdf_Type::KMAC256;
   }
   if(type == "SHA3-256") {
      return Ounsworth::Kdf_Type::SHA3_256;
   }
   if(type == "SHA3-512") {
      return Ounsworth::Kdf_Type::SHA3_512;
   }
   throw Invalid_Argument(fmt("Unknown Ounsworth KDF type '{}'", type));
}

std::string kdf_type_to_string(Ounsworth::Kdf_Type type) {
   switch(type) {
      case Ounsworth::Kdf_Type::KMAC128:
         return "KMAC-128";
      case Ounsworth::Kdf_Type::KMAC256:
         return "KMAC-256";
      case Ounsworth::Kdf_Type::SHA3_256:
         return "SHA3-256";
      case Ounsworth::Kdf_Type::SHA3_512:
         return "SHA3-512";
   }
   BOTAN_ASSERT_UNREACHABLE();
}

// Example: "OunsworthKEMCombiner/Kyber-512-r3/FrodoKEM-640-SHAKE/KMAC-128"
std::pair<std::vector<Ounsworth::Sub_Algo_Type>, Ounsworth::Kdf_Type> parse_ounsworth_mode(std::string_view mode) {
   const std::string prefix = Ounsworth::Mode::algorithm_name();
   const std::vector<std::string> parts = split_on(mode, '/');
   BOTAN_ARG_CHECK(parts.size() >= 4, "Ounsworth mode string must contain at least 4 parts");
   BOTAN_ARG_CHECK(parts[0] == Ounsworth::Mode::algorithm_name(), "Invalid Ounsworth mode string");

   // Parse sub-algorithms
   std::vector<Ounsworth::Sub_Algo_Type> sub_algo_types;
   std::transform(parts.begin() + 1, parts.end() - 1, std::back_inserter(sub_algo_types), [](const std::string& part) {
      return sub_algo_type_from_string(part);
   });
   // Parse KDF
   const Ounsworth::Kdf_Type kdf_type = kdf_type_from_string(parts.back());

   return {sub_algo_types, kdf_type};
}

std::function<std::unique_ptr<Private_Key>(RandomNumberGenerator&)> get_create_private_key_callback(
   Ounsworth::Sub_Algo_Type algo, std::string_view algo_name_view, std::string_view algo_params_view) {
   if(is_kem(algo)) {
      return [algo_name = std::string(algo_name_view), algo_params = std::string(algo_params_view)](
                RandomNumberGenerator& rng) { return ::Botan::create_private_key(algo_name, rng, algo_params); };
   }
   return [algo_name = std::string(algo_name_view),
           algo_params = std::string(algo_params_view)](RandomNumberGenerator& rng) -> std::unique_ptr<Private_Key> {
      std::unique_ptr<Private_Key> sk = ::Botan::create_private_key(algo_name, rng, algo_params);
      if(auto kex_sk = std::unique_ptr<PK_Key_Agreement_Key>(dynamic_cast<PK_Key_Agreement_Key*>(sk.release()))) {
         return std::make_unique<KEX_to_KEM_Adapter_PrivateKey>(std::move(kex_sk));
      }
      throw Invalid_Argument(fmt("Algorithm {} is not listed as KEM and does not support key agreement", algo_name));
   };
}

std::function<std::unique_ptr<Private_Key>(std::span<const uint8_t>)> get_load_private_key_raw_callback(
   [[maybe_unused]] std::string_view algo_name_view, [[maybe_unused]] std::string_view algo_params_view) {
#ifdef BOTAN_HAS_KYBER
   if(algo_name_view == "Kyber") {
      return [algo_params =
                 std::string(algo_params_view)](std::span<const uint8_t> key_data) -> std::unique_ptr<Private_Key> {
         return std::make_unique<Kyber_PrivateKey>(key_data, KyberMode(algo_params));
      };
   }
#endif
#ifdef BOTAN_HAS_FRODOKEM
   if(algo_name_view == "FrodoKEM") {
      return [algo_params =
                 std::string(algo_params_view)](std::span<const uint8_t> key_data) -> std::unique_ptr<Private_Key> {
         return std::make_unique<FrodoKEM_PrivateKey>(key_data, FrodoKEMMode(algo_params));
      };
   }
#endif
#ifdef BOTAN_HAS_X25519
   if(algo_name_view == "X25519") {
      return [algo_params =
                 std::string(algo_params_view)](std::span<const uint8_t> key_data) -> std::unique_ptr<Private_Key> {
         const secure_vector<uint8_t> sk(key_data.begin(), key_data.end());
         return std::make_unique<KEX_to_KEM_Adapter_PrivateKey>(std::make_unique<X25519_PrivateKey>(sk));
      };
   }
#endif
#ifdef BOTAN_HAS_X448
   if(algo_name_view == "X448") {
      return [algo_params =
                 std::string(algo_params_view)](std::span<const uint8_t> key_data) -> std::unique_ptr<Private_Key> {
         return std::make_unique<KEX_to_KEM_Adapter_PrivateKey>(std::make_unique<X448_PrivateKey>(key_data));
      };
   }
#endif
#ifdef BOTAN_HAS_ECDH
   if(algo_name_view == "ECDH") {
      return [algo_params =
                 std::string(algo_params_view)](std::span<const uint8_t> key_data) -> std::unique_ptr<Private_Key> {
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
   throw Invalid_Argument(fmt("Algorithm {} is not listed as KEM and does not support key agreement", algo_name_view));
}

std::function<std::unique_ptr<Public_Key>(std::span<const uint8_t>)> get_load_public_key_callback(
   [[maybe_unused]] std::string_view algo_name_view, [[maybe_unused]] std::string_view algo_params_view) {
#ifdef BOTAN_HAS_KYBER
   if(algo_name_view == "Kyber") {
      return [algo_params =
                 std::string(algo_params_view)](std::span<const uint8_t> key_data) -> std::unique_ptr<Public_Key> {
         return std::make_unique<Kyber_PublicKey>(key_data, KyberMode(algo_params));
      };
   }
#endif
#ifdef BOTAN_HAS_FRODOKEM
   if(algo_name_view == "FrodoKEM") {
      return [algo_params =
                 std::string(algo_params_view)](std::span<const uint8_t> key_data) -> std::unique_ptr<Public_Key> {
         return std::make_unique<FrodoKEM_PublicKey>(key_data, FrodoKEMMode(algo_params));
      };
   }
#endif
#ifdef BOTAN_HAS_X25519
   if(algo_name_view == "X25519") {
      return [algo_params =
                 std::string(algo_params_view)](std::span<const uint8_t> key_data) -> std::unique_ptr<Public_Key> {
         const secure_vector<uint8_t> pk(key_data.begin(), key_data.end());
         return std::make_unique<KEX_to_KEM_Adapter_PublicKey>(std::make_unique<X25519_PublicKey>(pk));
      };
   }
#endif
#ifdef BOTAN_HAS_X448
   if(algo_name_view == "X448") {
      return [algo_params =
                 std::string(algo_params_view)](std::span<const uint8_t> key_data) -> std::unique_ptr<Public_Key> {
         return std::make_unique<KEX_to_KEM_Adapter_PublicKey>(std::make_unique<X448_PublicKey>(key_data));
      };
   }
#endif
#ifdef BOTAN_HAS_ECDH
   if(algo_name_view == "ECDH") {
      return [algo_params =
                 std::string(algo_params_view)](std::span<const uint8_t> key_data) -> std::unique_ptr<Public_Key> {
         const AlgorithmIdentifier alg_id(OID::from_string("ECDH"),
                                          EC_Group(algo_params).DER_encode(EC_Group_Encoding::Explicit));

         return std::make_unique<KEX_to_KEM_Adapter_PublicKey>(std::make_unique<ECDH_PublicKey>(alg_id, key_data));
      };
   }
#endif
   throw Invalid_Argument(fmt("Algorithm {} is not listed as KEM and does not support key agreement", algo_name_view));
}

std::string ounsworth_mode_to_string(const Ounsworth::Mode& mode) {
   std::stringstream ss;
   ss << Ounsworth::Mode::algorithm_name() << "/";
   for(const auto& sub_algo : mode.sub_algos()) {
      if(auto type = sub_algo.type()) {
         ss << sub_algo_type_to_string(*type);
      } else {
         throw Invalid_State("No algorithm identifiers for sub-algorithms with custom types");
      }
      ss << "/";
   }
   ss << kdf_type_to_string(mode.kdf_mode());
   return ss.str();
}

}  // namespace

Ounsworth::Sub_Algo::Sub_Algo(Sub_Algo_Type algo) : m_maybe_type(algo) {
   const auto [algo_name, algo_params] = algo_name_and_params_for_sub_algo(algo);
   std::tie(m_raw_sk_length, m_raw_pk_length) = sk_pk_size_for_algo(algo_name, algo_params);

   m_create_private_key_callback = get_create_private_key_callback(algo, algo_name, algo_params);
   m_load_private_key_callback = get_load_private_key_raw_callback(algo_name, algo_params);
   m_load_public_key_callback = get_load_public_key_callback(algo_name, algo_params);
}

Ounsworth::Mode::Mode(std::string_view mode_str) {
   const auto [sub_algo_types, kdf_mode] = parse_ounsworth_mode(mode_str);
   std::transform(
      sub_algo_types.begin(), sub_algo_types.end(), std::back_inserter(m_sub_algos), [](Sub_Algo_Type algo) {
         return Sub_Algo(algo);
      });
   BOTAN_ARG_CHECK(m_sub_algos.size() >= 2, "At least two sub-algorithms must be provided");
   m_kdf = kdf_mode;
}

Ounsworth::Mode::Mode(const AlgorithmIdentifier& alg_id) : Ounsworth::Mode::Mode(alg_id.oid().to_formatted_string()) {}

std::unique_ptr<KDF> Ounsworth::Mode::kdf_instance() const {
   switch(kdf_mode()) {
      case KMAC128:
         return KDF::create_or_throw("SP800-56A(KMAC-128)");
      case KMAC256:
         return KDF::create_or_throw("SP800-56A(KMAC-256)");
      case SHA3_256:
         return KDF::create_or_throw("SP800-56A(SHA-3(256))");
      case SHA3_512:
         return KDF::create_or_throw("SP800-56A(SHA-3(512))");
   }
   BOTAN_ASSERT_UNREACHABLE();
}

AlgorithmIdentifier Ounsworth::Mode::algorithm_identifier() const {
   try {
      return AlgorithmIdentifier(OID::from_string(ounsworth_mode_to_string(*this)),
                                 AlgorithmIdentifier::USE_EMPTY_PARAM);
   } catch(Lookup_Error&) {
      throw Invalid_State("No algorithm identifier specified for this Ounsworth mode.");
   }
   BOTAN_ASSERT_UNREACHABLE();
}

size_t Ounsworth::Mode::pk_length() const {
   return reduce(m_sub_algos, size_t(0), [](size_t acc, const Sub_Algo& algo) { return acc + algo.raw_pk_length(); });
}

size_t Ounsworth::Mode::sk_length() const {
   return reduce(m_sub_algos, size_t(0), [](size_t acc, const Sub_Algo& algo) { return acc + algo.raw_sk_length(); });
}

}  // namespace Botan
