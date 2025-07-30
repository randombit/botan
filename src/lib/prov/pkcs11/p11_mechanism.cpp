/*
* PKCS#11 Mechanism
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/p11_mechanism.h>

#include <botan/internal/fmt.h>
#include <botan/internal/parsing.h>
#include <botan/internal/pk_options.h>
#include <botan/internal/scan_name.h>
#include <tuple>

namespace Botan::PKCS11 {

namespace {
using PSS_Params = std::tuple<size_t, MechanismType, MGF>;

// maps a PSS mechanism type to the number of bytes used for the salt, the mechanism type of the underlying hash algorithm and the MGF
const std::map<MechanismType, PSS_Params>& PssOptions() {
   static const std::map<MechanismType, PSS_Params> pss_options = {
      {MechanismType::RsaPkcsPss, PSS_Params(0, MechanismType::Sha1, MGF::Mgf1Sha1)},
      {MechanismType::Sha1RsaPkcsPss, PSS_Params(20, MechanismType::Sha1, MGF::Mgf1Sha1)},
      {MechanismType::Sha224RsaPkcsPss, PSS_Params(28, MechanismType::Sha224, MGF::Mgf1Sha224)},
      {MechanismType::Sha256RsaPkcsPss, PSS_Params(32, MechanismType::Sha256, MGF::Mgf1Sha256)},
      {MechanismType::Sha384RsaPkcsPss, PSS_Params(48, MechanismType::Sha384, MGF::Mgf1Sha384)},
      {MechanismType::Sha512RsaPkcsPss, PSS_Params(64, MechanismType::Sha512, MGF::Mgf1Sha512)}};

   return pss_options;
}

class MechanismData {
   public:
      explicit MechanismData(MechanismType type) : m_type(type) {}

      MechanismData(const MechanismData& other) = default;
      MechanismData(MechanismData&& other) = default;

      MechanismData& operator=(const MechanismData& other) = default;
      MechanismData& operator=(MechanismData&& other) = default;

      virtual ~MechanismData() = default;

      MechanismType type() const { return m_type; }

   private:
      // the mechanism to perform
      MechanismType m_type;
};

class RSA_SignMechanism final : public MechanismData {
   public:
      explicit RSA_SignMechanism(MechanismType typ) noexcept :
            MechanismData(typ), m_hash(static_cast<MechanismType>(0)), m_mgf(MGF::MgfUnused), m_salt_size(0) {
         auto pss_option = PssOptions().find(type());
         if(pss_option != PssOptions().end()) {
            m_hash = std::get<1>(pss_option->second);
            m_mgf = std::get<2>(pss_option->second);
            m_salt_size = std::get<0>(pss_option->second);
         }
      }

      MechanismType hash() const { return m_hash; }

      MGF mgf() const { return m_mgf; }

      size_t salt_size() const { return m_salt_size; }

   private:
      /*
      hash algorithm used in the PSS encoding; if the signature
      mechanism does not include message hashing, then this value must
      be the mechanism used by the application to generate the message
      hash; if the signature mechanism includes hashing, then this
      value must match the hash algorithm indicated by the signature mechanism
      */
      MechanismType m_hash;

      // mask generation function to use on the encoded block
      MGF m_mgf;

      // length, in bytes, of the salt value used in the PSS encoding; typical values are the length of the message hash and zero
      size_t m_salt_size;
};

struct RSA_CryptMechanism final : public MechanismData {
   public:
      RSA_CryptMechanism(MechanismType typ, size_t padding_size, MechanismType hash, MGF mgf) :
            MechanismData(typ), m_hash(hash), m_mgf(mgf), m_padding_size(padding_size) {}

      RSA_CryptMechanism(MechanismType typ, size_t padding_size) :
            RSA_CryptMechanism(typ, padding_size, static_cast<MechanismType>(0), MGF::MgfUnused) {}

      MechanismType hash() const { return m_hash; }

      MGF mgf() const { return m_mgf; }

      size_t padding_size() const { return m_padding_size; }

   private:
      // mechanism ID of the message digest algorithm used to calculate the digest of the encoding parameter
      MechanismType m_hash;

      // mask generation function to use on the encoded block
      MGF m_mgf;

      // number of bytes required for the padding
      size_t m_padding_size;
};

}  // namespace

MechanismWrapper::MechanismWrapper(MechanismType mechanism_type) :
      m_mechanism({static_cast<CK_MECHANISM_TYPE>(mechanism_type), nullptr, 0}), m_parameters(nullptr) {}

MechanismWrapper MechanismWrapper::create_rsa_crypt_mechanism(std::string_view padding) {
   // note: when updating this map, update the documentation for `MechanismWrapper::create_rsa_crypt_mechanism`
   static const std::map<std::string_view, RSA_CryptMechanism> CryptMechanisms = {
      {"Raw", RSA_CryptMechanism(MechanismType::RsaX509, 0)},
      // TODO(Botan4) Remove this
      {"EME-PKCS1-v1_5", RSA_CryptMechanism(MechanismType::RsaPkcs, 11)},
      {"PKCS1v15", RSA_CryptMechanism(MechanismType::RsaPkcs, 11)},
      {"OAEP(SHA-1)", RSA_CryptMechanism(MechanismType::RsaPkcsOaep, 2 + 2 * 20, MechanismType::Sha1, MGF::Mgf1Sha1)},
      {"OAEP(SHA-224)",
       RSA_CryptMechanism(MechanismType::RsaPkcsOaep, 2 + 2 * 28, MechanismType::Sha224, MGF::Mgf1Sha224)},
      {"OAEP(SHA-256)",
       RSA_CryptMechanism(MechanismType::RsaPkcsOaep, 2 + 2 * 32, MechanismType::Sha256, MGF::Mgf1Sha256)},
      {"OAEP(SHA-384)",
       RSA_CryptMechanism(MechanismType::RsaPkcsOaep, 2 + 2 * 48, MechanismType::Sha384, MGF::Mgf1Sha384)},
      {"OAEP(SHA-512)",
       RSA_CryptMechanism(MechanismType::RsaPkcsOaep, 2 + 2 * 64, MechanismType::Sha512, MGF::Mgf1Sha512)}};

   auto mechanism_info_it = CryptMechanisms.find(padding);
   if(mechanism_info_it == CryptMechanisms.end()) {
      // at this point it would be possible to support additional configurations that are not predefined above by parsing `padding`
      throw Lookup_Error(fmt("PKCS#11 RSA encrypt/decrypt does not support padding with '{}'", padding));
   }
   RSA_CryptMechanism mechanism_info = mechanism_info_it->second;

   MechanismWrapper mech(mechanism_info.type());
   if(mechanism_info.type() == MechanismType::RsaPkcsOaep) {
      mech.m_parameters = std::make_shared<MechanismParameters>();
      mech.m_parameters->oaep_params.hashAlg = static_cast<CK_MECHANISM_TYPE>(mechanism_info.hash());
      mech.m_parameters->oaep_params.mgf = static_cast<CK_RSA_PKCS_MGF_TYPE>(mechanism_info.mgf());
      mech.m_parameters->oaep_params.source = CKZ_DATA_SPECIFIED;
      mech.m_parameters->oaep_params.pSourceData = nullptr;
      mech.m_parameters->oaep_params.ulSourceDataLen = 0;
      mech.m_mechanism.pParameter = mech.m_parameters.get();
      mech.m_mechanism.ulParameterLen = sizeof(RsaPkcsOaepParams);
   }
   mech.m_padding_size = mechanism_info.padding_size();
   return mech;
}

MechanismWrapper MechanismWrapper::create_rsa_sign_mechanism(const PK_Signature_Options& options) {
   // note: when updating this map, update the documentation for `MechanismWrapper::create_rsa_sign_mechanism`
   static const std::map<std::string_view, RSA_SignMechanism> SignMechanisms = {
      {"Raw", RSA_SignMechanism(MechanismType::RsaX509)},

      // X9.31
      {"X9.31(Raw)", RSA_SignMechanism(MechanismType::RsaX931)},
      {"X9.31(SHA-1)", RSA_SignMechanism(MechanismType::Sha1RsaX931)},

      // RSASSA PKCS#1 v1.5
      {"PKCS1v15(SHA-1)", RSA_SignMechanism(MechanismType::Sha1RsaPkcs)},
      {"PKCS1v15(SHA-224)", RSA_SignMechanism(MechanismType::Sha224RsaPkcs)},
      {"PKCS1v15(SHA-256)", RSA_SignMechanism(MechanismType::Sha256RsaPkcs)},
      {"PKCS1v15(SHA-384)", RSA_SignMechanism(MechanismType::Sha384RsaPkcs)},
      {"PKCS1v15(SHA-512)", RSA_SignMechanism(MechanismType::Sha512RsaPkcs)},

      // PSS PKCS#1 v2.0
      {"PSS(Raw)", RSA_SignMechanism(MechanismType::RsaPkcsPss)},

      {"PSS(SHA-1)", RSA_SignMechanism(MechanismType::Sha1RsaPkcsPss)},
      {"PSS(SHA-1,MGF1,20)", RSA_SignMechanism(MechanismType::Sha1RsaPkcsPss)},

      {"PSS(SHA-224)", RSA_SignMechanism(MechanismType::Sha224RsaPkcsPss)},
      {"PSS(SHA-224,MGF1,24)", RSA_SignMechanism(MechanismType::Sha224RsaPkcsPss)},

      {"PSS(SHA-256)", RSA_SignMechanism(MechanismType::Sha256RsaPkcsPss)},
      {"PSS(SHA-256,MGF1,32)", RSA_SignMechanism(MechanismType::Sha256RsaPkcsPss)},

      {"PSS(SHA-384)", RSA_SignMechanism(MechanismType::Sha384RsaPkcsPss)},
      {"PSS(SHA-384,MGF1,48)", RSA_SignMechanism(MechanismType::Sha384RsaPkcsPss)},

      {"PSS(SHA-512)", RSA_SignMechanism(MechanismType::Sha512RsaPkcsPss)},
      {"PSS(SHA-512,MGF1,64)", RSA_SignMechanism(MechanismType::Sha512RsaPkcsPss)},

      // ISO 9796 - this is the obsolete and insecure DS1 scheme, not the PSS-based DS2/DS3
      // TODO(Botan4) remove this
      {"ISO9796", RSA_SignMechanism(MechanismType::Rsa9796)},

      // Deprecated aliases
      // TODO(Botan4) remove these
      {"EMSA2(Raw)", RSA_SignMechanism(MechanismType::RsaX931)},
      {"EMSA2(SHA-1)", RSA_SignMechanism(MechanismType::Sha1RsaX931)},

      {"EMSA3(Raw)", RSA_SignMechanism(MechanismType::RsaPkcs)},
      {"EMSA3(SHA-1)", RSA_SignMechanism(MechanismType::Sha1RsaPkcs)},
      {"EMSA3(SHA-224)", RSA_SignMechanism(MechanismType::Sha224RsaPkcs)},
      {"EMSA3(SHA-256)", RSA_SignMechanism(MechanismType::Sha256RsaPkcs)},
      {"EMSA3(SHA-384)", RSA_SignMechanism(MechanismType::Sha384RsaPkcs)},
      {"EMSA3(SHA-512)", RSA_SignMechanism(MechanismType::Sha512RsaPkcs)},

      {"EMSA_PKCS1(SHA-1)", RSA_SignMechanism(MechanismType::Sha1RsaPkcs)},
      {"EMSA_PKCS1(SHA-224)", RSA_SignMechanism(MechanismType::Sha224RsaPkcs)},
      {"EMSA_PKCS1(SHA-256)", RSA_SignMechanism(MechanismType::Sha256RsaPkcs)},
      {"EMSA_PKCS1(SHA-384)", RSA_SignMechanism(MechanismType::Sha384RsaPkcs)},
      {"EMSA_PKCS1(SHA-512)", RSA_SignMechanism(MechanismType::Sha512RsaPkcs)},

      {"EMSA4(Raw)", RSA_SignMechanism(MechanismType::RsaPkcsPss)},
      {"EMSA4(SHA-1)", RSA_SignMechanism(MechanismType::Sha1RsaPkcsPss)},
      {"EMSA4(SHA-224)", RSA_SignMechanism(MechanismType::Sha224RsaPkcsPss)},

      {"EMSA4(SHA-256)", RSA_SignMechanism(MechanismType::Sha256RsaPkcsPss)},
      {"EMSA4(SHA-256,MGF1,32)", RSA_SignMechanism(MechanismType::Sha256RsaPkcsPss)},
      {"PSSR(SHA-256,MGF1,32)", RSA_SignMechanism(MechanismType::Sha256RsaPkcsPss)},

      {"EMSA4(SHA-384)", RSA_SignMechanism(MechanismType::Sha384RsaPkcsPss)},
      {"EMSA4(SHA-384,MGF1,48)", RSA_SignMechanism(MechanismType::Sha384RsaPkcsPss)},
      {"PSSR(SHA-384,MGF1,48)", RSA_SignMechanism(MechanismType::Sha384RsaPkcsPss)},

      {"EMSA4(SHA-512)", RSA_SignMechanism(MechanismType::Sha512RsaPkcsPss)},
      {"EMSA4(SHA-512,MGF1,64)", RSA_SignMechanism(MechanismType::Sha512RsaPkcsPss)},
      {"PSSR(SHA-512,MGF1,64)", RSA_SignMechanism(MechanismType::Sha512RsaPkcsPss)},
   };

   const std::string padding = [&]() {
      if(options.using_hash() && options.using_padding()) {
         return fmt("{}({})", options.padding().value(), options.hash_function_name());
      }

      if(options.using_padding()) {
         return options.padding().value();
      }

      if(options.using_hash()) {
         return options.hash_function_name();
      }

      throw Invalid_Argument("RSA signature requires a padding scheme");
   }();

   auto mechanism_info_it = SignMechanisms.find(padding);
   if(mechanism_info_it == SignMechanisms.end()) {
      // at this point it would be possible to support additional configurations that are not predefined above by parsing `padding`
      throw Lookup_Error(fmt("PKCS#11 RSA sign/verify does not support padding with '{}'", padding));
   }
   RSA_SignMechanism mechanism_info = mechanism_info_it->second;

   MechanismWrapper mech(mechanism_info.type());
   if(PssOptions().contains(mechanism_info.type())) {
      mech.m_parameters = std::make_shared<MechanismParameters>();
      mech.m_parameters->pss_params.hashAlg = static_cast<CK_MECHANISM_TYPE>(mechanism_info.hash());
      mech.m_parameters->pss_params.mgf = static_cast<CK_RSA_PKCS_MGF_TYPE>(mechanism_info.mgf());
      mech.m_parameters->pss_params.sLen = static_cast<Ulong>(mechanism_info.salt_size());
      mech.m_mechanism.pParameter = mech.m_parameters.get();
      mech.m_mechanism.ulParameterLen = sizeof(RsaPkcsPssParams);
   }
   return mech;
}

MechanismWrapper MechanismWrapper::create_ecdsa_mechanism(std::string_view hash_spec_view) {
   // note: when updating this map, update the documentation for `MechanismWrapper::create_ecdsa_mechanism`
   static const std::map<std::string_view, MechanismType> EcdsaHash = {{"Raw", MechanismType::Ecdsa},
                                                                       {"SHA-1", MechanismType::EcdsaSha1},
                                                                       {"SHA-224", MechanismType::EcdsaSha224},
                                                                       {"SHA-256", MechanismType::EcdsaSha256},
                                                                       {"SHA-384", MechanismType::EcdsaSha384},
                                                                       {"SHA-512", MechanismType::EcdsaSha512}};

   const std::string hash_spec(hash_spec_view);
   auto mechanism = EcdsaHash.find(hash_spec);
   if(mechanism != EcdsaHash.end()) {
      return MechanismWrapper(mechanism->second);
   }

   SCAN_Name req(hash_spec);

   if(req.algo_name() == "EMSA1" && req.arg_count() == 1) {
      mechanism = EcdsaHash.find(req.arg(0));
      if(mechanism != EcdsaHash.end()) {
         return MechanismWrapper(mechanism->second);
      }
   }

   throw Lookup_Error(fmt("PKCS #11 ECDSA sign/verify does not support {}", hash_spec));
}

MechanismWrapper MechanismWrapper::create_ecdh_mechanism(std::string_view params) {
   // note: when updating this map, update the documentation for `MechanismWrapper::create_ecdh_mechanism`
   static const std::map<std::string_view, KeyDerivation> EcdhHash = {{"Raw", KeyDerivation::Null},
                                                                      {"SHA-1", KeyDerivation::Sha1Kdf},
                                                                      {"SHA-224", KeyDerivation::Sha224Kdf},
                                                                      {"SHA-256", KeyDerivation::Sha256Kdf},
                                                                      {"SHA-384", KeyDerivation::Sha384Kdf},
                                                                      {"SHA-512", KeyDerivation::Sha512Kdf}};

   std::vector<std::string> param_parts = split_on(params, ',');

   if(param_parts.empty() || param_parts.size() > 2) {
      throw Invalid_Argument(fmt("PKCS #11 ECDH key derivation bad params {}", params));
   }

   const bool use_cofactor =
      (param_parts[0] == "Cofactor") || (param_parts.size() == 2 && param_parts[1] == "Cofactor");

   std::string kdf_name = (param_parts[0] == "Cofactor" ? param_parts[1] : param_parts[0]);
   std::string hash = kdf_name;

   if(kdf_name != "Raw") {
      SCAN_Name kdf_hash(kdf_name);

      if(kdf_hash.arg_count() > 0) {
         hash = kdf_hash.arg(0);
      }
   }

   auto kdf = EcdhHash.find(hash);
   if(kdf == EcdhHash.end()) {
      throw Lookup_Error("PKCS#11 ECDH key derivation does not support KDF " + kdf_name);
   }
   MechanismWrapper mech(use_cofactor ? MechanismType::Ecdh1CofactorDerive : MechanismType::Ecdh1Derive);
   mech.m_parameters = std::make_shared<MechanismParameters>();
   mech.m_parameters->ecdh_params.kdf = static_cast<CK_EC_KDF_TYPE>(kdf->second);
   mech.m_mechanism.pParameter = mech.m_parameters.get();
   mech.m_mechanism.ulParameterLen = sizeof(Ecdh1DeriveParams);
   return mech;
}

}  // namespace Botan::PKCS11
