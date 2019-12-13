/*
* PKCS#11 Mechanism
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/p11_mechanism.h>
#include <botan/scan_name.h>
#include <botan/parsing.h>
#include <botan/emsa.h>

#include <tuple>

namespace Botan {
namespace PKCS11 {

namespace {
using PSS_Params = std::tuple<size_t, MechanismType, MGF>;

// maps a PSS mechanism type to the number of bytes used for the salt, the mechanism type of the underlying hash algorithm and the MGF
static const std::map<MechanismType, PSS_Params> PssOptions =
   {
      { MechanismType::RsaPkcsPss, PSS_Params(0, MechanismType::Sha1, MGF::Mgf1Sha1) },
      { MechanismType::Sha1RsaPkcsPss, PSS_Params(20, MechanismType::Sha1, MGF::Mgf1Sha1) },
      { MechanismType::Sha224RsaPkcsPss, PSS_Params(28, MechanismType::Sha224, MGF::Mgf1Sha224) },
      { MechanismType::Sha256RsaPkcsPss, PSS_Params(32, MechanismType::Sha256, MGF::Mgf1Sha256) },
      { MechanismType::Sha384RsaPkcsPss, PSS_Params(48, MechanismType::Sha384, MGF::Mgf1Sha384) },
      { MechanismType::Sha512RsaPkcsPss, PSS_Params(64, MechanismType::Sha512, MGF::Mgf1Sha512) }
   };

struct MechanismData
   {
   explicit MechanismData(MechanismType _type)
      : type(_type)
      {}

   MechanismData(MechanismData const&) = default;
   MechanismData& operator=(MechanismData const&) = default;
   virtual ~MechanismData() = default;

   // the mechanism to perform
   MechanismType type;
   };

struct RSA_SignMechanism final : public MechanismData
   {
   explicit RSA_SignMechanism(MechanismType _type)
      : MechanismData(_type), hash(static_cast<MechanismType>(0)), mgf(static_cast<MGF>(0)), salt_size(0)
      {
      auto pss_option = PssOptions.find(type);
      if(pss_option != PssOptions.end())
         {
         hash = std::get<1>(pss_option->second);
         mgf = std::get<2>(pss_option->second);
         salt_size = std::get<0>(pss_option->second);
         }
      }

   // hash algorithm used in the PSS encoding; if the signature mechanism does not include message hashing,
   // then this value must be the mechanism used by the application to generate the message hash;
   // if the signature mechanism includes hashing, then this value must match the hash algorithm indicated by the signature mechanism
   MechanismType hash;

   // mask generation function to use on the encoded block
   MGF mgf;

   // length, in bytes, of the salt value used in the PSS encoding; typical values are the length of the message hash and zero
   size_t salt_size;
   };

// note: when updating this map, update the documentation for `MechanismWrapper::create_rsa_sign_mechanism`
static std::map<std::string, RSA_SignMechanism> SignMechanisms =
   {
      { "Raw", RSA_SignMechanism(MechanismType::RsaX509) },

      { "EMSA2(Raw)", RSA_SignMechanism(MechanismType::RsaX931) },
      { "EMSA2(SHA-1)", RSA_SignMechanism(MechanismType::Sha1RsaX931) },

      // RSASSA PKCS#1 v1.5
      { "EMSA3(Raw)", RSA_SignMechanism(MechanismType::RsaPkcs) },
      { "EMSA3(SHA-1)", RSA_SignMechanism(MechanismType::Sha1RsaPkcs) },
      { "EMSA3(SHA-224)", RSA_SignMechanism(MechanismType::Sha224RsaPkcs) },
      { "EMSA3(SHA-256)", RSA_SignMechanism(MechanismType::Sha256RsaPkcs) },
      { "EMSA3(SHA-384)", RSA_SignMechanism(MechanismType::Sha384RsaPkcs) },
      { "EMSA3(SHA-512)", RSA_SignMechanism(MechanismType::Sha512RsaPkcs) },

      { "EMSA_PKCS1(SHA-1)", RSA_SignMechanism(MechanismType::Sha1RsaPkcs) },
      { "EMSA_PKCS1(SHA-224)", RSA_SignMechanism(MechanismType::Sha224RsaPkcs) },
      { "EMSA_PKCS1(SHA-256)", RSA_SignMechanism(MechanismType::Sha256RsaPkcs) },
      { "EMSA_PKCS1(SHA-384)", RSA_SignMechanism(MechanismType::Sha384RsaPkcs) },
      { "EMSA_PKCS1(SHA-512)", RSA_SignMechanism(MechanismType::Sha512RsaPkcs) },

      // RSASSA PKCS#1 PSS
      { "EMSA4(Raw)", RSA_SignMechanism(MechanismType::RsaPkcsPss) },
      { "EMSA4(SHA-1)", RSA_SignMechanism(MechanismType::Sha1RsaPkcsPss) },
      { "EMSA4(SHA-224)", RSA_SignMechanism(MechanismType::Sha224RsaPkcsPss) },

      { "EMSA4(SHA-256)", RSA_SignMechanism(MechanismType::Sha256RsaPkcsPss) },
      { "EMSA4(SHA-256,MGF1,32)", RSA_SignMechanism(MechanismType::Sha256RsaPkcsPss) },
      { "PSSR(SHA-256,MGF1,32)", RSA_SignMechanism(MechanismType::Sha256RsaPkcsPss) },

      { "EMSA4(SHA-384)", RSA_SignMechanism(MechanismType::Sha384RsaPkcsPss) },
      { "EMSA4(SHA-384,MGF1,48)", RSA_SignMechanism(MechanismType::Sha384RsaPkcsPss) },
      { "PSSR(SHA-384,MGF1,48)", RSA_SignMechanism(MechanismType::Sha384RsaPkcsPss) },

      { "EMSA4(SHA-512)", RSA_SignMechanism(MechanismType::Sha512RsaPkcsPss) },
      { "EMSA4(SHA-512,MGF1,64)", RSA_SignMechanism(MechanismType::Sha512RsaPkcsPss) },
      { "PSSR(SHA-512,MGF1,64)", RSA_SignMechanism(MechanismType::Sha512RsaPkcsPss) },

      { "ISO9796", RSA_SignMechanism(MechanismType::Rsa9796) }
   };

struct RSA_CryptMechanism final : public MechanismData
   {
   RSA_CryptMechanism(MechanismType _type, size_t _padding_size, MechanismType _hash, MGF _mgf)
      : MechanismData(_type), hash(_hash), mgf(_mgf), padding_size(_padding_size)
      {}

   RSA_CryptMechanism(MechanismType _type, size_t _padding_size)
      : RSA_CryptMechanism(_type, _padding_size, static_cast<MechanismType>(0), static_cast<MGF>(0))
      {}

   // mechanism ID of the message digest algorithm used to calculate the digest of the encoding parameter
   MechanismType hash;

   // mask generation function to use on the encoded block
   MGF mgf;

   // number of bytes required for the padding
   size_t padding_size;
   };

// note: when updating this map, update the documentation for `MechanismWrapper::create_rsa_crypt_mechanism`
static const std::map<std::string, RSA_CryptMechanism> CryptMechanisms =
   {
      { "Raw", RSA_CryptMechanism(MechanismType::RsaX509, 0) },
      { "EME-PKCS1-v1_5", RSA_CryptMechanism(MechanismType::RsaPkcs, 11) },
      { "OAEP(SHA-1)", RSA_CryptMechanism(MechanismType::RsaPkcsOaep, 2 + 2 * 20, MechanismType::Sha1, MGF::Mgf1Sha1) },
      { "OAEP(SHA-224)", RSA_CryptMechanism(MechanismType::RsaPkcsOaep, 2 + 2 * 28, MechanismType::Sha224, MGF::Mgf1Sha224) },
      { "OAEP(SHA-256)", RSA_CryptMechanism(MechanismType::RsaPkcsOaep, 2 + 2 * 32, MechanismType::Sha256, MGF::Mgf1Sha256) },
      { "OAEP(SHA-384)", RSA_CryptMechanism(MechanismType::RsaPkcsOaep, 2 + 2 * 48, MechanismType::Sha384, MGF::Mgf1Sha384) },
      { "OAEP(SHA-512)", RSA_CryptMechanism(MechanismType::RsaPkcsOaep, 2 + 2 * 64, MechanismType::Sha512, MGF::Mgf1Sha512) }
   };

// note: when updating this map, update the documentation for `MechanismWrapper::create_ecdsa_mechanism`
static std::map<std::string, MechanismType> EcdsaHash =
   {
      { "Raw", MechanismType::Ecdsa },
      { "SHA-160", MechanismType::EcdsaSha1 },
      { "SHA-224", MechanismType::EcdsaSha224 },
      { "SHA-256", MechanismType::EcdsaSha256 },
      { "SHA-384", MechanismType::EcdsaSha384 },
      { "SHA-512", MechanismType::EcdsaSha512 }
   };

// note: when updating this map, update the documentation for `MechanismWrapper::create_ecdh_mechanism`
static std::map<std::string, KeyDerivation> EcdhHash =
   {
      { "Raw", KeyDerivation::Null },
      { "SHA-160", KeyDerivation::Sha1Kdf },
      { "SHA-224", KeyDerivation::Sha224Kdf },
      { "SHA-256", KeyDerivation::Sha256Kdf },
      { "SHA-384", KeyDerivation::Sha384Kdf },
      { "SHA-512", KeyDerivation::Sha512Kdf }
   };
}

MechanismWrapper::MechanismWrapper(MechanismType mechanism_type)
   : m_mechanism( { static_cast<CK_MECHANISM_TYPE>(mechanism_type), nullptr, 0 }), m_parameters(nullptr)
   {}

MechanismWrapper MechanismWrapper::create_rsa_crypt_mechanism(const std::string& padding)
   {
   auto mechanism_info_it = CryptMechanisms.find(padding);
   if(mechanism_info_it == CryptMechanisms.end())
      {
      // at this point it would be possible to support additional configurations that are not predefined above by parsing `padding`
      throw Lookup_Error("PKCS#11 RSA encrypt/decrypt does not support EME " + padding);
      }
   RSA_CryptMechanism mechanism_info = mechanism_info_it->second;

   MechanismWrapper mech(mechanism_info.type);
   if(mechanism_info.type == MechanismType::RsaPkcsOaep)
      {
      mech.m_parameters = std::make_shared<MechanismParameters>();
      mech.m_parameters->oaep_params.hashAlg = static_cast<CK_MECHANISM_TYPE>(mechanism_info.hash);
      mech.m_parameters->oaep_params.mgf = static_cast<CK_RSA_PKCS_MGF_TYPE>(mechanism_info.mgf);
      mech.m_parameters->oaep_params.source = CKZ_DATA_SPECIFIED;
      mech.m_parameters->oaep_params.pSourceData = nullptr;
      mech.m_parameters->oaep_params.ulSourceDataLen = 0;
      mech.m_mechanism.pParameter = mech.m_parameters.get();
      mech.m_mechanism.ulParameterLen = sizeof(RsaPkcsOaepParams);
      }
   mech.m_padding_size = mechanism_info.padding_size;
   return mech;
   }

MechanismWrapper MechanismWrapper::create_rsa_sign_mechanism(const std::string& padding)
   {
   auto mechanism_info_it = SignMechanisms.find(padding);
   if(mechanism_info_it == SignMechanisms.end())
      {
      // at this point it would be possible to support additional configurations that are not predefined above by parsing `padding`
      throw Lookup_Error("PKCS#11 RSA sign/verify does not support EMSA " + padding);
      }
   RSA_SignMechanism mechanism_info = mechanism_info_it->second;

   MechanismWrapper mech(mechanism_info.type);
   if(PssOptions.find(mechanism_info.type) != PssOptions.end())
      {
      mech.m_parameters = std::make_shared<MechanismParameters>();
      mech.m_parameters->pss_params.hashAlg = static_cast<CK_MECHANISM_TYPE>(mechanism_info.hash);
      mech.m_parameters->pss_params.mgf = static_cast<CK_RSA_PKCS_MGF_TYPE>(mechanism_info.mgf);
      mech.m_parameters->pss_params.sLen = static_cast<Ulong>(mechanism_info.salt_size);
      mech.m_mechanism.pParameter = mech.m_parameters.get();
      mech.m_mechanism.ulParameterLen = sizeof(RsaPkcsPssParams);
      }
   return mech;
   }

MechanismWrapper MechanismWrapper::create_ecdsa_mechanism(const std::string& hash)
   {
   std::string hash_name = hash;

   if(hash_name != "Raw")
      {
      hash_name = hash_for_emsa(hash);
      }

   auto mechanism_type = EcdsaHash.find(hash_name);
   if(mechanism_type == EcdsaHash.end())
      {
      throw Lookup_Error("PKCS#11 ECDSA sign/verify does not support " + hash);
      }
   return MechanismWrapper(mechanism_type->second);
   }

MechanismWrapper MechanismWrapper::create_ecdh_mechanism(const std::string& params)
   {
   std::vector<std::string> param_parts = split_on(params, ',');

   if(param_parts.empty() || param_parts.size() > 2)
      throw Invalid_Argument("PKCS #11 ECDH key derivation bad params " + params);

   const bool use_cofactor =
      (param_parts[0] == "Cofactor") ||
      (param_parts.size() == 2 && param_parts[1] == "Cofactor");

   std::string kdf_name = (param_parts[0] == "Cofactor" ? param_parts[1] : param_parts[0]);
   std::string hash = kdf_name;

   if(kdf_name != "Raw")
      {
      SCAN_Name kdf_hash(kdf_name);

      if(kdf_hash.arg_count() > 0)
         {
         hash = kdf_hash.arg(0);
         }
      }

   auto kdf = EcdhHash.find(hash);
   if(kdf == EcdhHash.end())
      {
      throw Lookup_Error("PKCS#11 ECDH key derivation does not support KDF " + kdf_name);
      }
   MechanismWrapper mech(use_cofactor ? MechanismType::Ecdh1CofactorDerive : MechanismType::Ecdh1Derive);
   mech.m_parameters = std::make_shared<MechanismParameters>();
   mech.m_parameters->ecdh_params.kdf = static_cast<CK_EC_KDF_TYPE>(kdf->second);
   mech.m_mechanism.pParameter = mech.m_parameters.get();
   mech.m_mechanism.ulParameterLen = sizeof(Ecdh1DeriveParams);
   return mech;
   }

}
}
