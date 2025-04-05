/*
* PKCS #11
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
* (C) 2025 Fabian Albert, Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_P11_H_
#define BOTAN_P11_H_

#include <botan/exceptn.h>
#include <botan/secmem.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#define CK_PTR *

#if defined(_MSC_VER)
   #define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#else
   #define CK_DECLARE_FUNCTION(returnType, name) returnType name
#endif

#if defined(_MSC_VER)
   #define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport)(*name)
#else
   #define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#endif

#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)

#ifndef NULL_PTR
   #define NULL_PTR nullptr
#endif

#if defined(_MSC_VER)
   #pragma pack(push, cryptoki, 1)
#endif

#include "pkcs11.h"

#if defined(_MSC_VER)
   #pragma pack(pop, cryptoki)
#endif

static_assert(
   CRYPTOKI_VERSION_MAJOR == 3 && CRYPTOKI_VERSION_MINOR == 2,
   "The Botan PKCS #11 module was implemented against PKCS #11 v3.2. Please use the correct PKCS #11 headers.");

namespace Botan {

class Dynamically_Loaded_Library;

namespace PKCS11 {

using secure_string = secure_vector<uint8_t>;

enum class AttributeType : CK_ATTRIBUTE_TYPE {
   Class = CKA_CLASS,
   Token = CKA_TOKEN,
   Private = CKA_PRIVATE,
   Label = CKA_LABEL,
   UniqueId = CKA_UNIQUE_ID,
   Application = CKA_APPLICATION,
   Value = CKA_VALUE,
   ObjectId = CKA_OBJECT_ID,
   CertificateType = CKA_CERTIFICATE_TYPE,
   Issuer = CKA_ISSUER,
   SerialNumber = CKA_SERIAL_NUMBER,
   AcIssuer = CKA_AC_ISSUER,
   Owner = CKA_OWNER,
   AttrTypes = CKA_ATTR_TYPES,
   Trusted = CKA_TRUSTED,
   CertificateCategory = CKA_CERTIFICATE_CATEGORY,
   JavaMidpSecurityDomain = CKA_JAVA_MIDP_SECURITY_DOMAIN,
   Url = CKA_URL,
   HashOfSubjectPublicKey = CKA_HASH_OF_SUBJECT_PUBLIC_KEY,
   HashOfIssuerPublicKey = CKA_HASH_OF_ISSUER_PUBLIC_KEY,
   NameHashAlgorithm = CKA_NAME_HASH_ALGORITHM,
   CheckValue = CKA_CHECK_VALUE,
   KeyType = CKA_KEY_TYPE,
   Subject = CKA_SUBJECT,
   Id = CKA_ID,
   Sensitive = CKA_SENSITIVE,
   Encrypt = CKA_ENCRYPT,
   Decrypt = CKA_DECRYPT,
   Wrap = CKA_WRAP,
   Unwrap = CKA_UNWRAP,
   Sign = CKA_SIGN,
   SignRecover = CKA_SIGN_RECOVER,
   Verify = CKA_VERIFY,
   VerifyRecover = CKA_VERIFY_RECOVER,
   Derive = CKA_DERIVE,
   StartDate = CKA_START_DATE,
   EndDate = CKA_END_DATE,
   Modulus = CKA_MODULUS,
   ModulusBits = CKA_MODULUS_BITS,
   PublicExponent = CKA_PUBLIC_EXPONENT,
   PrivateExponent = CKA_PRIVATE_EXPONENT,
   Prime1 = CKA_PRIME_1,
   Prime2 = CKA_PRIME_2,
   Exponent1 = CKA_EXPONENT_1,
   Exponent2 = CKA_EXPONENT_2,
   Coefficient = CKA_COEFFICIENT,
   PublicKeyInfo = CKA_PUBLIC_KEY_INFO,
   Prime = CKA_PRIME,
   Subprime = CKA_SUBPRIME,
   Base = CKA_BASE,
   PrimeBits = CKA_PRIME_BITS,
   SubprimeBits = CKA_SUBPRIME_BITS,
   SubPrimeBits = CKA_SUB_PRIME_BITS,
   ValueBits = CKA_VALUE_BITS,
   ValueLen = CKA_VALUE_LEN,
   Extractable = CKA_EXTRACTABLE,
   Local = CKA_LOCAL,
   NeverExtractable = CKA_NEVER_EXTRACTABLE,
   AlwaysSensitive = CKA_ALWAYS_SENSITIVE,
   KeyGenMechanism = CKA_KEY_GEN_MECHANISM,
   Modifiable = CKA_MODIFIABLE,
   Copyable = CKA_COPYABLE,
   Destroyable = CKA_DESTROYABLE,
   EcdsaParams = CKA_ECDSA_PARAMS,
   EcParams = CKA_EC_PARAMS,
   EcPoint = CKA_EC_POINT,
   SecondaryAuth = CKA_SECONDARY_AUTH,
   AuthPinFlags = CKA_AUTH_PIN_FLAGS,
   AlwaysAuthenticate = CKA_ALWAYS_AUTHENTICATE,
   WrapWithTrusted = CKA_WRAP_WITH_TRUSTED,
   WrapTemplate = CKA_WRAP_TEMPLATE,
   UnwrapTemplate = CKA_UNWRAP_TEMPLATE,
   DeriveTemplate = CKA_DERIVE_TEMPLATE,
   OtpFormat = CKA_OTP_FORMAT,
   OtpLength = CKA_OTP_LENGTH,
   OtpTimeInterval = CKA_OTP_TIME_INTERVAL,
   OtpUserFriendlyMode = CKA_OTP_USER_FRIENDLY_MODE,
   OtpChallengeRequirement = CKA_OTP_CHALLENGE_REQUIREMENT,
   OtpTimeRequirement = CKA_OTP_TIME_REQUIREMENT,
   OtpCounterRequirement = CKA_OTP_COUNTER_REQUIREMENT,
   OtpPinRequirement = CKA_OTP_PIN_REQUIREMENT,
   OtpCounter = CKA_OTP_COUNTER,
   OtpTime = CKA_OTP_TIME,
   OtpUserIdentifier = CKA_OTP_USER_IDENTIFIER,
   OtpServiceIdentifier = CKA_OTP_SERVICE_IDENTIFIER,
   OtpServiceLogo = CKA_OTP_SERVICE_LOGO,
   OtpServiceLogoType = CKA_OTP_SERVICE_LOGO_TYPE,
   Gostr3410Params = CKA_GOSTR3410_PARAMS,
   Gostr3411Params = CKA_GOSTR3411_PARAMS,
   Gost28147Params = CKA_GOST28147_PARAMS,
   HwFeatureType = CKA_HW_FEATURE_TYPE,
   ResetOnInit = CKA_RESET_ON_INIT,
   HasReset = CKA_HAS_RESET,
   PixelX = CKA_PIXEL_X,
   PixelY = CKA_PIXEL_Y,
   Resolution = CKA_RESOLUTION,
   CharRows = CKA_CHAR_ROWS,
   CharColumns = CKA_CHAR_COLUMNS,
   Color = CKA_COLOR,
   BitsPerPixel = CKA_BITS_PER_PIXEL,
   CharSets = CKA_CHAR_SETS,
   EncodingMethods = CKA_ENCODING_METHODS,
   MimeTypes = CKA_MIME_TYPES,
   MechanismType = CKA_MECHANISM_TYPE,
   RequiredCmsAttributes = CKA_REQUIRED_CMS_ATTRIBUTES,
   DefaultCmsAttributes = CKA_DEFAULT_CMS_ATTRIBUTES,
   SupportedCmsAttributes = CKA_SUPPORTED_CMS_ATTRIBUTES,
   AllowedMechanisms = CKA_ALLOWED_MECHANISMS,
   ProfileId = CKA_PROFILE_ID,
   X2ratchetBag = CKA_X2RATCHET_BAG,
   X2ratchetBagsize = CKA_X2RATCHET_BAGSIZE,
   X2ratchetBobs1stmsg = CKA_X2RATCHET_BOBS1STMSG,
   X2ratchetCkr = CKA_X2RATCHET_CKR,
   X2ratchetCks = CKA_X2RATCHET_CKS,
   X2ratchetDhp = CKA_X2RATCHET_DHP,
   X2ratchetDhr = CKA_X2RATCHET_DHR,
   X2ratchetDhs = CKA_X2RATCHET_DHS,
   X2ratchetHkr = CKA_X2RATCHET_HKR,
   X2ratchetHks = CKA_X2RATCHET_HKS,
   X2ratchetIsalice = CKA_X2RATCHET_ISALICE,
   X2ratchetNhkr = CKA_X2RATCHET_NHKR,
   X2ratchetNhks = CKA_X2RATCHET_NHKS,
   X2ratchetNr = CKA_X2RATCHET_NR,
   X2ratchetNs = CKA_X2RATCHET_NS,
   X2ratchetPns = CKA_X2RATCHET_PNS,
   X2ratchetRk = CKA_X2RATCHET_RK,
   HssLevels = CKA_HSS_LEVELS,
   HssLmsType = CKA_HSS_LMS_TYPE,
   HssLmotsType = CKA_HSS_LMOTS_TYPE,
   HssLmsTypes = CKA_HSS_LMS_TYPES,
   HssLmotsTypes = CKA_HSS_LMOTS_TYPES,
   HssKeysRemaining = CKA_HSS_KEYS_REMAINING,
   ParameterSet = CKA_PARAMETER_SET,
   ValidationFlags = CKA_VALIDATION_FLAGS,
   ValidationType = CKA_VALIDATION_TYPE,
   ValidationVersion = CKA_VALIDATION_VERSION,
   ValidationLevel = CKA_VALIDATION_LEVEL,
   ValidationModuleId = CKA_VALIDATION_MODULE_ID,
   ValidationFlag = CKA_VALIDATION_FLAG,
   ValidationAuthorityType = CKA_VALIDATION_AUTHORITY_TYPE,
   ValidationCountry = CKA_VALIDATION_COUNTRY,
   ValidationCertificateIdentifier = CKA_VALIDATION_CERTIFICATE_IDENTIFIER,
   ValidationCertificateUri = CKA_VALIDATION_CERTIFICATE_URI,
   ValidationVendor = CKA_VALIDATION_VENDOR,
   ValidationProfile = CKA_VALIDATION_PROFILE,
   EncapsulateTemplate = CKA_ENCAPSULATE_TEMPLATE,
   DecapsulateTemplate = CKA_DECAPSULATE_TEMPLATE,
   TrustServerAuth = CKA_TRUST_SERVER_AUTH,
   TrustClientAuth = CKA_TRUST_CLIENT_AUTH,
   TrustCodeSigning = CKA_TRUST_CODE_SIGNING,
   TrustEmailProtection = CKA_TRUST_EMAIL_PROTECTION,
   TrustIpsecIke = CKA_TRUST_IPSEC_IKE,
   TrustTimeStamping = CKA_TRUST_TIME_STAMPING,
   TrustOcspSigning = CKA_TRUST_OCSP_SIGNING,
   Encapsulate = CKA_ENCAPSULATE,
   Decapsulate = CKA_DECAPSULATE,
   HashOfCertificate = CKA_HASH_OF_CERTIFICATE,
   VendorDefined = CKA_VENDOR_DEFINED,
};

enum class CertificateType : CK_CERTIFICATE_TYPE {
   X509 = CKC_X_509,
   X509AttrCert = CKC_X_509_ATTR_CERT,
   Wtls = CKC_WTLS,
   VendorDefined = CKC_VENDOR_DEFINED,
};

/// Indicates if a stored certificate is a user certificate for which the corresponding private key is available
/// on the token ("token user"), a CA certificate ("authority"), or another end-entity certificate ("other entity").
enum class CertificateCategory : CK_ULONG {
   Unspecified = CK_CERTIFICATE_CATEGORY_UNSPECIFIED,
   TokenUser = CK_CERTIFICATE_CATEGORY_TOKEN_USER,
   Authority = CK_CERTIFICATE_CATEGORY_AUTHORITY,
   OtherEntity = CK_CERTIFICATE_CATEGORY_OTHER_ENTITY
};

enum class KeyDerivation : CK_ULONG {
   Null = CKD_NULL,
   Sha1Kdf = CKD_SHA1_KDF,
   Sha1KdfAsn1 = CKD_SHA1_KDF_ASN1,
   Sha1KdfConcatenate = CKD_SHA1_KDF_CONCATENATE,
   Sha224Kdf = CKD_SHA224_KDF,
   Sha256Kdf = CKD_SHA256_KDF,
   Sha384Kdf = CKD_SHA384_KDF,
   Sha512Kdf = CKD_SHA512_KDF,
   CpdiversifyKdf = CKD_CPDIVERSIFY_KDF,
   Sha3_224Kdf = CKD_SHA3_224_KDF,
   Sha3_256Kdf = CKD_SHA3_256_KDF,
   Sha3_384Kdf = CKD_SHA3_384_KDF,
   Sha3_512Kdf = CKD_SHA3_512_KDF,
   Sha1KdfSp800 = CKD_SHA1_KDF_SP800,
   Sha224KdfSp800 = CKD_SHA224_KDF_SP800,
   Sha256KdfSp800 = CKD_SHA256_KDF_SP800,
   Sha384KdfSp800 = CKD_SHA384_KDF_SP800,
   Sha512KdfSp800 = CKD_SHA512_KDF_SP800,
   Sha3_224KdfSp800 = CKD_SHA3_224_KDF_SP800,
   Sha3_256KdfSp800 = CKD_SHA3_256_KDF_SP800,
   Sha3_384KdfSp800 = CKD_SHA3_384_KDF_SP800,
   Sha3_512KdfSp800 = CKD_SHA3_512_KDF_SP800,
   Blake2b160Kdf = CKD_BLAKE2B_160_KDF,
   Blake2b256Kdf = CKD_BLAKE2B_256_KDF,
   Blake2b384Kdf = CKD_BLAKE2B_384_KDF,
   Blake2b512Kdf = CKD_BLAKE2B_512_KDF,
};

enum class Flag : CK_FLAGS {
   None = 0,
   TokenPresent = CKF_TOKEN_PRESENT,
   RemovableDevice = CKF_REMOVABLE_DEVICE,
   HwSlot = CKF_HW_SLOT,
   Rng = CKF_RNG,
   WriteProtected = CKF_WRITE_PROTECTED,
   LoginRequired = CKF_LOGIN_REQUIRED,
   UserPinInitialized = CKF_USER_PIN_INITIALIZED,
   RestoreKeyNotNeeded = CKF_RESTORE_KEY_NOT_NEEDED,
   ClockOnToken = CKF_CLOCK_ON_TOKEN,
   ProtectedAuthenticationPath = CKF_PROTECTED_AUTHENTICATION_PATH,
   DualCryptoOperations = CKF_DUAL_CRYPTO_OPERATIONS,
   TokenInitialized = CKF_TOKEN_INITIALIZED,
   SecondaryAuthentication = CKF_SECONDARY_AUTHENTICATION,
   UserPinCountLow = CKF_USER_PIN_COUNT_LOW,
   UserPinFinalTry = CKF_USER_PIN_FINAL_TRY,
   UserPinLocked = CKF_USER_PIN_LOCKED,
   UserPinToBeChanged = CKF_USER_PIN_TO_BE_CHANGED,
   SoPinCountLow = CKF_SO_PIN_COUNT_LOW,
   SoPinFinalTry = CKF_SO_PIN_FINAL_TRY,
   SoPinLocked = CKF_SO_PIN_LOCKED,
   SoPinToBeChanged = CKF_SO_PIN_TO_BE_CHANGED,
   ErrorState = CKF_ERROR_STATE,
   SeedRandomRequired = CKF_SEED_RANDOM_REQUIRED,
   AsyncSessionSupported = CKF_ASYNC_SESSION_SUPPORTED,
   RwSession = CKF_RW_SESSION,
   SerialSession = CKF_SERIAL_SESSION,
   AsyncSession = CKF_ASYNC_SESSION,
   ArrayAttribute = CKF_ARRAY_ATTRIBUTE,
   Hw = CKF_HW,
   MessageEncrypt = CKF_MESSAGE_ENCRYPT,
   MessageDecrypt = CKF_MESSAGE_DECRYPT,
   MessageSign = CKF_MESSAGE_SIGN,
   MessageVerify = CKF_MESSAGE_VERIFY,
   MultiMessage = CKF_MULTI_MESSAGE,
   MultiMessge = CKF_MULTI_MESSGE,
   FindObjects = CKF_FIND_OBJECTS,
   Encrypt = CKF_ENCRYPT,
   Decrypt = CKF_DECRYPT,
   Digest = CKF_DIGEST,
   Sign = CKF_SIGN,
   SignRecover = CKF_SIGN_RECOVER,
   Verify = CKF_VERIFY,
   VerifyRecover = CKF_VERIFY_RECOVER,
   Generate = CKF_GENERATE,
   GenerateKeyPair = CKF_GENERATE_KEY_PAIR,
   Wrap = CKF_WRAP,
   Unwrap = CKF_UNWRAP,
   Derive = CKF_DERIVE,
   EcFP = CKF_EC_F_P,
   EcF2m = CKF_EC_F_2M,
   EcEcparameters = CKF_EC_ECPARAMETERS,
   EcOid = CKF_EC_OID,
   EcNamedcurve = CKF_EC_NAMEDCURVE,
   EcUncompress = CKF_EC_UNCOMPRESS,
   EcCompress = CKF_EC_COMPRESS,
   EcCurvename = CKF_EC_CURVENAME,
   Encapsulate = CKF_ENCAPSULATE,
   Decapsulate = CKF_DECAPSULATE,
   Extension = CKF_EXTENSION,
   EndOfMessage = CKF_END_OF_MESSAGE,
   InterfaceForkSafe = CKF_INTERFACE_FORK_SAFE,
   LibraryCantCreateOsThreads = CKF_LIBRARY_CANT_CREATE_OS_THREADS,
   OsLockingOk = CKF_OS_LOCKING_OK,
   DontBlock = CKF_DONT_BLOCK,
   NextOtp = CKF_NEXT_OTP,
   ExcludeTime = CKF_EXCLUDE_TIME,
   ExcludeCounter = CKF_EXCLUDE_COUNTER,
   ExcludeChallenge = CKF_EXCLUDE_CHALLENGE,
   ExcludePin = CKF_EXCLUDE_PIN,
   UserFriendlyOtp = CKF_USER_FRIENDLY_OTP,
   HkdfSaltNull = CKF_HKDF_SALT_NULL,
   HkdfSaltData = CKF_HKDF_SALT_DATA,
   HkdfSaltKey = CKF_HKDF_SALT_KEY,
};

inline Flag operator|(Flag a, Flag b) {
   // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
   return static_cast<Flag>(static_cast<CK_FLAGS>(a) | static_cast<CK_FLAGS>(b));
}

enum class MGF : CK_RSA_PKCS_MGF_TYPE {
   MgfUnused = 0,
   Mgf1Sha1 = CKG_MGF1_SHA1,
   Mgf1Sha256 = CKG_MGF1_SHA256,
   Mgf1Sha384 = CKG_MGF1_SHA384,
   Mgf1Sha512 = CKG_MGF1_SHA512,
   Mgf1Sha224 = CKG_MGF1_SHA224,
   Mgf1Sha3_224 = CKG_MGF1_SHA3_224,
   Mgf1Sha3_256 = CKG_MGF1_SHA3_256,
   Mgf1Sha3_384 = CKG_MGF1_SHA3_384,
   Mgf1Sha3_512 = CKG_MGF1_SHA3_512,
};

enum class HardwareType : CK_HW_FEATURE_TYPE {
   MonotonicCounter = CKH_MONOTONIC_COUNTER,
   Clock = CKH_CLOCK,
   UserInterface = CKH_USER_INTERFACE,
   VendorDefined = CKH_VENDOR_DEFINED,
};

enum class KeyType : CK_KEY_TYPE {
   Rsa = CKK_RSA,
   Dsa = CKK_DSA,
   Dh = CKK_DH,
   Ecdsa = CKK_ECDSA,
   Ec = CKK_EC,
   X942Dh = CKK_X9_42_DH,
   Kea = CKK_KEA,
   GenericSecret = CKK_GENERIC_SECRET,
   Rc2 = CKK_RC2,
   Rc4 = CKK_RC4,
   Des = CKK_DES,
   Des2 = CKK_DES2,
   Des3 = CKK_DES3,
   Cast = CKK_CAST,
   Cast3 = CKK_CAST3,
   Cast5 = CKK_CAST5,
   Cast128 = CKK_CAST128,
   Rc5 = CKK_RC5,
   Idea = CKK_IDEA,
   Skipjack = CKK_SKIPJACK,
   Baton = CKK_BATON,
   Juniper = CKK_JUNIPER,
   Cdmf = CKK_CDMF,
   Aes = CKK_AES,
   Blowfish = CKK_BLOWFISH,
   Twofish = CKK_TWOFISH,
   Securid = CKK_SECURID,
   Hotp = CKK_HOTP,
   Acti = CKK_ACTI,
   Camellia = CKK_CAMELLIA,
   Aria = CKK_ARIA,
   Md5Hmac = CKK_MD5_HMAC,
   Sha1Hmac = CKK_SHA_1_HMAC,
   Ripemd128Hmac = CKK_RIPEMD128_HMAC,
   Ripemd160Hmac = CKK_RIPEMD160_HMAC,
   Sha256Hmac = CKK_SHA256_HMAC,
   Sha384Hmac = CKK_SHA384_HMAC,
   Sha512Hmac = CKK_SHA512_HMAC,
   Sha224Hmac = CKK_SHA224_HMAC,
   Seed = CKK_SEED,
   Gostr3410 = CKK_GOSTR3410,
   Gostr3411 = CKK_GOSTR3411,
   Gost28147 = CKK_GOST28147,
   Chacha20 = CKK_CHACHA20,
   Poly1305 = CKK_POLY1305,
   AesXts = CKK_AES_XTS,
   Sha3_224Hmac = CKK_SHA3_224_HMAC,
   Sha3_256Hmac = CKK_SHA3_256_HMAC,
   Sha3_384Hmac = CKK_SHA3_384_HMAC,
   Sha3_512Hmac = CKK_SHA3_512_HMAC,
   Blake2b160Hmac = CKK_BLAKE2B_160_HMAC,
   Blake2b256Hmac = CKK_BLAKE2B_256_HMAC,
   Blake2b384Hmac = CKK_BLAKE2B_384_HMAC,
   Blake2b512Hmac = CKK_BLAKE2B_512_HMAC,
   Salsa20 = CKK_SALSA20,
   X2ratchet = CKK_X2RATCHET,
   EcEdwards = CKK_EC_EDWARDS,
   EcMontgomery = CKK_EC_MONTGOMERY,
   Hkdf = CKK_HKDF,
   Sha512_224Hmac = CKK_SHA512_224_HMAC,
   Sha512_256Hmac = CKK_SHA512_256_HMAC,
   Sha512THmac = CKK_SHA512_T_HMAC,
   Hss = CKK_HSS,
   Xmss = CKK_XMSS,
   Xmssmt = CKK_XMSSMT,
   MlKem = CKK_ML_KEM,
   MlDsa = CKK_ML_DSA,
   SlhDsa = CKK_SLH_DSA,
   VendorDefined = CKK_VENDOR_DEFINED,
};

enum class MechanismType : CK_MECHANISM_TYPE {
   RsaPkcsKeyPairGen = CKM_RSA_PKCS_KEY_PAIR_GEN,
   RsaPkcs = CKM_RSA_PKCS,
   Rsa9796 = CKM_RSA_9796,
   RsaX509 = CKM_RSA_X_509,
   Md2RsaPkcs = CKM_MD2_RSA_PKCS,
   Md5RsaPkcs = CKM_MD5_RSA_PKCS,
   Sha1RsaPkcs = CKM_SHA1_RSA_PKCS,
   Ripemd128RsaPkcs = CKM_RIPEMD128_RSA_PKCS,
   Ripemd160RsaPkcs = CKM_RIPEMD160_RSA_PKCS,
   RsaPkcsOaep = CKM_RSA_PKCS_OAEP,
   RsaX931KeyPairGen = CKM_RSA_X9_31_KEY_PAIR_GEN,
   RsaX931 = CKM_RSA_X9_31,
   Sha1RsaX931 = CKM_SHA1_RSA_X9_31,
   RsaPkcsPss = CKM_RSA_PKCS_PSS,
   Sha1RsaPkcsPss = CKM_SHA1_RSA_PKCS_PSS,
   DsaKeyPairGen = CKM_DSA_KEY_PAIR_GEN,
   Dsa = CKM_DSA,
   DsaSha1 = CKM_DSA_SHA1,
   DsaSha224 = CKM_DSA_SHA224,
   DsaSha256 = CKM_DSA_SHA256,
   DsaSha384 = CKM_DSA_SHA384,
   DsaSha512 = CKM_DSA_SHA512,
   DsaSha3_224 = CKM_DSA_SHA3_224,
   DsaSha3_256 = CKM_DSA_SHA3_256,
   DsaSha3_384 = CKM_DSA_SHA3_384,
   DsaSha3_512 = CKM_DSA_SHA3_512,
   DhPkcsKeyPairGen = CKM_DH_PKCS_KEY_PAIR_GEN,
   DhPkcsDerive = CKM_DH_PKCS_DERIVE,
   X942DhKeyPairGen = CKM_X9_42_DH_KEY_PAIR_GEN,
   X942DhDerive = CKM_X9_42_DH_DERIVE,
   X942DhHybridDerive = CKM_X9_42_DH_HYBRID_DERIVE,
   X942MqvDerive = CKM_X9_42_MQV_DERIVE,
   Sha256RsaPkcs = CKM_SHA256_RSA_PKCS,
   Sha384RsaPkcs = CKM_SHA384_RSA_PKCS,
   Sha512RsaPkcs = CKM_SHA512_RSA_PKCS,
   Sha256RsaPkcsPss = CKM_SHA256_RSA_PKCS_PSS,
   Sha384RsaPkcsPss = CKM_SHA384_RSA_PKCS_PSS,
   Sha512RsaPkcsPss = CKM_SHA512_RSA_PKCS_PSS,
   Sha224RsaPkcs = CKM_SHA224_RSA_PKCS,
   Sha224RsaPkcsPss = CKM_SHA224_RSA_PKCS_PSS,
   Sha512224 = CKM_SHA512_224,
   Sha512224Hmac = CKM_SHA512_224_HMAC,
   Sha512224HmacGeneral = CKM_SHA512_224_HMAC_GENERAL,
   Sha512224KeyDerivation = CKM_SHA512_224_KEY_DERIVATION,
   Sha512256 = CKM_SHA512_256,
   Sha512256Hmac = CKM_SHA512_256_HMAC,
   Sha512256HmacGeneral = CKM_SHA512_256_HMAC_GENERAL,
   Sha512256KeyDerivation = CKM_SHA512_256_KEY_DERIVATION,
   Sha512T = CKM_SHA512_T,
   Sha512THmac = CKM_SHA512_T_HMAC,
   Sha512THmacGeneral = CKM_SHA512_T_HMAC_GENERAL,
   Sha512TKeyDerivation = CKM_SHA512_T_KEY_DERIVATION,
   Sha3_256RsaPkcs = CKM_SHA3_256_RSA_PKCS,
   Sha3_384RsaPkcs = CKM_SHA3_384_RSA_PKCS,
   Sha3_512RsaPkcs = CKM_SHA3_512_RSA_PKCS,
   Sha3_256RsaPkcsPss = CKM_SHA3_256_RSA_PKCS_PSS,
   Sha3_384RsaPkcsPss = CKM_SHA3_384_RSA_PKCS_PSS,
   Sha3_512RsaPkcsPss = CKM_SHA3_512_RSA_PKCS_PSS,
   Sha3_224RsaPkcs = CKM_SHA3_224_RSA_PKCS,
   Sha3_224RsaPkcsPss = CKM_SHA3_224_RSA_PKCS_PSS,
   Rc2KeyGen = CKM_RC2_KEY_GEN,
   Rc2Ecb = CKM_RC2_ECB,
   Rc2Cbc = CKM_RC2_CBC,
   Rc2Mac = CKM_RC2_MAC,
   Rc2MacGeneral = CKM_RC2_MAC_GENERAL,
   Rc2CbcPad = CKM_RC2_CBC_PAD,
   Rc4KeyGen = CKM_RC4_KEY_GEN,
   Rc4 = CKM_RC4,
   DesKeyGen = CKM_DES_KEY_GEN,
   DesEcb = CKM_DES_ECB,
   DesCbc = CKM_DES_CBC,
   DesMac = CKM_DES_MAC,
   DesMacGeneral = CKM_DES_MAC_GENERAL,
   DesCbcPad = CKM_DES_CBC_PAD,
   Des2KeyGen = CKM_DES2_KEY_GEN,
   Des3KeyGen = CKM_DES3_KEY_GEN,
   Des3Ecb = CKM_DES3_ECB,
   Des3Cbc = CKM_DES3_CBC,
   Des3Mac = CKM_DES3_MAC,
   Des3MacGeneral = CKM_DES3_MAC_GENERAL,
   Des3CbcPad = CKM_DES3_CBC_PAD,
   Des3CmacGeneral = CKM_DES3_CMAC_GENERAL,
   Des3Cmac = CKM_DES3_CMAC,
   CdmfKeyGen = CKM_CDMF_KEY_GEN,
   CdmfEcb = CKM_CDMF_ECB,
   CdmfCbc = CKM_CDMF_CBC,
   CdmfMac = CKM_CDMF_MAC,
   CdmfMacGeneral = CKM_CDMF_MAC_GENERAL,
   CdmfCbcPad = CKM_CDMF_CBC_PAD,
   DesOfb64 = CKM_DES_OFB64,
   DesOfb8 = CKM_DES_OFB8,
   DesCfb64 = CKM_DES_CFB64,
   DesCfb8 = CKM_DES_CFB8,
   Md2 = CKM_MD2,
   Md2Hmac = CKM_MD2_HMAC,
   Md2HmacGeneral = CKM_MD2_HMAC_GENERAL,
   Md5 = CKM_MD5,
   Md5Hmac = CKM_MD5_HMAC,
   Md5HmacGeneral = CKM_MD5_HMAC_GENERAL,
   Sha1 = CKM_SHA_1,
   Sha1Hmac = CKM_SHA_1_HMAC,
   Sha1HmacGeneral = CKM_SHA_1_HMAC_GENERAL,
   Ripemd128 = CKM_RIPEMD128,
   Ripemd128Hmac = CKM_RIPEMD128_HMAC,
   Ripemd128HmacGeneral = CKM_RIPEMD128_HMAC_GENERAL,
   Ripemd160 = CKM_RIPEMD160,
   Ripemd160Hmac = CKM_RIPEMD160_HMAC,
   Ripemd160HmacGeneral = CKM_RIPEMD160_HMAC_GENERAL,
   Sha256 = CKM_SHA256,
   Sha256Hmac = CKM_SHA256_HMAC,
   Sha256HmacGeneral = CKM_SHA256_HMAC_GENERAL,
   Sha224 = CKM_SHA224,
   Sha224Hmac = CKM_SHA224_HMAC,
   Sha224HmacGeneral = CKM_SHA224_HMAC_GENERAL,
   Sha384 = CKM_SHA384,
   Sha384Hmac = CKM_SHA384_HMAC,
   Sha384HmacGeneral = CKM_SHA384_HMAC_GENERAL,
   Sha512 = CKM_SHA512,
   Sha512Hmac = CKM_SHA512_HMAC,
   Sha512HmacGeneral = CKM_SHA512_HMAC_GENERAL,
   SecuridKeyGen = CKM_SECURID_KEY_GEN,
   Securid = CKM_SECURID,
   HotpKeyGen = CKM_HOTP_KEY_GEN,
   Hotp = CKM_HOTP,
   Acti = CKM_ACTI,
   ActiKeyGen = CKM_ACTI_KEY_GEN,
   Sha3_256 = CKM_SHA3_256,
   Sha3_256Hmac = CKM_SHA3_256_HMAC,
   Sha3_256HmacGeneral = CKM_SHA3_256_HMAC_GENERAL,
   Sha3_256KeyGen = CKM_SHA3_256_KEY_GEN,
   Sha3_224 = CKM_SHA3_224,
   Sha3_224Hmac = CKM_SHA3_224_HMAC,
   Sha3_224HmacGeneral = CKM_SHA3_224_HMAC_GENERAL,
   Sha3_224KeyGen = CKM_SHA3_224_KEY_GEN,
   Sha3_384 = CKM_SHA3_384,
   Sha3_384Hmac = CKM_SHA3_384_HMAC,
   Sha3_384HmacGeneral = CKM_SHA3_384_HMAC_GENERAL,
   Sha3_384KeyGen = CKM_SHA3_384_KEY_GEN,
   Sha3_512 = CKM_SHA3_512,
   Sha3_512Hmac = CKM_SHA3_512_HMAC,
   Sha3_512HmacGeneral = CKM_SHA3_512_HMAC_GENERAL,
   Sha3_512KeyGen = CKM_SHA3_512_KEY_GEN,
   CastKeyGen = CKM_CAST_KEY_GEN,
   CastEcb = CKM_CAST_ECB,
   CastCbc = CKM_CAST_CBC,
   CastMac = CKM_CAST_MAC,
   CastMacGeneral = CKM_CAST_MAC_GENERAL,
   CastCbcPad = CKM_CAST_CBC_PAD,
   Cast3KeyGen = CKM_CAST3_KEY_GEN,
   Cast3Ecb = CKM_CAST3_ECB,
   Cast3Cbc = CKM_CAST3_CBC,
   Cast3Mac = CKM_CAST3_MAC,
   Cast3MacGeneral = CKM_CAST3_MAC_GENERAL,
   Cast3CbcPad = CKM_CAST3_CBC_PAD,
   Cast5KeyGen = CKM_CAST5_KEY_GEN,
   Cast128KeyGen = CKM_CAST128_KEY_GEN,
   Cast5Ecb = CKM_CAST5_ECB,
   Cast128Ecb = CKM_CAST128_ECB,
   Cast5Cbc = CKM_CAST5_CBC,
   Cast128Cbc = CKM_CAST128_CBC,
   Cast5Mac = CKM_CAST5_MAC,
   Cast128Mac = CKM_CAST128_MAC,
   Cast5MacGeneral = CKM_CAST5_MAC_GENERAL,
   Cast128MacGeneral = CKM_CAST128_MAC_GENERAL,
   Cast5CbcPad = CKM_CAST5_CBC_PAD,
   Cast128CbcPad = CKM_CAST128_CBC_PAD,
   Rc5KeyGen = CKM_RC5_KEY_GEN,
   Rc5Ecb = CKM_RC5_ECB,
   Rc5Cbc = CKM_RC5_CBC,
   Rc5Mac = CKM_RC5_MAC,
   Rc5MacGeneral = CKM_RC5_MAC_GENERAL,
   Rc5CbcPad = CKM_RC5_CBC_PAD,
   IdeaKeyGen = CKM_IDEA_KEY_GEN,
   IdeaEcb = CKM_IDEA_ECB,
   IdeaCbc = CKM_IDEA_CBC,
   IdeaMac = CKM_IDEA_MAC,
   IdeaMacGeneral = CKM_IDEA_MAC_GENERAL,
   IdeaCbcPad = CKM_IDEA_CBC_PAD,
   GenericSecretKeyGen = CKM_GENERIC_SECRET_KEY_GEN,
   ConcatenateBaseAndKey = CKM_CONCATENATE_BASE_AND_KEY,
   ConcatenateBaseAndData = CKM_CONCATENATE_BASE_AND_DATA,
   ConcatenateDataAndBase = CKM_CONCATENATE_DATA_AND_BASE,
   XorBaseAndData = CKM_XOR_BASE_AND_DATA,
   ExtractKeyFromKey = CKM_EXTRACT_KEY_FROM_KEY,
   Ssl3PreMasterKeyGen = CKM_SSL3_PRE_MASTER_KEY_GEN,
   Ssl3MasterKeyDerive = CKM_SSL3_MASTER_KEY_DERIVE,
   Ssl3KeyAndMacDerive = CKM_SSL3_KEY_AND_MAC_DERIVE,
   Ssl3MasterKeyDeriveDh = CKM_SSL3_MASTER_KEY_DERIVE_DH,
   TlsPreMasterKeyGen = CKM_TLS_PRE_MASTER_KEY_GEN,
   TlsMasterKeyDerive = CKM_TLS_MASTER_KEY_DERIVE,
   TlsKeyAndMacDerive = CKM_TLS_KEY_AND_MAC_DERIVE,
   TlsMasterKeyDeriveDh = CKM_TLS_MASTER_KEY_DERIVE_DH,
   TlsPrf = CKM_TLS_PRF,
   Ssl3Md5Mac = CKM_SSL3_MD5_MAC,
   Ssl3Sha1Mac = CKM_SSL3_SHA1_MAC,
   Md5KeyDerivation = CKM_MD5_KEY_DERIVATION,
   Md2KeyDerivation = CKM_MD2_KEY_DERIVATION,
   Sha1KeyDerivation = CKM_SHA1_KEY_DERIVATION,
   Sha256KeyDerivation = CKM_SHA256_KEY_DERIVATION,
   Sha384KeyDerivation = CKM_SHA384_KEY_DERIVATION,
   Sha512KeyDerivation = CKM_SHA512_KEY_DERIVATION,
   Sha224KeyDerivation = CKM_SHA224_KEY_DERIVATION,
   Sha3_256KeyDerivation = CKM_SHA3_256_KEY_DERIVATION,
   Sha3_224KeyDerivation = CKM_SHA3_224_KEY_DERIVATION,
   Sha3_384KeyDerivation = CKM_SHA3_384_KEY_DERIVATION,
   Sha3_512KeyDerivation = CKM_SHA3_512_KEY_DERIVATION,
   Shake128KeyDerivation = CKM_SHAKE_128_KEY_DERIVATION,
   Shake256KeyDerivation = CKM_SHAKE_256_KEY_DERIVATION,
   PbeMd2DesCbc = CKM_PBE_MD2_DES_CBC,
   PbeMd5DesCbc = CKM_PBE_MD5_DES_CBC,
   PbeMd5CastCbc = CKM_PBE_MD5_CAST_CBC,
   PbeMd5Cast3Cbc = CKM_PBE_MD5_CAST3_CBC,
   PbeMd5Cast5Cbc = CKM_PBE_MD5_CAST5_CBC,
   PbeMd5Cast128Cbc = CKM_PBE_MD5_CAST128_CBC,
   PbeSha1Cast5Cbc = CKM_PBE_SHA1_CAST5_CBC,
   PbeSha1Cast128Cbc = CKM_PBE_SHA1_CAST128_CBC,
   PbeSha1Rc4128 = CKM_PBE_SHA1_RC4_128,
   PbeSha1Rc440 = CKM_PBE_SHA1_RC4_40,
   PbeSha1Des3EdeCbc = CKM_PBE_SHA1_DES3_EDE_CBC,
   PbeSha1Des2EdeCbc = CKM_PBE_SHA1_DES2_EDE_CBC,
   PbeSha1Rc2128Cbc = CKM_PBE_SHA1_RC2_128_CBC,
   PbeSha1Rc240Cbc = CKM_PBE_SHA1_RC2_40_CBC,
   Pkcs5Pbkd2 = CKM_PKCS5_PBKD2,
   PbaSha1WithSha1Hmac = CKM_PBA_SHA1_WITH_SHA1_HMAC,
   WtlsPreMasterKeyGen = CKM_WTLS_PRE_MASTER_KEY_GEN,
   WtlsMasterKeyDerive = CKM_WTLS_MASTER_KEY_DERIVE,
   WtlsMasterKeyDeriveDhEcc = CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
   WtlsPrf = CKM_WTLS_PRF,
   WtlsServerKeyAndMacDerive = CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
   WtlsClientKeyAndMacDerive = CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
   Tls10MacServer = CKM_TLS10_MAC_SERVER,
   Tls10MacClient = CKM_TLS10_MAC_CLIENT,
   Tls12Mac = CKM_TLS12_MAC,
   Tls12Kdf = CKM_TLS12_KDF,
   Tls12MasterKeyDerive = CKM_TLS12_MASTER_KEY_DERIVE,
   Tls12KeyAndMacDerive = CKM_TLS12_KEY_AND_MAC_DERIVE,
   Tls12MasterKeyDeriveDh = CKM_TLS12_MASTER_KEY_DERIVE_DH,
   Tls12KeySafeDerive = CKM_TLS12_KEY_SAFE_DERIVE,
   TlsMac = CKM_TLS_MAC,
   TlsKdf = CKM_TLS_KDF,
   KeyWrapLynks = CKM_KEY_WRAP_LYNKS,
   KeyWrapSetOaep = CKM_KEY_WRAP_SET_OAEP,
   CmsSig = CKM_CMS_SIG,
   KipDerive = CKM_KIP_DERIVE,
   KipWrap = CKM_KIP_WRAP,
   KipMac = CKM_KIP_MAC,
   CamelliaKeyGen = CKM_CAMELLIA_KEY_GEN,
   CamelliaEcb = CKM_CAMELLIA_ECB,
   CamelliaCbc = CKM_CAMELLIA_CBC,
   CamelliaMac = CKM_CAMELLIA_MAC,
   CamelliaMacGeneral = CKM_CAMELLIA_MAC_GENERAL,
   CamelliaCbcPad = CKM_CAMELLIA_CBC_PAD,
   CamelliaEcbEncryptData = CKM_CAMELLIA_ECB_ENCRYPT_DATA,
   CamelliaCbcEncryptData = CKM_CAMELLIA_CBC_ENCRYPT_DATA,
   CamelliaCtr = CKM_CAMELLIA_CTR,
   AriaKeyGen = CKM_ARIA_KEY_GEN,
   AriaEcb = CKM_ARIA_ECB,
   AriaCbc = CKM_ARIA_CBC,
   AriaMac = CKM_ARIA_MAC,
   AriaMacGeneral = CKM_ARIA_MAC_GENERAL,
   AriaCbcPad = CKM_ARIA_CBC_PAD,
   AriaEcbEncryptData = CKM_ARIA_ECB_ENCRYPT_DATA,
   AriaCbcEncryptData = CKM_ARIA_CBC_ENCRYPT_DATA,
   SeedKeyGen = CKM_SEED_KEY_GEN,
   SeedEcb = CKM_SEED_ECB,
   SeedCbc = CKM_SEED_CBC,
   SeedMac = CKM_SEED_MAC,
   SeedMacGeneral = CKM_SEED_MAC_GENERAL,
   SeedCbcPad = CKM_SEED_CBC_PAD,
   SeedEcbEncryptData = CKM_SEED_ECB_ENCRYPT_DATA,
   SeedCbcEncryptData = CKM_SEED_CBC_ENCRYPT_DATA,
   SkipjackKeyGen = CKM_SKIPJACK_KEY_GEN,
   SkipjackEcb64 = CKM_SKIPJACK_ECB64,
   SkipjackCbc64 = CKM_SKIPJACK_CBC64,
   SkipjackOfb64 = CKM_SKIPJACK_OFB64,
   SkipjackCfb64 = CKM_SKIPJACK_CFB64,
   SkipjackCfb32 = CKM_SKIPJACK_CFB32,
   SkipjackCfb16 = CKM_SKIPJACK_CFB16,
   SkipjackCfb8 = CKM_SKIPJACK_CFB8,
   SkipjackWrap = CKM_SKIPJACK_WRAP,
   SkipjackPrivateWrap = CKM_SKIPJACK_PRIVATE_WRAP,
   SkipjackRelayx = CKM_SKIPJACK_RELAYX,
   KeaKeyPairGen = CKM_KEA_KEY_PAIR_GEN,
   KeaKeyDerive = CKM_KEA_KEY_DERIVE,
   KeaDerive = CKM_KEA_DERIVE,
   FortezzaTimestamp = CKM_FORTEZZA_TIMESTAMP,
   BatonKeyGen = CKM_BATON_KEY_GEN,
   BatonEcb128 = CKM_BATON_ECB128,
   BatonEcb96 = CKM_BATON_ECB96,
   BatonCbc128 = CKM_BATON_CBC128,
   BatonCounter = CKM_BATON_COUNTER,
   BatonShuffle = CKM_BATON_SHUFFLE,
   BatonWrap = CKM_BATON_WRAP,
   EcdsaKeyPairGen = CKM_ECDSA_KEY_PAIR_GEN,
   EcKeyPairGen = CKM_EC_KEY_PAIR_GEN,
   Ecdsa = CKM_ECDSA,
   EcdsaSha1 = CKM_ECDSA_SHA1,
   EcdsaSha224 = CKM_ECDSA_SHA224,
   EcdsaSha256 = CKM_ECDSA_SHA256,
   EcdsaSha384 = CKM_ECDSA_SHA384,
   EcdsaSha512 = CKM_ECDSA_SHA512,
   EcKeyPairGenWExtraBits = CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS,
   Ecdh1Derive = CKM_ECDH1_DERIVE,
   Ecdh1CofactorDerive = CKM_ECDH1_COFACTOR_DERIVE,
   EcmqvDerive = CKM_ECMQV_DERIVE,
   EcdhAesKeyWrap = CKM_ECDH_AES_KEY_WRAP,
   RsaAesKeyWrap = CKM_RSA_AES_KEY_WRAP,
   JuniperKeyGen = CKM_JUNIPER_KEY_GEN,
   JuniperEcb128 = CKM_JUNIPER_ECB128,
   JuniperCbc128 = CKM_JUNIPER_CBC128,
   JuniperCounter = CKM_JUNIPER_COUNTER,
   JuniperShuffle = CKM_JUNIPER_SHUFFLE,
   JuniperWrap = CKM_JUNIPER_WRAP,
   Fasthash = CKM_FASTHASH,
   AesXts = CKM_AES_XTS,
   AesXtsKeyGen = CKM_AES_XTS_KEY_GEN,
   AesKeyGen = CKM_AES_KEY_GEN,
   AesEcb = CKM_AES_ECB,
   AesCbc = CKM_AES_CBC,
   AesMac = CKM_AES_MAC,
   AesMacGeneral = CKM_AES_MAC_GENERAL,
   AesCbcPad = CKM_AES_CBC_PAD,
   AesCtr = CKM_AES_CTR,
   AesGcm = CKM_AES_GCM,
   AesCcm = CKM_AES_CCM,
   AesCts = CKM_AES_CTS,
   AesCmac = CKM_AES_CMAC,
   AesCmacGeneral = CKM_AES_CMAC_GENERAL,
   AesXcbcMac = CKM_AES_XCBC_MAC,
   AesXcbcMac96 = CKM_AES_XCBC_MAC_96,
   AesGmac = CKM_AES_GMAC,
   BlowfishKeyGen = CKM_BLOWFISH_KEY_GEN,
   BlowfishCbc = CKM_BLOWFISH_CBC,
   TwofishKeyGen = CKM_TWOFISH_KEY_GEN,
   TwofishCbc = CKM_TWOFISH_CBC,
   BlowfishCbcPad = CKM_BLOWFISH_CBC_PAD,
   TwofishCbcPad = CKM_TWOFISH_CBC_PAD,
   DesEcbEncryptData = CKM_DES_ECB_ENCRYPT_DATA,
   DesCbcEncryptData = CKM_DES_CBC_ENCRYPT_DATA,
   Des3EcbEncryptData = CKM_DES3_ECB_ENCRYPT_DATA,
   Des3CbcEncryptData = CKM_DES3_CBC_ENCRYPT_DATA,
   AesEcbEncryptData = CKM_AES_ECB_ENCRYPT_DATA,
   AesCbcEncryptData = CKM_AES_CBC_ENCRYPT_DATA,
   Gostr3410KeyPairGen = CKM_GOSTR3410_KEY_PAIR_GEN,
   Gostr3410 = CKM_GOSTR3410,
   Gostr3410WithGostr3411 = CKM_GOSTR3410_WITH_GOSTR3411,
   Gostr3410KeyWrap = CKM_GOSTR3410_KEY_WRAP,
   Gostr3410Derive = CKM_GOSTR3410_DERIVE,
   Gostr3411 = CKM_GOSTR3411,
   Gostr3411Hmac = CKM_GOSTR3411_HMAC,
   Gost28147KeyGen = CKM_GOST28147_KEY_GEN,
   Gost28147Ecb = CKM_GOST28147_ECB,
   Gost28147 = CKM_GOST28147,
   Gost28147Mac = CKM_GOST28147_MAC,
   Gost28147KeyWrap = CKM_GOST28147_KEY_WRAP,
   Chacha20KeyGen = CKM_CHACHA20_KEY_GEN,
   Chacha20 = CKM_CHACHA20,
   Poly1305KeyGen = CKM_POLY1305_KEY_GEN,
   Poly1305 = CKM_POLY1305,
   DsaParameterGen = CKM_DSA_PARAMETER_GEN,
   DhPkcsParameterGen = CKM_DH_PKCS_PARAMETER_GEN,
   X942DhParameterGen = CKM_X9_42_DH_PARAMETER_GEN,
   DsaProbablisticParameterGen = CKM_DSA_PROBABILISTIC_PARAMETER_GEN,
   DsaShaweTaylorParameterGen = CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN,
   DsaFipsGGen = CKM_DSA_FIPS_G_GEN,
   AesOfb = CKM_AES_OFB,
   AesCfb64 = CKM_AES_CFB64,
   AesCfb8 = CKM_AES_CFB8,
   AesCfb128 = CKM_AES_CFB128,
   AesCfb1 = CKM_AES_CFB1,
   AesKeyWrap = CKM_AES_KEY_WRAP,
   AesKeyWrapPad = CKM_AES_KEY_WRAP_PAD,
   AesKeyWrapKwp = CKM_AES_KEY_WRAP_KWP,
   AesKeyWrapPkcs7 = CKM_AES_KEY_WRAP_PKCS7,
   RsaPkcsTpm11 = CKM_RSA_PKCS_TPM_1_1,
   RsaPkcsOaepTpm11 = CKM_RSA_PKCS_OAEP_TPM_1_1,
   Sha1KeyGen = CKM_SHA_1_KEY_GEN,
   Sha224KeyGen = CKM_SHA224_KEY_GEN,
   Sha256KeyGen = CKM_SHA256_KEY_GEN,
   Sha384KeyGen = CKM_SHA384_KEY_GEN,
   Sha512KeyGen = CKM_SHA512_KEY_GEN,
   Sha512_224KeyGen = CKM_SHA512_224_KEY_GEN,
   Sha512_256KeyGen = CKM_SHA512_256_KEY_GEN,
   Sha512TKeyGen = CKM_SHA512_T_KEY_GEN,
   Null = CKM_NULL,
   Blake2b160 = CKM_BLAKE2B_160,
   Blake2b160Hmac = CKM_BLAKE2B_160_HMAC,
   Blake2b160HmacGeneral = CKM_BLAKE2B_160_HMAC_GENERAL,
   Blake2b160KeyDerive = CKM_BLAKE2B_160_KEY_DERIVE,
   Blake2b160KeyGen = CKM_BLAKE2B_160_KEY_GEN,
   Blake2b256 = CKM_BLAKE2B_256,
   Blake2b256Hmac = CKM_BLAKE2B_256_HMAC,
   Blake2b256HmacGeneral = CKM_BLAKE2B_256_HMAC_GENERAL,
   Blake2b256KeyDerive = CKM_BLAKE2B_256_KEY_DERIVE,
   Blake2b256KeyGen = CKM_BLAKE2B_256_KEY_GEN,
   Blake2b384 = CKM_BLAKE2B_384,
   Blake2b384Hmac = CKM_BLAKE2B_384_HMAC,
   Blake2b384HmacGeneral = CKM_BLAKE2B_384_HMAC_GENERAL,
   Blake2b384KeyDerive = CKM_BLAKE2B_384_KEY_DERIVE,
   Blake2b384KeyGen = CKM_BLAKE2B_384_KEY_GEN,
   Blake2b512 = CKM_BLAKE2B_512,
   Blake2b512Hmac = CKM_BLAKE2B_512_HMAC,
   Blake2b512HmacGeneral = CKM_BLAKE2B_512_HMAC_GENERAL,
   Blake2b512KeyDerive = CKM_BLAKE2B_512_KEY_DERIVE,
   Blake2b512KeyGen = CKM_BLAKE2B_512_KEY_GEN,
   Salsa20 = CKM_SALSA20,
   Chacha20Poly1305 = CKM_CHACHA20_POLY1305,
   Salsa20Poly1305 = CKM_SALSA20_POLY1305,
   X3dhInitialize = CKM_X3DH_INITIALIZE,
   X3dhRespond = CKM_X3DH_RESPOND,
   X2ratchetInitialize = CKM_X2RATCHET_INITIALIZE,
   X2ratchetRespond = CKM_X2RATCHET_RESPOND,
   X2ratchetEncrypt = CKM_X2RATCHET_ENCRYPT,
   X2ratchetDecrypt = CKM_X2RATCHET_DECRYPT,
   Xeddsa = CKM_XEDDSA,
   HkdfDerive = CKM_HKDF_DERIVE,
   HkdfData = CKM_HKDF_DATA,
   HkdfKeyGen = CKM_HKDF_KEY_GEN,
   Salsa20_KeyGen = CKM_SALSA20_KEY_GEN,
   EcdsaSha3_224 = CKM_ECDSA_SHA3_224,
   EcdsaSha3_256 = CKM_ECDSA_SHA3_256,
   EcdsaSha3_384 = CKM_ECDSA_SHA3_384,
   EcdsaSha3_512 = CKM_ECDSA_SHA3_512,
   EcEdwardsKeyPairGen = CKM_EC_EDWARDS_KEY_PAIR_GEN,
   EcMontgomeryKeyPairGen = CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
   Eddsa = CKM_EDDSA,
   Sp800_108CounterKdf = CKM_SP800_108_COUNTER_KDF,
   Sp800_108FeedbackKdf = CKM_SP800_108_FEEDBACK_KDF,
   Sp800_108DoublePipelineKdf = CKM_SP800_108_DOUBLE_PIPELINE_KDF,
   Ike2PrfPlusDerive = CKM_IKE2_PRF_PLUS_DERIVE,
   IkePrfDerive = CKM_IKE_PRF_DERIVE,
   Ike1PrfDerive = CKM_IKE1_PRF_DERIVE,
   Ike1ExtendedDerive = CKM_IKE1_EXTENDED_DERIVE,
   HssKeyPairGen = CKM_HSS_KEY_PAIR_GEN,
   Hss = CKM_HSS,
   XmssKeyPairGen = CKM_XMSS_KEY_PAIR_GEN,
   XmssmtKeyPairGen = CKM_XMSSMT_KEY_PAIR_GEN,
   Xmss = CKM_XMSS,
   Xmssmt = CKM_XMSSMT,
   EcdhXAesKeyWrap = CKM_ECDH_X_AES_KEY_WRAP,
   EcdhCofAesKeyWrap = CKM_ECDH_COF_AES_KEY_WRAP,
   PubKeyFromPrivKey = CKM_PUB_KEY_FROM_PRIV_KEY,
   MlKemKeyPairGen = CKM_ML_KEM_KEY_PAIR_GEN,
   MlKem = CKM_ML_KEM,
   MlDsaKeyPairGen = CKM_ML_DSA_KEY_PAIR_GEN,
   MlDsa = CKM_ML_DSA,
   HashMlDsa = CKM_HASH_ML_DSA,
   HashMlDsaSha224 = CKM_HASH_ML_DSA_SHA224,
   HashMlDsaSha256 = CKM_HASH_ML_DSA_SHA256,
   HashMlDsaSha384 = CKM_HASH_ML_DSA_SHA384,
   HashMlDsaSha512 = CKM_HASH_ML_DSA_SHA512,
   HashMlDsaSha3_224 = CKM_HASH_ML_DSA_SHA3_224,
   HashMlDsaSha3_256 = CKM_HASH_ML_DSA_SHA3_256,
   HashMlDsaSha3_384 = CKM_HASH_ML_DSA_SHA3_384,
   HashMlDsaSha3_512 = CKM_HASH_ML_DSA_SHA3_512,
   HashMlDsaShake128 = CKM_HASH_ML_DSA_SHAKE128,
   HashMlDsaShake256 = CKM_HASH_ML_DSA_SHAKE256,
   SlhDsaKeyPairGen = CKM_SLH_DSA_KEY_PAIR_GEN,
   SlhDsa = CKM_SLH_DSA,
   HashSlhDsa = CKM_HASH_SLH_DSA,
   HashSlhDsaSha224 = CKM_HASH_SLH_DSA_SHA224,
   HashSlhDsaSha256 = CKM_HASH_SLH_DSA_SHA256,
   HashSlhDsaSha384 = CKM_HASH_SLH_DSA_SHA384,
   HashSlhDsaSha512 = CKM_HASH_SLH_DSA_SHA512,
   HashSlhDsaSha3_224 = CKM_HASH_SLH_DSA_SHA3_224,
   HashSlhDsaSha3_256 = CKM_HASH_SLH_DSA_SHA3_256,
   HashSlhDsaSha3_384 = CKM_HASH_SLH_DSA_SHA3_384,
   HashSlhDsaSha3_512 = CKM_HASH_SLH_DSA_SHA3_512,
   HashSlhDsaShake128 = CKM_HASH_SLH_DSA_SHAKE128,
   HashSlhDsaShake256 = CKM_HASH_SLH_DSA_SHAKE256,
   Tls12ExtendedMasterKeyDerive = CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
   Tls12ExtendedMasterKeyDeriveDh = CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH,
   VendorDefined = CKM_VENDOR_DEFINED,
};

enum class Notification : CK_NOTIFICATION {
   Surrender = CKN_SURRENDER,
   OtpChanged = CKN_OTP_CHANGED,
};

enum class ObjectClass : CK_OBJECT_CLASS {
   Data = CKO_DATA,
   Certificate = CKO_CERTIFICATE,
   PublicKey = CKO_PUBLIC_KEY,
   PrivateKey = CKO_PRIVATE_KEY,
   SecretKey = CKO_SECRET_KEY,
   HwFeature = CKO_HW_FEATURE,
   DomainParameters = CKO_DOMAIN_PARAMETERS,
   Mechanism = CKO_MECHANISM,
   OtpKey = CKO_OTP_KEY,
   Profile = CKO_PROFILE,
   Validation = CKO_VALIDATION,
   Trust = CKO_TRUST,
   VendorDefined = CKO_VENDOR_DEFINED,
};

enum class PseudoRandom : CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE {
   Pkcs5Pbkd2HmacSha1 = CKP_PKCS5_PBKD2_HMAC_SHA1,
   Pkcs5Pbkd2HmacGostr3411 = CKP_PKCS5_PBKD2_HMAC_GOSTR3411,
   Pkcs5Pbkd2HmacSha224 = CKP_PKCS5_PBKD2_HMAC_SHA224,
   Pkcs5Pbkd2HmacSha256 = CKP_PKCS5_PBKD2_HMAC_SHA256,
   Pkcs5Pbkd2HmacSha384 = CKP_PKCS5_PBKD2_HMAC_SHA384,
   Pkcs5Pbkd2HmacSha512 = CKP_PKCS5_PBKD2_HMAC_SHA512,
   Pkcs5Pbkd2HmacSha512224 = CKP_PKCS5_PBKD2_HMAC_SHA512_224,
   Pkcs5Pbkd2HmacSha512256 = CKP_PKCS5_PBKD2_HMAC_SHA512_256,
};

enum class MlDsaParameterSet : CK_ML_DSA_PARAMETER_SET_TYPE {
   MlDsa44 = CKP_ML_DSA_44,
   MlDsa65 = CKP_ML_DSA_65,
   MlDsa87 = CKP_ML_DSA_87,
};

enum class SlhDsaParameterSet : CK_SLH_DSA_PARAMETER_SET_TYPE {
   SlhDsaSha2_128s = CKP_SLH_DSA_SHA2_128S,
   SlhDsaShake128s = CKP_SLH_DSA_SHAKE_128S,
   SlhDsaSha2_128f = CKP_SLH_DSA_SHA2_128F,
   SlhDsaShake128f = CKP_SLH_DSA_SHAKE_128F,
   SlhDsaSha2_192s = CKP_SLH_DSA_SHA2_192S,
   SlhDsaShake192s = CKP_SLH_DSA_SHAKE_192S,
   SlhDsaSha2_192f = CKP_SLH_DSA_SHA2_192F,
   SlhDsaShake192f = CKP_SLH_DSA_SHAKE_192F,
   SlhDsaSha2_256s = CKP_SLH_DSA_SHA2_256S,
   SlhDsaShake256s = CKP_SLH_DSA_SHAKE_256S,
   SlhDsaSha2_256f = CKP_SLH_DSA_SHA2_256F,
   SlhDsaShake256f = CKP_SLH_DSA_SHAKE_256F,
};

enum class MlKemParameterSet : CK_ML_KEM_PARAMETER_SET_TYPE {
   MlKem512 = CKP_ML_KEM_512,
   MlKem768 = CKP_ML_KEM_768,
   MlKem1024 = CKP_ML_KEM_1024,
};

enum class SessionState : CK_STATE {
   RoPublicSession = CKS_RO_PUBLIC_SESSION,
   RoUserFunctions = CKS_RO_USER_FUNCTIONS,
   RwPublicSession = CKS_RW_PUBLIC_SESSION,
   RwUserFunctions = CKS_RW_USER_FUNCTIONS,
   RwSoFunctions = CKS_RW_SO_FUNCTIONS,
};

enum class ReturnValue : CK_RV {
   OK = CKR_OK,
   Cancel = CKR_CANCEL,
   HostMemory = CKR_HOST_MEMORY,
   SlotIdInvalid = CKR_SLOT_ID_INVALID,
   GeneralError = CKR_GENERAL_ERROR,
   FunctionFailed = CKR_FUNCTION_FAILED,
   ArgumentsBad = CKR_ARGUMENTS_BAD,
   NoEvent = CKR_NO_EVENT,
   NeedToCreateThreads = CKR_NEED_TO_CREATE_THREADS,
   CantLock = CKR_CANT_LOCK,
   AttributeReadOnly = CKR_ATTRIBUTE_READ_ONLY,
   AttributeSensitive = CKR_ATTRIBUTE_SENSITIVE,
   AttributeTypeInvalid = CKR_ATTRIBUTE_TYPE_INVALID,
   AttributeValueInvalid = CKR_ATTRIBUTE_VALUE_INVALID,
   ActionProhibited = CKR_ACTION_PROHIBITED,
   DataInvalid = CKR_DATA_INVALID,
   DataLenRange = CKR_DATA_LEN_RANGE,
   DeviceError = CKR_DEVICE_ERROR,
   DeviceMemory = CKR_DEVICE_MEMORY,
   DeviceRemoved = CKR_DEVICE_REMOVED,
   EncryptedDataInvalid = CKR_ENCRYPTED_DATA_INVALID,
   EncryptedDataLenRange = CKR_ENCRYPTED_DATA_LEN_RANGE,
   AeadDecryptFailed = CKR_AEAD_DECRYPT_FAILED,
   FunctionCanceled = CKR_FUNCTION_CANCELED,
   FunctionNotParallel = CKR_FUNCTION_NOT_PARALLEL,
   FunctionNotSupported = CKR_FUNCTION_NOT_SUPPORTED,
   KeyHandleInvalid = CKR_KEY_HANDLE_INVALID,
   KeySizeRange = CKR_KEY_SIZE_RANGE,
   KeyTypeInconsistent = CKR_KEY_TYPE_INCONSISTENT,
   KeyNotNeeded = CKR_KEY_NOT_NEEDED,
   KeyChanged = CKR_KEY_CHANGED,
   KeyNeeded = CKR_KEY_NEEDED,
   KeyIndigestible = CKR_KEY_INDIGESTIBLE,
   KeyFunctionNotPermitted = CKR_KEY_FUNCTION_NOT_PERMITTED,
   KeyNotWrappable = CKR_KEY_NOT_WRAPPABLE,
   KeyUnextractable = CKR_KEY_UNEXTRACTABLE,
   MechanismInvalid = CKR_MECHANISM_INVALID,
   MechanismParamInvalid = CKR_MECHANISM_PARAM_INVALID,
   ObjectHandleInvalid = CKR_OBJECT_HANDLE_INVALID,
   OperationActive = CKR_OPERATION_ACTIVE,
   OperationNotInitialized = CKR_OPERATION_NOT_INITIALIZED,
   PinIncorrect = CKR_PIN_INCORRECT,
   PinInvalid = CKR_PIN_INVALID,
   PinLenRange = CKR_PIN_LEN_RANGE,
   PinExpired = CKR_PIN_EXPIRED,
   PinLocked = CKR_PIN_LOCKED,
   SessionClosed = CKR_SESSION_CLOSED,
   SessionCount = CKR_SESSION_COUNT,
   SessionHandleInvalid = CKR_SESSION_HANDLE_INVALID,
   SessionParallelNotSupported = CKR_SESSION_PARALLEL_NOT_SUPPORTED,
   SessionReadOnly = CKR_SESSION_READ_ONLY,
   SessionExists = CKR_SESSION_EXISTS,
   SessionReadOnlyExists = CKR_SESSION_READ_ONLY_EXISTS,
   SessionReadWriteSoExists = CKR_SESSION_READ_WRITE_SO_EXISTS,
   SignatureInvalid = CKR_SIGNATURE_INVALID,
   SignatureLenRange = CKR_SIGNATURE_LEN_RANGE,
   TemplateIncomplete = CKR_TEMPLATE_INCOMPLETE,
   TemplateInconsistent = CKR_TEMPLATE_INCONSISTENT,
   TokenNotPresent = CKR_TOKEN_NOT_PRESENT,
   TokenNotRecognized = CKR_TOKEN_NOT_RECOGNIZED,
   TokenWriteProtected = CKR_TOKEN_WRITE_PROTECTED,
   UnwrappingKeyHandleInvalid = CKR_UNWRAPPING_KEY_HANDLE_INVALID,
   UnwrappingKeySizeRange = CKR_UNWRAPPING_KEY_SIZE_RANGE,
   UnwrappingKeyTypeInconsistent = CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
   UserAlreadyLoggedIn = CKR_USER_ALREADY_LOGGED_IN,
   UserNotLoggedIn = CKR_USER_NOT_LOGGED_IN,
   UserPinNotInitialized = CKR_USER_PIN_NOT_INITIALIZED,
   UserTypeInvalid = CKR_USER_TYPE_INVALID,
   UserAnotherAlreadyLoggedIn = CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
   UserTooManyTypes = CKR_USER_TOO_MANY_TYPES,
   WrappedKeyInvalid = CKR_WRAPPED_KEY_INVALID,
   WrappedKeyLenRange = CKR_WRAPPED_KEY_LEN_RANGE,
   WrappingKeyHandleInvalid = CKR_WRAPPING_KEY_HANDLE_INVALID,
   WrappingKeySizeRange = CKR_WRAPPING_KEY_SIZE_RANGE,
   WrappingKeyTypeInconsistent = CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
   RandomSeedNotSupported = CKR_RANDOM_SEED_NOT_SUPPORTED,
   RandomNoRng = CKR_RANDOM_NO_RNG,
   DomainParamsInvalid = CKR_DOMAIN_PARAMS_INVALID,
   CurveNotSupported = CKR_CURVE_NOT_SUPPORTED,
   BufferTooSmall = CKR_BUFFER_TOO_SMALL,
   SavedStateInvalid = CKR_SAVED_STATE_INVALID,
   InformationSensitive = CKR_INFORMATION_SENSITIVE,
   StateUnsaveable = CKR_STATE_UNSAVEABLE,
   CryptokiNotInitialized = CKR_CRYPTOKI_NOT_INITIALIZED,
   CryptokiAlreadyInitialized = CKR_CRYPTOKI_ALREADY_INITIALIZED,
   MutexBad = CKR_MUTEX_BAD,
   MutexNotLocked = CKR_MUTEX_NOT_LOCKED,
   NewPinMode = CKR_NEW_PIN_MODE,
   NextOtp = CKR_NEXT_OTP,
   ExceededMaxIterations = CKR_EXCEEDED_MAX_ITERATIONS,
   FipsSelfTestFailed = CKR_FIPS_SELF_TEST_FAILED,
   LibraryLoadFailed = CKR_LIBRARY_LOAD_FAILED,
   PinTooWeak = CKR_PIN_TOO_WEAK,
   PublicKeyInvalid = CKR_PUBLIC_KEY_INVALID,
   FunctionRejected = CKR_FUNCTION_REJECTED,
   TokenResourceExceeded = CKR_TOKEN_RESOURCE_EXCEEDED,
   OperationCancelFailed = CKR_OPERATION_CANCEL_FAILED,
   KeyExhausted = CKR_KEY_EXHAUSTED,
   Pending = CKR_PENDING,
   SessionAsyncNotSupported = CKR_SESSION_ASYNC_NOT_SUPPORTED,
   SeedRandomRequired = CKR_SEED_RANDOM_REQUIRED,
   OperationNotValidated = CKR_OPERATION_NOT_VALIDATED,
   TokenNotInitialized = CKR_TOKEN_NOT_INITIALIZED,
   VendorDefined = CKR_VENDOR_DEFINED,
};

enum class UserType : CK_USER_TYPE {
   SO = CKU_SO,
   User = CKU_USER,
   ContextSpecific = CKU_CONTEXT_SPECIFIC,
};

enum class PublicPointEncoding : uint32_t { Raw, Der };

using FunctionList = CK_FUNCTION_LIST;
using FunctionListPtr = CK_FUNCTION_LIST_PTR;
using FunctionList30 = CK_FUNCTION_LIST_3_0;
using FunctionList32 = CK_FUNCTION_LIST_3_2;
using Interface = CK_INTERFACE;
using VoidPtr = CK_VOID_PTR;
using C_InitializeArgs = CK_C_INITIALIZE_ARGS;
using CreateMutex = CK_CREATEMUTEX;
using DestroyMutex = CK_DESTROYMUTEX;
using LockMutex = CK_LOCKMUTEX;
using UnlockMutex = CK_UNLOCKMUTEX;
using Flags = CK_FLAGS;
using Info = CK_INFO;
using Version = CK_VERSION;
using Bbool = CK_BBOOL;
using SlotId = CK_SLOT_ID;
using Ulong = CK_ULONG;
using SlotInfo = CK_SLOT_INFO;
using TokenInfo = CK_TOKEN_INFO;
using Mechanism = CK_MECHANISM;
using MechanismInfo = CK_MECHANISM_INFO;
using Utf8Char = CK_UTF8CHAR;
using Notify = CK_NOTIFY;
using SessionHandle = CK_SESSION_HANDLE;
using SessionInfo = CK_SESSION_INFO;
using Attribute = CK_ATTRIBUTE;
using ObjectHandle = CK_OBJECT_HANDLE;
using Byte = CK_BYTE;
using RsaPkcsOaepParams = CK_RSA_PKCS_OAEP_PARAMS;
using RsaPkcsPssParams = CK_RSA_PKCS_PSS_PARAMS;
using Ecdh1DeriveParams = CK_ECDH1_DERIVE_PARAMS;
using Date = CK_DATE;
using AsyncData = CK_ASYNC_DATA;

BOTAN_PUBLIC_API(2, 0) extern ReturnValue* ThrowException;

const Bbool True = CK_TRUE;
const Bbool False = CK_FALSE;

inline Flags flags(Flag flags) {
   return static_cast<Flags>(flags);
}

class Slot;

/**
* Initializes a token
* @param slot The slot with the attached token that should be initialized
* @param label The token label
* @param so_pin PIN of the security officer. Will be set if the token is uninitialized other this has to be the current SO_PIN
* @param pin The user PIN that will be set
*/
BOTAN_PUBLIC_API(2, 0)
void initialize_token(Slot& slot, std::string_view label, const secure_string& so_pin, const secure_string& pin);

/**
* Change PIN with old PIN to new PIN
* @param slot The slot with the attached token
* @param old_pin The old user PIN
* @param new_pin The new user PIN
*/

BOTAN_PUBLIC_API(2, 0) void change_pin(Slot& slot, const secure_string& old_pin, const secure_string& new_pin);

/**
* Change SO_PIN with old SO_PIN to new SO_PIN
* @param slot The slot with the attached token
* @param old_so_pin The old SO_PIN
* @param new_so_pin The new SO_PIN
*/
BOTAN_PUBLIC_API(2, 0) void change_so_pin(Slot& slot, const secure_string& old_so_pin, const secure_string& new_so_pin);

/**
* Sets user PIN with SO_PIN
* @param slot The slot with the attached token
* @param so_pin PIN of the security officer
* @param pin The user PIN that should be set
*/
BOTAN_PUBLIC_API(2, 0) void set_pin(Slot& slot, const secure_string& so_pin, const secure_string& pin);

/**
 * @brief Wraps a PKCS #11 Interface object.
 *
 * This class provides an interface to access PKCS #11 functions of various versions.
 * For example func_3_0() returns the PKCS #11 v3.0 function list for a loaded interface.
 * The default implementation only supports the official "PKCS 11" named
 * interfaces .
 *
 * When using vendor defined interfaces, this class can be subclassed to specify access
 * to the official PKCS #11 functions while vendor defined function lists can be added.
 * In this case, the LowLevel class can be subclassed as well to provide access to the
 * default PKCS #11 functions (via func_2_40(), func_3_0(), etc.) which is extended by
 * the vendor defined ones.
 */
class BOTAN_PUBLIC_API(3, 7) InterfaceWrapper {
   private:
      Interface m_interface;

   public:
      /// Basic constructor using an interface.
      InterfaceWrapper(Interface raw_interface);

      InterfaceWrapper(const InterfaceWrapper&) = default;
      InterfaceWrapper& operator=(const InterfaceWrapper&) = default;
      InterfaceWrapper(InterfaceWrapper&&) = default;
      InterfaceWrapper& operator=(InterfaceWrapper&&) = default;
      virtual ~InterfaceWrapper() = default;

      /// Access the underlying interface object
      const Interface& raw_interface() const { return m_interface; }

      /// Access the version of the interface
      Version version() const;

      /// Access the name of the interface
      std::basic_string_view<Utf8Char> name() const;

      /// Access a function list that contains all methods since PKCS #11 v.2.40
      virtual const FunctionList& func_2_40() const;

      /// Access a function list that contains all methods since PKCS #11 v.3.0
      virtual const FunctionList30& func_3_0() const;

      /// Access a function list that contains all methods since PKCS #11 v.3.2
      virtual const FunctionList32& func_3_2() const;

      /// Find the latest supported "PKCS 11" interface. Fork safe interfaces
      /// are prefered over non fork safe ones of the same version.
      static std::unique_ptr<InterfaceWrapper> latest_p11_interface(Dynamically_Loaded_Library& library);

      /**
       * Returns an immortal pointer to the Utf8Char string "PKCS 11".
       * Used to define an interface object.
       *
       * @warning Unfortunately, the interface object requires a non constant
       * pointer. However, this string MUST NOT be modified!
       */
      static Utf8Char* p11_interface_name_ptr();
};

/// Provides access to all PKCS #11 functions
class BOTAN_PUBLIC_API(2, 0) LowLevel {
   public:
      /// @param ptr the functon list pointer to use. Can be retrieved via `LowLevel::C_GetFunctionList`
      BOTAN_DEPRECATED("Use LowLevel(InterfaceWrapperDefault::latest_p11_interface(module.library()))")
      explicit LowLevel(FunctionList* ptr);

      explicit LowLevel(std::unique_ptr<InterfaceWrapper> interface_wrapper);

      /****************************** General purpose functions ******************************/

      /**
      * C_Initialize initializes the Cryptoki library.
      * @param init_args if this is not nullptr, it gets cast to (`C_InitializeArgs`) and dereferenced
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CantLock \li CryptokiAlreadyInitialized
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li NeedToCreateThreads \li OK
      * @return true on success, false otherwise
      */
      bool C_Initialize(const void* init_args, ReturnValue* return_value = ThrowException) const;

      /**
      * C_Finalize indicates that an application is done with the Cryptoki library.
      * @param reserved reserved.  Should be nullptr
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li FunctionFailed
      *     \li GeneralError \li HostMemory \li OK
      * @return true on success, false otherwise
      */
      bool C_Finalize(void* reserved, ReturnValue* return_value = ThrowException) const;

      /**
      * C_GetInfo returns general information about Cryptoki.
      * @param info_ptr location that receives information
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li FunctionFailed
      *     \li GeneralError \li HostMemory \li OK
      * @return true on success, false otherwise
      */
      bool C_GetInfo(Info* info_ptr, ReturnValue* return_value = ThrowException) const;

      /**
      * C_GetFunctionList returns the function list.
      * @param pkcs11_module The PKCS #11 module
      * @param function_list_ptr_ptr receives pointer to function list
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li FunctionFailed \li GeneralError
      *     \li HostMemory \li OK
      * @return true on success, false otherwise
      */
      static bool C_GetFunctionList(const Dynamically_Loaded_Library& pkcs11_module,
                                    FunctionList** function_list_ptr_ptr,
                                    ReturnValue* return_value = ThrowException);

      /**
       * C_GetInterfaceList is used to obtain a list of interfaces supported by
       * a Cryptoki library. count_ptr points to the location that receives the
       * number of interfaces. There are two ways for an application to call
       * C_GetInterfaceList:
       *  1. If interface_list_ptr is NULL_PTR, then all that C_GetInterfaceList
       *     does is return (in *count_ptr) the number of interfaces, without
       *     actually returning a list of interfaces. The contents of *count_ptr
       *     on entry to C_GetInterfaceList have no meaning in this case, and the
       *     call returns the value CKR_OK.
       *  2. If pIntrerfaceList is not NULL_PTR, then *count_ptr MUST contain the
       *     size (in terms of CK_INTERFACE elements) of the buffer pointed to
       *     by interface_list_ptr. If that buffer is large enough to  hold the
       *     list of interfaces, then the list is returned in it, and CKR_OK is
       *     returned. If not, then the call to C_GetInterfaceList returns the
       *     value CKR_BUFFER_TOO_SMALL. In either case, the value *count_ptr is
       *     set to hold the number of interfaces.
       *
       * Because C_GetInterfaceList does not allocate any space of its own, an
       * application will often call C_GetInterfaceList twice. However, this
       * behavior is by no means required. C_GetInterfaceList obtains
       * (in *pFunctionList of each interface) a pointer to the Cryptoki
       * library’s list of function pointers. The pointer thus obtained may
       * point into memory which is owned by the Cryptoki library, and which
       * may or may not be writable. Whether or not this is the case, no attempt
       * should be made to write to this memory. The same caveat applies to
       * the interface names returned.
       *
       * @param pkcs11_module The PKCS #11 module
       * @param interface_list_ptr returned interfaces
       * @param count_ptr number of interfaces returned
       * @param return_value default value (`ThrowException`): throw exception on error.
       * @return true on success, false otherwise
       */
      static bool C_GetInterfaceList(const Dynamically_Loaded_Library& pkcs11_module,
                                     Interface* interface_list_ptr,
                                     Ulong* count_ptr,
                                     ReturnValue* return_value = ThrowException);

      /**
       * C_GetInterface is used to obtain an interface supported by a Cryptoki
       * library. pInterfaceName specifies  the name of the interface, pVersion
       * specifies the interface version, ppInterface points to the location
       * that  receives the interface, flags specifies the required interface
       * flags. There are multiple ways for an application to specify a
       * particular interface when calling C_GetInterface:
       * 1. If pInterfaceName is not NULL_PTR, the name of the interface
       *    returned must match. If  pInterfaceName is NULL_PTR, the cryptoki
       *    library can return a default interface of its choice
       * 2. If pVersion is not NULL_PTR, the version of the interface returned
       *    must match. If pVersion is  NULL_PTR, the cryptoki library can
       *    return an interface of any version
       * 3. If flags is non-zero, the interface returned must match all of the
       *    supplied flag values (but may include  additional flags not
       *    specified). If flags is 0, the cryptoki library can return an
       *    interface with any flags
       *
       * @param pkcs11_module The PKCS #11 module
       * @param interface_name_ptr name of the interface
       * @param version_ptr version of the interface
       * @param interface_ptr_ptr returned interface
       * @param flags flags controlling the semantics of the interface
       * @param return_value default value (`ThrowException`): throw exception on error.
       * @return true on success, false otherwise
       */
      static bool C_GetInterface(const Dynamically_Loaded_Library& pkcs11_module,
                                 const Utf8Char* interface_name_ptr,
                                 const Version* version_ptr,
                                 Interface* interface_ptr_ptr,
                                 Flags flags,
                                 ReturnValue* return_value = ThrowException);

      /****************************** Slot and token management functions ******************************/

      /**
      * C_GetSlotList obtains a list of slots in the system.
      * @param token_present only slots with tokens
      * @param slot_list_ptr receives array of slot IDs
      * @param count_ptr receives number of slots
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li OK
      * @return true on success, false otherwise
      */
      bool C_GetSlotList(Bbool token_present,
                         SlotId* slot_list_ptr,
                         Ulong* count_ptr,
                         ReturnValue* return_value = ThrowException) const;

      /**
      * C_GetSlotList obtains a list of slots in the system.
      * @param token_present only slots with tokens
      * @param slot_ids receives vector of slot IDs
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li OK
      * @return true on success, false otherwise
      */
      bool C_GetSlotList(bool token_present,
                         std::vector<SlotId>& slot_ids,
                         ReturnValue* return_value = ThrowException) const;

      /**
      * C_GetSlotInfo obtains information about a particular slot in the system.
      * @param slot_id the ID of the slot
      * @param info_ptr receives the slot information
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li DeviceError
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li OK \li SlotIdInvalid
      * @return true on success, false otherwise
      */
      bool C_GetSlotInfo(SlotId slot_id, SlotInfo* info_ptr, ReturnValue* return_value = ThrowException) const;

      /**
      * C_GetTokenInfo obtains information about a particular token in the system.
      * @param slot_id ID of the token's slot
      * @param info_ptr receives the token information
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li CryptokiNotInitialized \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionFailed \li GeneralError
      *     \li HostMemory \li OK \li SlotIdInvalid
      *     \li TokenNotPresent \li TokenNotRecognized \li ArgumentsBad
      * @return true on success, false otherwise
      */
      bool C_GetTokenInfo(SlotId slot_id, TokenInfo* info_ptr, ReturnValue* return_value = ThrowException) const;

      /**
      * C_WaitForSlotEvent waits for a slot event (token insertion, removal, etc.) to occur.
      * @param flags blocking/nonblocking flag
      * @param slot_ptr location that receives the slot ID
      * @param reserved reserved.  Should be NULL_PTR
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li FunctionFailed
      *     \li GeneralError \li HostMemory \li NoEvent
      *     \li OK
      * @return true on success, false otherwise
      */
      bool C_WaitForSlotEvent(Flags flags,
                              SlotId* slot_ptr,
                              void* reserved,
                              ReturnValue* return_value = ThrowException) const;

      /**
      * C_GetMechanismList obtains a list of mechanism types supported by a token.
      * @param slot_id ID of token's slot
      * @param mechanism_list_ptr gets mech. array
      * @param count_ptr gets # of mechs.
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li BufferTooSmall \li CryptokiNotInitialized \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionFailed
      *     \li GeneralError \li HostMemory \li OK
      *     \li SlotIdInvalid \li TokenNotPresent \li TokenNotRecognized
      *     \li ArgumentsBad
      * @return true on success, false otherwise
      */
      bool C_GetMechanismList(SlotId slot_id,
                              MechanismType* mechanism_list_ptr,
                              Ulong* count_ptr,
                              ReturnValue* return_value = ThrowException) const;

      /**
      * C_GetMechanismList obtains a list of mechanism types supported by a token.
      * @param slot_id ID of token's slot
      * @param mechanisms receives vector of supported mechanisms
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li BufferTooSmall \li CryptokiNotInitialized \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionFailed
      *     \li GeneralError \li HostMemory \li OK
      *     \li SlotIdInvalid \li TokenNotPresent \li TokenNotRecognized
      *     \li ArgumentsBad
      * @return true on success, false otherwise
      */
      bool C_GetMechanismList(SlotId slot_id,
                              std::vector<MechanismType>& mechanisms,
                              ReturnValue* return_value = ThrowException) const;

      /**
      * C_GetMechanismInfo obtains information about a particular mechanism possibly supported by a token.
      * @param slot_id ID of the token's slot
      * @param type type of mechanism
      * @param info_ptr receives mechanism info
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li CryptokiNotInitialized \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionFailed \li GeneralError
      *     \li HostMemory \li MechanismInvalid \li OK
      *     \li SlotIdInvalid \li TokenNotPresent \li TokenNotRecognized
      *     \li ArgumentsBad
      * @return true on success, false otherwise
      */
      bool C_GetMechanismInfo(SlotId slot_id,
                              MechanismType type,
                              MechanismInfo* info_ptr,
                              ReturnValue* return_value = ThrowException) const;

      /**
      * C_InitToken initializes a token.
      * @param slot_id ID of the token's slot
      * @param so_pin_ptr the SO's initial PIN
      * @param so_pin_len length in bytes of the SO_PIN
      * @param label_ptr 32-byte token label (blank padded)
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li CryptokiNotInitialized \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionCanceled \li FunctionFailed
      *     \li GeneralError \li HostMemory \li OK
      *     \li PinIncorrect \li PinLocked \li SessionExists
      *     \li SlotIdInvalid \li TokenNotPresent \li TokenNotRecognized
      *     \li TokenWriteProtected \li ArgumentsBad
      * @return true on success, false otherwise
      */
      bool C_InitToken(SlotId slot_id,
                       const Utf8Char* so_pin_ptr,
                       Ulong so_pin_len,
                       const Utf8Char* label_ptr,
                       ReturnValue* return_value = ThrowException) const;

      /**
      * C_InitToken initializes a token.
      * @param slot_id ID of the token's slot
      * @param so_pin the SO's initial PIN
      * @param label token label (at max 32 bytes long)
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li CryptokiNotInitialized \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionCanceled \li FunctionFailed
      *     \li GeneralError \li HostMemory \li OK
      *     \li PinIncorrect \li PinLocked \li SessionExists
      *     \li SlotIdInvalid \li TokenNotPresent \li TokenNotRecognized
      *     \li TokenWriteProtected \li ArgumentsBad
      * @return true on success, false otherwise
      */
      template <typename TAlloc>
      bool C_InitToken(SlotId slot_id,
                       const std::vector<uint8_t, TAlloc>& so_pin,
                       std::string_view label,
                       ReturnValue* return_value = ThrowException) const {
         std::string padded_label(label);
         if(label.size() < 32) {
            padded_label.insert(padded_label.end(), 32 - label.size(), ' ');
         }

         return C_InitToken(slot_id,
                            reinterpret_cast<Utf8Char*>(const_cast<uint8_t*>(so_pin.data())),
                            static_cast<Ulong>(so_pin.size()),
                            reinterpret_cast<Utf8Char*>(const_cast<char*>(padded_label.c_str())),
                            return_value);
      }

      /**
      * C_InitPIN initializes the normal user's PIN.
      * @param session the session's handle
      * @param pin_ptr the normal user's PIN
      * @param pin_len length in bytes of the PIN
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li CryptokiNotInitialized \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionCanceled \li FunctionFailed
      *     \li GeneralError \li HostMemory \li OK
      *     \li PinInvalid \li PinLenRange \li SessionClosed
      *     \li SessionReadOnly \li SessionHandleInvalid \li TokenWriteProtected
      *     \li UserNotLoggedIn \li ArgumentsBad
      * @return true on success, false otherwise
      */
      bool C_InitPIN(SessionHandle session,
                     const Utf8Char* pin_ptr,
                     Ulong pin_len,
                     ReturnValue* return_value = ThrowException) const;

      /**
      * C_InitPIN initializes the normal user's PIN.
      * @param session the session's handle
      * @param pin the normal user's PIN
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li CryptokiNotInitialized \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionCanceled \li FunctionFailed
      *     \li GeneralError \li HostMemory \li OK
      *     \li PinInvalid \li PinLenRange \li SessionClosed
      *     \li SessionReadOnly \li SessionHandleInvalid \li TokenWriteProtected
      *     \li UserNotLoggedIn \li ArgumentsBad
      * @return true on success, false otherwise
      */
      template <typename TAlloc>
      bool C_InitPIN(SessionHandle session,
                     const std::vector<uint8_t, TAlloc>& pin,
                     ReturnValue* return_value = ThrowException) const {
         return C_InitPIN(session,
                          reinterpret_cast<Utf8Char*>(const_cast<uint8_t*>(pin.data())),
                          static_cast<Ulong>(pin.size()),
                          return_value);
      }

      /**
      * C_SetPIN modifies the PIN of the user who is logged in.
      * @param session the session's handle
      * @param old_pin_ptr the old PIN
      * @param old_len length of the old PIN
      * @param new_pin_ptr the new PIN
      * @param new_len length of the new PIN
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li CryptokiNotInitialized \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionCanceled \li FunctionFailed
      *     \li GeneralError \li HostMemory \li OK
      *     \li PinIncorrect \li PinInvalid \li PinLenRange
      *     \li PinLocked \li SessionClosed \li SessionHandleInvalid
      *     \li SessionReadOnly \li TokenWriteProtected \li ArgumentsBad
      * @return true on success, false otherwise
      */
      bool C_SetPIN(SessionHandle session,
                    const Utf8Char* old_pin_ptr,
                    Ulong old_len,
                    const Utf8Char* new_pin_ptr,
                    Ulong new_len,
                    ReturnValue* return_value = ThrowException) const;

      /**
      * C_SetPIN modifies the PIN of the user who is logged in.
      * @param session the session's handle
      * @param old_pin the old PIN
      * @param new_pin the new PIN
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li CryptokiNotInitialized \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionCanceled \li FunctionFailed
      *     \li GeneralError \li HostMemory \li OK
      *     \li PinIncorrect \li PinInvalid \li PinLenRange
      *     \li PinLocked \li SessionClosed \li SessionHandleInvalid
      *     \li SessionReadOnly \li TokenWriteProtected \li ArgumentsBad
      * @return true on success, false otherwise
      */
      template <typename TAlloc>
      bool C_SetPIN(SessionHandle session,
                    const std::vector<uint8_t, TAlloc>& old_pin,
                    const std::vector<uint8_t, TAlloc>& new_pin,
                    ReturnValue* return_value = ThrowException) const {
         return C_SetPIN(session,
                         reinterpret_cast<Utf8Char*>(const_cast<uint8_t*>(old_pin.data())),
                         static_cast<Ulong>(old_pin.size()),
                         reinterpret_cast<Utf8Char*>(const_cast<uint8_t*>(new_pin.data())),
                         static_cast<Ulong>(new_pin.size()),
                         return_value);
      }

      /****************************** Session management ******************************/

      /**
      * C_OpenSession opens a session between an application and a token.
      * @param slot_id the slot's ID
      * @param flags from CK_SESSION_INFO
      * @param application passed to callback
      * @param notify callback function
      * @param session_ptr gets session handle
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li CryptokiNotInitialized \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionFailed \li GeneralError
      *     \li HostMemory \li OK \li SessionCount
      *     \li SessionParallelNotSupported \li SessionReadWriteSoExists \li SlotIdInvalid
      *     \li TokenNotPresent \li TokenNotRecognized \li TokenWriteProtected
      *     \li ArgumentsBad
      * @return true on success, false otherwise
      */
      bool C_OpenSession(SlotId slot_id,
                         Flags flags,
                         void* application,
                         Notify notify,
                         SessionHandle* session_ptr,
                         ReturnValue* return_value = ThrowException) const;

      /**
      * C_CloseSession closes a session between an application and a token.
      * @param session the session's handle
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li CryptokiNotInitialized \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionFailed \li GeneralError
      *     \li HostMemory \li OK \li SessionClosed
      *     \li SessionHandleInvalid
      * @return true on success, false otherwise
      */
      bool C_CloseSession(SessionHandle session, ReturnValue* return_value = ThrowException) const;

      /**
      * C_CloseAllSessions closes all sessions with a token.
      * @param slot_id the token's slot
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li CryptokiNotInitialized \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionFailed \li GeneralError
      *     \li HostMemory \li OK \li SlotIdInvalid
      *     \li TokenNotPresent
      * @return true on success, false otherwise
      */
      bool C_CloseAllSessions(SlotId slot_id, ReturnValue* return_value = ThrowException) const;

      /**
      * C_GetSessionInfo obtains information about the session.
      * @param session the session's handle
      * @param info_ptr receives session info
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li CryptokiNotInitialized \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionFailed \li GeneralError
      *     \li HostMemory \li OK \li SessionClosed
      *     \li SessionHandleInvalid \li ArgumentsBad
      * @return true on success, false otherwise
      */
      bool C_GetSessionInfo(SessionHandle session,
                            SessionInfo* info_ptr,
                            ReturnValue* return_value = ThrowException) const;

      /**
       * C_SessionCancel terminates active session based operations.
       *
       * @param session the session's handle
       * @param flags flags control which sessions are cancelled
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_SessionCancel(SessionHandle session, Flags flags, ReturnValue* return_value = ThrowException);

      /**
      * C_GetOperationState obtains the state of the cryptographic operation in a session.
      * @param session session's handle
      * @param operation_state_ptr gets state
      * @param operation_state_len_ptr gets state length
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li BufferTooSmall \li CryptokiNotInitialized \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionFailed
      *     \li GeneralError \li HostMemory \li OK
      *     \li OperationNotInitialized \li SessionClosed \li SessionHandleInvalid
      *     \li StateUnsaveable \li ArgumentsBad
      * @return true on success, false otherwise
      */
      bool C_GetOperationState(SessionHandle session,
                               Byte* operation_state_ptr,
                               Ulong* operation_state_len_ptr,
                               ReturnValue* return_value = ThrowException) const;

      /**
      * C_SetOperationState restores the state of the cryptographic operation in a session.
      * @param session session's handle
      * @param operation_state_ptr holds state
      * @param operation_state_len holds state length
      * @param encryption_key en/decryption key
      * @param authentication_key sign/verify key
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li CryptokiNotInitialized \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionFailed \li GeneralError
      *     \li HostMemory \li KeyChanged \li KeyNeeded
      *     \li KeyNotNeeded \li OK \li SavedStateInvalid
      *     \li SessionClosed \li SessionHandleInvalid \li ArgumentsBad
      * @return true on success, false otherwise
      */
      bool C_SetOperationState(SessionHandle session,
                               const Byte* operation_state_ptr,
                               Ulong operation_state_len,
                               ObjectHandle encryption_key,
                               ObjectHandle authentication_key,
                               ReturnValue* return_value = ThrowException) const;

      /**
      * C_Login logs a user into a token.
      * @param session the session's handle
      * @param user_type the user type
      * @param pin_ptr the user's PIN
      * @param pin_len the length of the PIN
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li OK \li OperationNotInitialized \li PinIncorrect
      *     \li PinLocked \li SessionClosed \li SessionHandleInvalid
      *     \li SessionReadOnlyExists \li UserAlreadyLoggedIn \li UserAnotherAlreadyLoggedIn
      *     \li UserPinNotInitialized \li UserTooManyTypes \li UserTypeInvalid
      * @return true on success, false otherwise
      */
      bool C_Login(SessionHandle session,
                   UserType user_type,
                   const Utf8Char* pin_ptr,
                   Ulong pin_len,
                   ReturnValue* return_value = ThrowException) const;

      /**
      * C_Login logs a user into a token.
      * @param session the session's handle
      * @param user_type the user type
      * @param pin the user or security officer's PIN
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li OK \li OperationNotInitialized \li PinIncorrect
      *     \li PinLocked \li SessionClosed \li SessionHandleInvalid
      *     \li SessionReadOnlyExists \li UserAlreadyLoggedIn \li UserAnotherAlreadyLoggedIn
      *     \li UserPinNotInitialized \li UserTooManyTypes \li UserTypeInvalid
      * @return true on success, false otherwise
      */
      template <typename TAlloc>
      bool C_Login(SessionHandle session,
                   UserType user_type,
                   const std::vector<uint8_t, TAlloc>& pin,
                   ReturnValue* return_value = ThrowException) const {
         return C_Login(session,
                        user_type,
                        reinterpret_cast<Utf8Char*>(const_cast<uint8_t*>(pin.data())),
                        static_cast<Ulong>(pin.size()),
                        return_value);
      }

      /**
       * C_LoginUser logs a user into a token.
       *
       * @param session the session's handle
       * @param user_type the user type
       * @param pin_ptr the user's PIN
       * @param pin_len the length of the PIN
       * @param username_ptr the user's name
       * @param username_len the length of the user's name
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_LoginUser(SessionHandle session,
                       UserType user_type,
                       const Utf8Char* pin_ptr,
                       Ulong pin_len,
                       const Utf8Char* username_ptr,
                       Ulong username_len,
                       ReturnValue* return_value = ThrowException);

      /**
      * C_Logout logs a user out from a token.
      * @param session the session's handle
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li CryptokiNotInitialized \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionFailed \li GeneralError
      *     \li HostMemory \li OK \li SessionClosed
      *     \li SessionHandleInvalid \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_Logout(SessionHandle session, ReturnValue* return_value = ThrowException) const;

      /**
       * C_GetSessionValidationFlags fetches the requested flags from the session. See
       * Validation indicators (section4.15.3.1) for meaning and semantics for these
       * flags. Applications are responsible for the appropriate locking to protect
       * session to get a meaningful result from this call.
       *
       * @param session the session's handle
       * @param type which state of flags
       * @param flags_ptr validation flags
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_GetSessionValidationFlags(SessionHandle session,
                                       Ulong type,
                                       Flags* flags_ptr,
                                       ReturnValue* return_value = ThrowException);

      /****************************** Object management functions ******************************/

      /**
      * C_CreateObject creates a new object.
      * @param session the session's handle
      * @param attribute_template_ptr the object's template
      * @param count attributes in template
      * @param object_ptr gets new object's handle.
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li AttributeReadOnly \li AttributeTypeInvalid
      *     \li AttributeValueInvalid \li CryptokiNotInitialized \li CurveNotSupported
      *     \li DeviceError \li DeviceMemory \li DeviceRemoved
      *     \li DomainParamsInvalid \li FunctionFailed \li GeneralError
      *     \li HostMemory \li OK \li PinExpired
      *     \li SessionClosed \li SessionHandleInvalid \li SessionReadOnly
      *     \li TemplateIncomplete \li TemplateInconsistent \li TokenWriteProtected
      *     \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_CreateObject(SessionHandle session,
                          Attribute* attribute_template_ptr,
                          Ulong count,
                          ObjectHandle* object_ptr,
                          ReturnValue* return_value = ThrowException) const;

      /**
      * C_CopyObject copies an object, creating a new object for the copy.
      * @param session the session's handle
      * @param object the object's handle
      * @param attribute_template_ptr template for new object
      * @param count attributes in template
      * @param new_object_ptr receives handle of copy
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ActionProhibited \li ArgumentsBad \li AttributeReadOnly
      *     \li AttributeTypeInvalid \li AttributeValueInvalid \li CryptokiNotInitialized
      *     \li DeviceError \li DeviceMemory \li DeviceRemoved
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li ObjectHandleInvalid \li OK \li PinExpired
      *     \li SessionClosed \li SessionHandleInvalid \li SessionReadOnly
      *     \li TemplateInconsistent \li TokenWriteProtected \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_CopyObject(SessionHandle session,
                        ObjectHandle object,
                        Attribute* attribute_template_ptr,
                        Ulong count,
                        ObjectHandle* new_object_ptr,
                        ReturnValue* return_value = ThrowException) const;

      /**
      * C_DestroyObject destroys an object.
      * @param session the session's handle
      * @param object the object's handle
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ActionProhibited \li CryptokiNotInitialized \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionFailed
      *     \li GeneralError \li HostMemory \li ObjectHandleInvalid
      *     \li OK \li PinExpired \li SessionClosed
      *     \li SessionHandleInvalid \li SessionReadOnly \li TokenWriteProtected
      * @return true on success, false otherwise
      */
      bool C_DestroyObject(SessionHandle session,
                           ObjectHandle object,
                           ReturnValue* return_value = ThrowException) const;

      /**
      * C_GetObjectSize gets the size of an object in bytes.
      * @param session the session's handle
      * @param object the object's handle
      * @param size_ptr receives size of object
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionFailed
      *     \li GeneralError \li HostMemory \li InformationSensitive
      *     \li ObjectHandleInvalid \li OK \li SessionClosed
      *     \li SessionHandleInvalid
      * @return true on success, false otherwise
      */
      bool C_GetObjectSize(SessionHandle session,
                           ObjectHandle object,
                           Ulong* size_ptr,
                           ReturnValue* return_value = ThrowException) const;

      /**
      * C_GetAttributeValue obtains the value of one or more object attributes.
      * @param session the session's handle
      * @param object the object's handle
      * @param attribute_template_ptr specifies attrs; gets vals
      * @param count attributes in template
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li AttributeSensitive \li AttributeTypeInvalid
      *     \li BufferTooSmall \li CryptokiNotInitialized \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionFailed
      *     \li GeneralError \li HostMemory \li ObjectHandleInvalid
      *     \li OK \li SessionClosed \li SessionHandleInvalid
      * @return true on success, false otherwise
      */
      bool C_GetAttributeValue(SessionHandle session,
                               ObjectHandle object,
                               Attribute* attribute_template_ptr,
                               Ulong count,
                               ReturnValue* return_value = ThrowException) const;

      /**
      * C_GetAttributeValue obtains the value of one or more object attributes.
      * @param session the session's handle
      * @param object the object's handle
      * @param attribute_values specifies attrs; gets vals
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li AttributeSensitive \li AttributeTypeInvalid
      *     \li BufferTooSmall \li CryptokiNotInitialized \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionFailed
      *     \li GeneralError \li HostMemory \li ObjectHandleInvalid
      *     \li OK \li SessionClosed \li SessionHandleInvalid
      * @return true on success, false otherwise
      */
      template <typename TAlloc>
      bool C_GetAttributeValue(SessionHandle session,
                               ObjectHandle object,
                               std::map<AttributeType, std::vector<uint8_t, TAlloc>>& attribute_values,
                               ReturnValue* return_value = ThrowException) const {
         std::vector<Attribute> getter_template;

         for(const auto& entry : attribute_values) {
            getter_template.emplace_back(Attribute{static_cast<CK_ATTRIBUTE_TYPE>(entry.first), nullptr, 0});
         }

         bool success = C_GetAttributeValue(session,
                                            object,
                                            const_cast<Attribute*>(getter_template.data()),
                                            static_cast<Ulong>(getter_template.size()),
                                            return_value);

         if(!success) {
            return success;
         }

         size_t i = 0;
         for(auto& entry : attribute_values) {
            entry.second.clear();
            entry.second.resize(getter_template.at(i).ulValueLen);
            getter_template.at(i).pValue = const_cast<uint8_t*>(entry.second.data());
            i++;
         }

         return C_GetAttributeValue(session,
                                    object,
                                    const_cast<Attribute*>(getter_template.data()),
                                    static_cast<Ulong>(getter_template.size()),
                                    return_value);
      }

      /**
      * C_SetAttributeValue modifies the value of one or more object attributes.
      * @param session the session's handle
      * @param object the object's handle
      * @param attribute_template_ptr specifies attrs and values
      * @param count attributes in template
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ActionProhibited \li ArgumentsBad \li AttributeReadOnly
      *     \li AttributeTypeInvalid \li AttributeValueInvalid \li CryptokiNotInitialized
      *     \li DeviceError \li DeviceMemory \li DeviceRemoved
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li ObjectHandleInvalid \li OK \li SessionClosed
      *     \li SessionHandleInvalid \li SessionReadOnly \li TemplateInconsistent
      *     \li TokenWriteProtected \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_SetAttributeValue(SessionHandle session,
                               ObjectHandle object,
                               Attribute* attribute_template_ptr,
                               Ulong count,
                               ReturnValue* return_value = ThrowException) const;

      /**
      * C_SetAttributeValue modifies the value of one or more object attributes.
      * @param session the session's handle
      * @param object the object's handle
      * @param attribute_values specifies attrs and values
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ActionProhibited \li ArgumentsBad \li AttributeReadOnly
      *     \li AttributeTypeInvalid \li AttributeValueInvalid \li CryptokiNotInitialized
      *     \li DeviceError \li DeviceMemory \li DeviceRemoved
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li ObjectHandleInvalid \li OK \li SessionClosed
      *     \li SessionHandleInvalid \li SessionReadOnly \li TemplateInconsistent
      *     \li TokenWriteProtected \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      template <typename TAlloc>
      bool C_SetAttributeValue(SessionHandle session,
                               ObjectHandle object,
                               std::map<AttributeType, std::vector<uint8_t, TAlloc>>& attribute_values,
                               ReturnValue* return_value = ThrowException) const {
         std::vector<Attribute> setter_template;

         for(auto& entry : attribute_values) {
            setter_template.emplace_back(Attribute{static_cast<CK_ATTRIBUTE_TYPE>(entry.first),
                                                   entry.second.data(),
                                                   static_cast<CK_ULONG>(entry.second.size())});
         }

         return C_SetAttributeValue(session,
                                    object,
                                    const_cast<Attribute*>(setter_template.data()),
                                    static_cast<Ulong>(setter_template.size()),
                                    return_value);
      }

      /**
      * C_FindObjectsInit initializes a search for token and session objects that match a template.
      * @param session the session's handle
      * @param attribute_template_ptr attribute values to match
      * @param count attrs in search template
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li AttributeTypeInvalid \li AttributeValueInvalid
      *     \li CryptokiNotInitialized \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionFailed \li GeneralError
      *     \li HostMemory \li OK \li OperationActive
      *     \li PinExpired \li SessionClosed \li SessionHandleInvalid
      * @return true on success, false otherwise
      */
      bool C_FindObjectsInit(SessionHandle session,
                             Attribute* attribute_template_ptr,
                             Ulong count,
                             ReturnValue* return_value = ThrowException) const;

      /**
      * C_FindObjects continues a search for token and session objects that match a template, obtaining additional object handles.
      * @param session session's handle
      * @param object_ptr gets obj. handles
      * @param max_object_count max handles to get
      * @param object_count_ptr actual # returned
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionFailed
      *     \li GeneralError \li HostMemory \li OK
      *     \li OperationNotInitialized \li SessionClosed \li SessionHandleInvalid
      * @return true on success, false otherwise
      */
      bool C_FindObjects(SessionHandle session,
                         ObjectHandle* object_ptr,
                         Ulong max_object_count,
                         Ulong* object_count_ptr,
                         ReturnValue* return_value = ThrowException) const;

      /**
      * C_FindObjectsFinal finishes a search for token and session objects.
      * @param session the session's handle
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li CryptokiNotInitialized \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionFailed \li GeneralError
      *     \li HostMemory \li OK \li OperationNotInitialized
      *     \li SessionClosed \li SessionHandleInvalid
      * @return true on success, false otherwise
      */
      bool C_FindObjectsFinal(SessionHandle session, ReturnValue* return_value = ThrowException) const;

      /****************************** Encryption functions ******************************/

      /**
      * C_EncryptInit initializes an encryption operation.
      * @param session the session's handle
      * @param mechanism_ptr the encryption mechanism
      * @param key handle of encryption key
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li CryptokiNotInitialized \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionCanceled \li FunctionFailed
      *     \li GeneralError \li HostMemory \li KeyFunctionNotPermitted
      *     \li KeyHandleInvalid \li KeySizeRange \li KeyTypeInconsistent
      *     \li MechanismInvalid \li MechanismParamInvalid \li OK
      *     \li OperationActive \li PinExpired \li SessionClosed
      *     \li SessionHandleInvalid \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_EncryptInit(SessionHandle session,
                         const Mechanism* mechanism_ptr,
                         ObjectHandle key,
                         ReturnValue* return_value = ThrowException) const;

      /**
      * C_Encrypt encrypts single-part data.
      * @param session session's handle
      * @param data_ptr the plaintext data
      * @param data_len size of plaintext data in bytes
      * @param encrypted_data gets ciphertext
      * @param encrypted_data_len_ptr gets c-text size
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li DataInvalid \li DataLenRange \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li OK \li OperationNotInitialized \li SessionClosed
      *     \li SessionHandleInvalid
      * @return true on success, false otherwise
      */
      bool C_Encrypt(SessionHandle session,
                     const Byte* data_ptr,
                     Ulong data_len,
                     Byte* encrypted_data,
                     Ulong* encrypted_data_len_ptr,
                     ReturnValue* return_value = ThrowException) const;

      /**
      * C_Encrypt encrypts single-part data.
      * @param session session's handle
      * @param plaintext_data the plaintext data
      * @param encrypted_data gets ciphertext
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li DataInvalid \li DataLenRange \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li OK \li OperationNotInitialized \li SessionClosed
      *     \li SessionHandleInvalid
      * @return true on success, false otherwise
      */
      template <typename TAllocA, typename TAllocB>
      bool C_Encrypt(SessionHandle session,
                     const std::vector<uint8_t, TAllocA>& plaintext_data,
                     std::vector<uint8_t, TAllocB>& encrypted_data,
                     ReturnValue* return_value = ThrowException) const {
         Ulong encrypted_size = 0;
         if(!C_Encrypt(session,
                       const_cast<Byte*>((plaintext_data.data())),
                       static_cast<Ulong>(plaintext_data.size()),
                       nullptr,
                       &encrypted_size,
                       return_value)) {
            return false;
         }

         encrypted_data.resize(encrypted_size);
         if(!C_Encrypt(session,
                       const_cast<Byte*>(plaintext_data.data()),
                       static_cast<Ulong>(plaintext_data.size()),
                       encrypted_data.data(),
                       &encrypted_size,
                       return_value)) {
            return false;
         }
         encrypted_data.resize(encrypted_size);
         return true;
      }

      /**
      * C_EncryptUpdate continues a multiple-part encryption operation.
      * @param session session's handle
      * @param part_ptr the plaintext data
      * @param part_len plaintext data len
      * @param encrypted_part_ptr gets ciphertext
      * @param encrypted_part_len_ptr gets c-text size
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li DataLenRange \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionCanceled \li FunctionFailed
      *     \li GeneralError \li HostMemory \li OK
      *     \li OperationNotInitialized \li SessionClosed \li SessionHandleInvalid
      * @return true on success, false otherwise
      */
      bool C_EncryptUpdate(SessionHandle session,
                           const Byte* part_ptr,
                           Ulong part_len,
                           Byte* encrypted_part_ptr,
                           Ulong* encrypted_part_len_ptr,
                           ReturnValue* return_value = ThrowException) const;

      /**
      * C_EncryptFinal finishes a multiple-part encryption operation.
      * @param session session handle
      * @param last_encrypted_part_ptr last c-text
      * @param last_encrypted_part_len_ptr gets last size
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li DataLenRange \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionCanceled \li FunctionFailed
      *     \li GeneralError \li HostMemory \li OK
      *     \li OperationNotInitialized \li SessionClosed \li SessionHandleInvalid
      * @return true on success, false otherwise
      */
      bool C_EncryptFinal(SessionHandle session,
                          Byte* last_encrypted_part_ptr,
                          Ulong* last_encrypted_part_len_ptr,
                          ReturnValue* return_value = ThrowException) const;

      /*********************** Message-based encryption functions ***********************/

      /**
       * C_MessageEncryptInit prepares a session for one or more encryption
       * operations that use the same encryption mechanism and
       * encryption key.
       *
       * @param session the session's handle
       * @param mechanism_ptr the encryption mechanism
       * @param key handle of encryption key
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_MessageEncryptInit(SessionHandle session,
                                const Mechanism* mechanism_ptr,
                                ObjectHandle key,
                                ReturnValue* return_value = ThrowException);

      /**
       * C_EncryptMessage encrypts a message in a single part.
       *
       * @param session the session's handle
       * @param parameter_ptr message specific parameter
       * @param parameter_len length of message specific parameter
       * @param associated_data_ptr AEAD Associated data
       * @param associated_data_len AEAD Associated data length
       * @param plaintext_ptr plain text
       * @param plaintext_len plain text length
       * @param ciphertext_ptr gets cipher text
       * @param ciphertext_len_ptr gets cipher text length
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_EncryptMessage(SessionHandle session,
                            const void* parameter_ptr,
                            Ulong parameter_len,
                            const Byte* associated_data_ptr,
                            Ulong associated_data_len,
                            const Byte* plaintext_ptr,
                            Ulong plaintext_len,
                            Byte* ciphertext_ptr,
                            Ulong* ciphertext_len_ptr,
                            ReturnValue* return_value = ThrowException);

      /**
       * C_EncryptMessageBegin begins a multiple-part message encryption operation.
       *
       * @param session the session's handle
       * @param parameter_ptr message specific parameter
       * @param parameter_len length of message specific parameter
       * @param associated_data_ptr AEAD Associated data
       * @param associated_data_len AEAD Associated data length
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_EncryptMessageBegin(SessionHandle session,
                                 const void* parameter_ptr,
                                 Ulong parameter_len,
                                 const Byte* associated_data_ptr,
                                 Ulong associated_data_len,
                                 ReturnValue* return_value = ThrowException);

      /**
       * C_EncryptMessageNext continues a multiple-part message encryption operation,
       * processing another message part.
       *
       * @param session the session's handle
       * @param parameter_ptr message specific parameter
       * @param parameter_len length of message specific parameter
       * @param plaintext_part_ptr plain text
       * @param plaintext_part_len plain text length
       * @param ciphertext_ptr gets cipher text
       * @param ciphertext_part_len_ptr gets cipher text length
       * @param flags multi mode flag
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_EncryptMessageNext(SessionHandle session,
                                const void* parameter_ptr,
                                Ulong parameter_len,
                                const Byte* plaintext_part_ptr,
                                Ulong plaintext_part_len,
                                Byte* ciphertext_ptr,
                                Ulong* ciphertext_part_len_ptr,
                                Flags flags,
                                ReturnValue* return_value = ThrowException);

      /**
       * C_MessageDecryptFinal finishes a message-based decryption process.
       *
       * @param session the session's handle
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_MessageEncryptFinal(SessionHandle session, ReturnValue* return_value = ThrowException);

      /****************************** Decryption functions ******************************/

      /**
      * C_DecryptInit initializes a decryption operation.
      * @param session the session's handle
      * @param mechanism_ptr the decryption mechanism
      * @param key handle of decryption key
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li KeyFunctionNotPermitted \li KeyHandleInvalid \li KeySizeRange
      *     \li KeyTypeInconsistent \li MechanismInvalid \li MechanismParamInvalid
      *     \li OK \li OperationActive \li PinExpired
      *     \li SessionClosed \li SessionHandleInvalid \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_DecryptInit(SessionHandle session,
                         const Mechanism* mechanism_ptr,
                         ObjectHandle key,
                         ReturnValue* return_value = ThrowException) const;

      /**
      * C_Decrypt decrypts encrypted data in a single part.
      * @param session session's handle
      * @param encrypted_data_ptr ciphertext
      * @param encrypted_data_len ciphertext length
      * @param data_ptr gets plaintext
      * @param data_len_ptr gets p-text size
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li DeviceError \li DeviceMemory \li DeviceRemoved
      *     \li EncryptedDataInvalid \li EncryptedDataLenRange \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li OK \li OperationNotInitialized \li SessionClosed
      *     \li SessionHandleInvalid \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_Decrypt(SessionHandle session,
                     const Byte* encrypted_data_ptr,
                     Ulong encrypted_data_len,
                     Byte* data_ptr,
                     Ulong* data_len_ptr,
                     ReturnValue* return_value = ThrowException) const;

      /**
      * C_Decrypt decrypts encrypted data in a single part.
      * @param session session's handle
      * @param encrypted_data ciphertext
      * @param decrypted_data gets plaintext
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li DeviceError \li DeviceMemory \li DeviceRemoved
      *     \li EncryptedDataInvalid \li EncryptedDataLenRange \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li OK \li OperationNotInitialized \li SessionClosed
      *     \li SessionHandleInvalid \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      template <typename TAllocA, typename TAllocB>
      bool C_Decrypt(SessionHandle session,
                     const std::vector<uint8_t, TAllocA>& encrypted_data,
                     std::vector<uint8_t, TAllocB>& decrypted_data,
                     ReturnValue* return_value = ThrowException) const {
         Ulong decrypted_size = 0;
         if(!C_Decrypt(session,
                       const_cast<Byte*>((encrypted_data.data())),
                       static_cast<Ulong>(encrypted_data.size()),
                       nullptr,
                       &decrypted_size,
                       return_value)) {
            return false;
         }

         decrypted_data.resize(decrypted_size);
         if(!C_Decrypt(session,
                       const_cast<Byte*>(encrypted_data.data()),
                       static_cast<Ulong>(encrypted_data.size()),
                       decrypted_data.data(),
                       &decrypted_size,
                       return_value)) {
            return false;
         }
         decrypted_data.resize(decrypted_size);
         return true;
      }

      /**
      * C_DecryptUpdate continues a multiple-part decryption operation.
      * @param session session's handle
      * @param encrypted_part_ptr encrypted data
      * @param encrypted_part_len input length
      * @param part_ptr gets plaintext
      * @param part_len_ptr p-text size
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li DeviceError \li DeviceMemory \li DeviceRemoved
      *     \li EncryptedDataInvalid \li EncryptedDataLenRange \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li OK \li OperationNotInitialized \li SessionClosed
      *     \li SessionHandleInvalid \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_DecryptUpdate(SessionHandle session,
                           const Byte* encrypted_part_ptr,
                           Ulong encrypted_part_len,
                           Byte* part_ptr,
                           Ulong* part_len_ptr,
                           ReturnValue* return_value = ThrowException) const;

      /**
      * C_DecryptFinal finishes a multiple-part decryption operation.
      * @param session the session's handle
      * @param last_part_ptr gets plaintext
      * @param last_part_len_ptr p-text size
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li DeviceError \li DeviceMemory \li DeviceRemoved
      *     \li EncryptedDataInvalid \li EncryptedDataLenRange \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li OK \li OperationNotInitialized \li SessionClosed
      *     \li SessionHandleInvalid \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_DecryptFinal(SessionHandle session,
                          Byte* last_part_ptr,
                          Ulong* last_part_len_ptr,
                          ReturnValue* return_value = ThrowException) const;

      /*********************** Message-based decryption functions ***********************/

      /**
       * C_MessageDecryptInit initializes a message-based decryption process,
       * preparing a session for one or more decryption operations that use the
       * same decryption mechanism and decryption key.
       *
       * @param session the session's handle
       * @param mechanism_ptr the decryption mechanism
       * @param key handle of decryption key
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_MessageDecryptInit(SessionHandle session,
                                const Mechanism* mechanism_ptr,
                                ObjectHandle key,
                                ReturnValue* return_value = ThrowException);

      /**
       * C_DecryptMessage decrypts an encrypted message in a single part.
       *
       * @param session the session's handle
       * @param parameter_ptr message specific parameter
       * @param parameter_len length of message specific parameter
       * @param associated_data_ptr AEAD Associated data
       * @param associated_data_len AEAD Associated data length
       * @param ciphertext_ptr cipher text
       * @param ciphertext_len cipher text length
       * @param plaintext_ptr gets plain text
       * @param plaintext_len_ptr gets plain text length
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_DecryptMessage(SessionHandle session,
                            const void* parameter_ptr,
                            Ulong parameter_len,
                            const Byte* associated_data_ptr,
                            Ulong associated_data_len,
                            const Byte* ciphertext_ptr,
                            Ulong ciphertext_len,
                            Byte* plaintext_ptr,
                            Ulong* plaintext_len_ptr,
                            ReturnValue* return_value = ThrowException);

      /**
       * C_DecryptMessageBegin begins a multiple-part message decryption operation.
       *
       * @param session the session's handle
       * @param parameter_ptr message specific parameter
       * @param parameter_len length of message specific parameter
       * @param associated_data_ptr AEAD Associated data
       * @param associated_data_len AEAD Associated data length
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_DecryptMessageBegin(SessionHandle session,
                                 const void* parameter_ptr,
                                 Ulong parameter_len,
                                 const Byte* associated_data_ptr,
                                 Ulong associated_data_len,
                                 ReturnValue* return_value = ThrowException);

      /**
       * C_DecryptMessageNext continues a multiple-part message decryption operation,
       * processing another encrypted message part.
       *
       * @param session the session's handle
       * @param parameter_ptr message specific parameter
       * @param parameter_len length of message specific parameter
       * @param ciphertext_part_ptr cipher text
       * @param ciphertext_part_len cipher text length
       * @param plaintext_ptr gets plain text
       * @param plaintext_part_len_ptr gets plain text length
       * @param flags multi mode flag
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_DecryptMessageNext(SessionHandle session,
                                const void* parameter_ptr,
                                Ulong parameter_len,
                                const Byte* ciphertext_part_ptr,
                                Ulong ciphertext_part_len,
                                Byte* plaintext_ptr,
                                Ulong* plaintext_part_len_ptr,
                                Flags flags,
                                ReturnValue* return_value = ThrowException);

      /**
       * C_MessageDecryptFinal finishes a message-based decryption process.
       *
       * @param session the session's handle
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_MessageDecryptFinal(SessionHandle session, ReturnValue* return_value = ThrowException);

      /****************************** Message digesting functions ******************************/

      /**
      * C_DigestInit initializes a message-digesting operation.
      * @param session the session's handle
      * @param mechanism_ptr the digesting mechanism
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li MechanismInvalid \li MechanismParamInvalid \li OK
      *     \li OperationActive \li PinExpired \li SessionClosed
      *     \li SessionHandleInvalid \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_DigestInit(SessionHandle session,
                        const Mechanism* mechanism_ptr,
                        ReturnValue* return_value = ThrowException) const;

      /**
      * C_Digest digests data in a single part.
      * @param session the session's handle
      * @param data_ptr data to be digested
      * @param data_len bytes of data to digest
      * @param digest_ptr gets the message digest
      * @param digest_len_ptr gets digest length
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li DeviceError \li DeviceMemory \li DeviceRemoved
      *     \li FunctionCanceled \li FunctionFailed \li GeneralError
      *     \li HostMemory \li OK \li OperationNotInitialized
      *     \li SessionClosed \li SessionHandleInvalid
      * @return true on success, false otherwise
      */
      bool C_Digest(SessionHandle session,
                    const Byte* data_ptr,
                    Ulong data_len,
                    Byte* digest_ptr,
                    Ulong* digest_len_ptr,
                    ReturnValue* return_value = ThrowException) const;

      /**
      * C_DigestUpdate continues a multiple-part message-digesting operation.
      * @param session the session's handle
      * @param part_ptr data to be digested
      * @param part_len bytes of data to be digested
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li OK \li OperationNotInitialized \li SessionClosed
      *     \li SessionHandleInvalid
      * @return true on success, false otherwise
      */
      bool C_DigestUpdate(SessionHandle session,
                          const Byte* part_ptr,
                          Ulong part_len,
                          ReturnValue* return_value = ThrowException) const;

      /**
      * C_DigestKey continues a multi-part message-digesting operation, by digesting the value of a secret key as part of the data already digested.
      * @param session the session's handle
      * @param key secret key to digest
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li CryptokiNotInitialized \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionCanceled \li FunctionFailed
      *     \li GeneralError \li HostMemory \li KeyHandleInvalid
      *     \li KeyIndigestible \li KeySizeRange \li OK
      *     \li OperationNotInitialized \li SessionClosed \li SessionHandleInvalid
      * @return true on success, false otherwise
      */
      bool C_DigestKey(SessionHandle session, ObjectHandle key, ReturnValue* return_value = ThrowException) const;

      /**
      * C_DigestFinal finishes a multiple-part message-digesting operation.
      * @param session the session's handle
      * @param digest_ptr gets the message digest
      * @param digest_len_ptr gets uint8_t count of digest
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li DeviceError \li DeviceMemory \li DeviceRemoved
      *     \li FunctionCanceled \li FunctionFailed \li GeneralError
      *     \li HostMemory \li OK \li OperationNotInitialized
      *     \li SessionClosed \li SessionHandleInvalid
      * @return true on success, false otherwise
      */
      bool C_DigestFinal(SessionHandle session,
                         Byte* digest_ptr,
                         Ulong* digest_len_ptr,
                         ReturnValue* return_value = ThrowException) const;

      /****************************** Signing and MACing functions ******************************/

      /**
      * C_SignInit initializes a signature (private key encryption) operation, where the signature is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.
      * @param session the session's handle
      * @param mechanism_ptr the signature mechanism
      * @param key handle of signature key
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li KeyFunctionNotPermitted \li KeyHandleInvalid \li KeySizeRange
      *     \li KeyTypeInconsistent \li MechanismInvalid \li MechanismParamInvalid
      *     \li OK \li OperationActive \li PinExpired
      *     \li SessionClosed \li SessionHandleInvalid \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_SignInit(SessionHandle session,
                      const Mechanism* mechanism_ptr,
                      ObjectHandle key,
                      ReturnValue* return_value = ThrowException) const;

      /**
      * C_Sign signs (encrypts with private key) data in a single part, where the signature is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.
      * @param session the session's handle
      * @param data_ptr the data to sign
      * @param data_len count of bytes to sign
      * @param signature_ptr gets the signature
      * @param signature_len_ptr gets signature length
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li DataInvalid \li DataLenRange \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li OK \li OperationNotInitialized \li SessionClosed
      *     \li SessionHandleInvalid \li UserNotLoggedIn \li FunctionRejected
      * @return true on success, false otherwise
      */
      bool C_Sign(SessionHandle session,
                  const Byte* data_ptr,
                  Ulong data_len,
                  Byte* signature_ptr,
                  Ulong* signature_len_ptr,
                  ReturnValue* return_value = ThrowException) const;

      /**
      * C_Sign signs (encrypts with private key) data in a single part, where the signature is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.
      * @param session the session's handle
      * @param data the data to sign
      * @param signature gets the signature
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li DataInvalid \li DataLenRange \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li OK \li OperationNotInitialized \li SessionClosed
      *     \li SessionHandleInvalid \li UserNotLoggedIn \li FunctionRejected
      * @return true on success, false otherwise
      */
      template <typename TAllocA, typename TAllocB>
      bool C_Sign(SessionHandle session,
                  const std::vector<uint8_t, TAllocA>& data,
                  std::vector<uint8_t, TAllocB>& signature,
                  ReturnValue* return_value = ThrowException) const {
         Ulong signature_size = 0;
         if(!C_Sign(session, data.data(), static_cast<Ulong>(data.size()), nullptr, &signature_size, return_value)) {
            return false;
         }

         signature.resize(signature_size);
         if(!C_Sign(session,
                    data.data(),
                    static_cast<Ulong>(data.size()),
                    signature.data(),
                    &signature_size,
                    return_value)) {
            return false;
         }
         signature.resize(signature_size);
         return true;
      }

      /**
      * C_SignUpdate continues a multiple-part signature operation, where the signature is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.
      * @param session the session's handle
      * @param part_ptr the data to sign
      * @param part_len count of bytes to sign
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li DataLenRange
      *     \li DeviceError \li DeviceMemory \li DeviceRemoved
      *     \li FunctionCanceled \li FunctionFailed \li GeneralError
      *     \li HostMemory \li OK \li OperationNotInitialized
      *     \li SessionClosed \li SessionHandleInvalid \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_SignUpdate(SessionHandle session,
                        const Byte* part_ptr,
                        Ulong part_len,
                        ReturnValue* return_value = ThrowException) const;

      /**
      * C_SignUpdate continues a multiple-part signature operation, where the signature is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.
      * @param session the session's handle
      * @param part the data to sign
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li DataLenRange
      *     \li DeviceError \li DeviceMemory \li DeviceRemoved
      *     \li FunctionCanceled \li FunctionFailed \li GeneralError
      *     \li HostMemory \li OK \li OperationNotInitialized
      *     \li SessionClosed \li SessionHandleInvalid \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      template <typename TAlloc>
      bool C_SignUpdate(SessionHandle session,
                        const std::vector<uint8_t, TAlloc>& part,
                        ReturnValue* return_value = ThrowException) const {
         return C_SignUpdate(session, part.data(), static_cast<Ulong>(part.size()), return_value);
      }

      /**
      * C_SignFinal finishes a multiple-part signature operation, returning the signature.
      * @param session the session's handle
      * @param signature_ptr gets the signature
      * @param signature_len_ptr gets signature length
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li DataLenRange \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionCanceled \li FunctionFailed
      *     \li GeneralError \li HostMemory \li OK
      *     \li OperationNotInitialized \li SessionClosed \li SessionHandleInvalid
      *     \li UserNotLoggedIn \li FunctionRejected
      * @return true on success, false otherwise
      */
      bool C_SignFinal(SessionHandle session,
                       Byte* signature_ptr,
                       Ulong* signature_len_ptr,
                       ReturnValue* return_value = ThrowException) const;

      /**
      * C_SignFinal finishes a multiple-part signature operation, returning the signature.
      * @param session the session's handle
      * @param signature gets the signature
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li DataLenRange \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionCanceled \li FunctionFailed
      *     \li GeneralError \li HostMemory \li OK
      *     \li OperationNotInitialized \li SessionClosed \li SessionHandleInvalid
      *     \li UserNotLoggedIn \li FunctionRejected
      * @return true on success, false otherwise
      */
      template <typename TAlloc>
      bool C_SignFinal(SessionHandle session,
                       std::vector<uint8_t, TAlloc>& signature,
                       ReturnValue* return_value = ThrowException) const {
         Ulong signature_size = 0;
         if(!C_SignFinal(session, nullptr, &signature_size, return_value)) {
            return false;
         }

         signature.resize(signature_size);
         if(!C_SignFinal(session, signature.data(), &signature_size, return_value)) {
            return false;
         }
         signature.resize(signature_size);
         return true;
      }

      /**
      * C_SignRecoverInit initializes a signature operation, where the data can be recovered from the signature.
      * @param session the session's handle
      * @param mechanism_ptr the signature mechanism
      * @param key handle of the signature key
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li KeyFunctionNotPermitted \li KeyHandleInvalid \li KeySizeRange
      *     \li KeyTypeInconsistent \li MechanismInvalid \li MechanismParamInvalid
      *     \li OK \li OperationActive \li PinExpired
      *     \li SessionClosed \li SessionHandleInvalid \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_SignRecoverInit(SessionHandle session,
                             const Mechanism* mechanism_ptr,
                             ObjectHandle key,
                             ReturnValue* return_value = ThrowException) const;

      /**
      * C_SignRecover signs data in a single operation, where the data can be recovered from the signature.
      * @param session the session's handle
      * @param data_ptr the data to sign
      * @param data_len count of bytes to sign
      * @param signature_ptr gets the signature
      * @param signature_len_ptr gets signature length
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li DataInvalid \li DataLenRange \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li OK \li OperationNotInitialized \li SessionClosed
      *     \li SessionHandleInvalid \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_SignRecover(SessionHandle session,
                         const Byte* data_ptr,
                         Ulong data_len,
                         Byte* signature_ptr,
                         Ulong* signature_len_ptr,
                         ReturnValue* return_value = ThrowException) const;

      /******************* Message-based signing and MACing functions *******************/

      /**
       * C_MessageSignInit initializes a message-based signature process, preparing a
       * session for one or more signature operations (where the signature is an
       * appendix to the data) that use the same signature mechanism and
       * signature key.
       *
       * @param session the session's handle
       * @param mechanism_ptr the signing mechanism
       * @param key handle of signing key
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_MessageSignInit(SessionHandle session,
                             const Mechanism* mechanism_ptr,
                             ObjectHandle key,
                             ReturnValue* return_value = ThrowException);

      /**
       * C_SignMessage signs a message in a single part, where the signature is an
       * appendix to the message. C_MessageSignInit must previously been called
       * on the session.
       *
       * @param session the session's handle
       * @param parameter_ptr message specific parameter
       * @param parameter_len length of message specific parameter
       * @param data_ptr data to sign
       * @param data_len data to sign length
       * @param signature_ptr gets signature
       * @param signature_len_ptr gets signature length
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_SignMessage(SessionHandle session,
                         const void* parameter_ptr,
                         Ulong parameter_len,
                         const Byte* data_ptr,
                         Ulong data_len,
                         Byte* signature_ptr,
                         Ulong* signature_len_ptr,
                         ReturnValue* return_value = ThrowException);

      /**
       * C_SignMessageBegin begins a multiple-part message signature operation, where
       * the signature is an appendix to the message. C_MessageSignInit must
       * previously been called on the session.
       *
       * @param session the session's handle
       * @param parameter_ptr message specific parameter
       * @param parameter_len length of message specific parameter
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_SignMessageBegin(SessionHandle session,
                              const void* parameter_ptr,
                              Ulong parameter_len,
                              ReturnValue* return_value = ThrowException);

      /**
       * C_SignMessageNext continues a multiple-part message signature operation,
       * processing another data part, or finishes a multiple-part message
       * signature operation, returning the signature.
       *
       * @param session the session's handle
       * @param parameter_ptr message specific parameter
       * @param parameter_len length of message specific parameter
       * @param data_ptr data to sign
       * @param data_len data to sign length
       * @param signature_ptr gets signature
       * @param signature_len_ptr gets signature length
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_SignMessageNext(SessionHandle session,
                             const void* parameter_ptr,
                             Ulong parameter_len,
                             const Byte* data_ptr,
                             Ulong data_len,
                             Byte* signature_ptr,
                             Ulong* signature_len_ptr,
                             ReturnValue* return_value = ThrowException);

      /**
       * C_MessageSignFinal finishes a message-based signing process.
       *
       * @param session the session's handle
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_MessageSignFinal(SessionHandle session, ReturnValue* return_value = ThrowException);

      /****************************** Functions for verifying signatures and MACs ******************************/

      /**
      * C_VerifyInit initializes a verification operation, where the signature is an appendix to the data, and plaintext cannot be recovered from the signature (e.g. DSA).
      * @param session the session's handle
      * @param mechanism_ptr the verification mechanism
      * @param key verification key
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li KeyFunctionNotPermitted \li KeyHandleInvalid \li KeySizeRange
      *     \li KeyTypeInconsistent \li MechanismInvalid \li MechanismParamInvalid
      *     \li OK \li OperationActive \li PinExpired
      *     \li SessionClosed \li SessionHandleInvalid \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_VerifyInit(SessionHandle session,
                        const Mechanism* mechanism_ptr,
                        ObjectHandle key,
                        ReturnValue* return_value = ThrowException) const;

      /**
      * C_Verify verifies a signature in a single-part operation, where the signature is an appendix to the data, and plaintext cannot be recovered from the signature.
      * @param session the session's handle
      * @param data_ptr signed data
      * @param data_len length of signed data
      * @param signature_ptr signature
      * @param signature_len signature length
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li DataInvalid
      *     \li DataLenRange \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionCanceled \li FunctionFailed
      *     \li GeneralError \li HostMemory \li OK
      *     \li OperationNotInitialized \li SessionClosed \li SessionHandleInvalid
      *     \li SignatureInvalid \li SignatureLenRange
      * @return true on success, false otherwise
      */
      bool C_Verify(SessionHandle session,
                    const Byte* data_ptr,
                    Ulong data_len,
                    const Byte* signature_ptr,
                    Ulong signature_len,
                    ReturnValue* return_value = ThrowException) const;

      /**
      * C_Verify verifies a signature in a single-part operation, where the signature is an appendix to the data, and plaintext cannot be recovered from the signature.
      * @param session the session's handle
      * @param data signed data
      * @param signature signature
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li DataInvalid
      *     \li DataLenRange \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionCanceled \li FunctionFailed
      *     \li GeneralError \li HostMemory \li OK
      *     \li OperationNotInitialized \li SessionClosed \li SessionHandleInvalid
      *     \li SignatureInvalid \li SignatureLenRange
      * @return true on success, false otherwise
      */
      template <typename TAllocA, typename TAllocB>
      bool C_Verify(SessionHandle session,
                    const std::vector<uint8_t, TAllocA>& data,
                    std::vector<uint8_t, TAllocB>& signature,
                    ReturnValue* return_value = ThrowException) const {
         return C_Verify(session,
                         data.data(),
                         static_cast<Ulong>(data.size()),
                         signature.data(),
                         static_cast<Ulong>(signature.size()),
                         return_value);
      }

      /**
      * C_VerifyUpdate continues a multiple-part verification operation, where the signature is an appendix to the data, and plaintext cannot be recovered from the signature.
      * @param session the session's handle
      * @param part_ptr signed data
      * @param part_len length of signed data
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li DataLenRange
      *     \li DeviceError \li DeviceMemory \li DeviceRemoved
      *     \li FunctionCanceled \li FunctionFailed \li GeneralError
      *     \li HostMemory \li OK \li OperationNotInitialized
      *     \li SessionClosed \li SessionHandleInvalid
      * @return true on success, false otherwise
      */
      bool C_VerifyUpdate(SessionHandle session,
                          const Byte* part_ptr,
                          Ulong part_len,
                          ReturnValue* return_value = ThrowException) const;

      /**
      * C_VerifyUpdate continues a multiple-part verification operation, where the signature is an appendix to the data, and plaintext cannot be recovered from the signature.
      * @param session the session's handle
      * @param part signed data
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li DataLenRange
      *     \li DeviceError \li DeviceMemory \li DeviceRemoved
      *     \li FunctionCanceled \li FunctionFailed \li GeneralError
      *     \li HostMemory \li OK \li OperationNotInitialized
      *     \li SessionClosed \li SessionHandleInvalid
      * @return true on success, false otherwise
      */
      template <typename TAlloc>
      bool C_VerifyUpdate(SessionHandle session,
                          std::vector<uint8_t, TAlloc> part,
                          ReturnValue* return_value = ThrowException) const {
         return C_VerifyUpdate(session, part.data(), static_cast<Ulong>(part.size()), return_value);
      }

      /**
      * C_VerifyFinal finishes a multiple-part verification operation, checking the signature.
      * @param session the session's handle
      * @param signature_ptr signature to verify
      * @param signature_len signature length
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li DataLenRange
      *     \li DeviceError \li DeviceMemory \li DeviceRemoved
      *     \li FunctionCanceled \li FunctionFailed \li GeneralError
      *     \li HostMemory \li OK \li OperationNotInitialized
      *     \li SessionClosed \li SessionHandleInvalid \li SignatureInvalid
      *     \li SignatureLenRange
      * @return true on success, false otherwise
      */
      bool C_VerifyFinal(SessionHandle session,
                         const Byte* signature_ptr,
                         Ulong signature_len,
                         ReturnValue* return_value = ThrowException) const;

      /**
      * C_VerifyRecoverInit initializes a signature verification operation, where the data is recovered from the signature.
      * @param session the session's handle
      * @param mechanism_ptr the verification mechanism
      * @param key verification key
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li KeyFunctionNotPermitted \li KeyHandleInvalid \li KeySizeRange
      *     \li KeyTypeInconsistent \li MechanismInvalid \li MechanismParamInvalid
      *     \li OK \li OperationActive \li PinExpired
      *     \li SessionClosed \li SessionHandleInvalid \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_VerifyRecoverInit(SessionHandle session,
                               const Mechanism* mechanism_ptr,
                               ObjectHandle key,
                               ReturnValue* return_value = ThrowException) const;

      /**
      * C_VerifyRecover verifies a signature in a single-part operation, where the data is recovered from the signature.
      * @param session the session's handle
      * @param signature_ptr signature to verify
      * @param signature_len signature length
      * @param data_ptr gets signed data
      * @param data_len_ptr gets signed data len
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li DataInvalid \li DataLenRange \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li OK \li OperationNotInitialized \li SessionClosed
      *     \li SessionHandleInvalid \li SignatureLenRange \li SignatureInvalid
      * @return true on success, false otherwise
      */
      bool C_VerifyRecover(SessionHandle session,
                           const Byte* signature_ptr,
                           Ulong signature_len,
                           Byte* data_ptr,
                           Ulong* data_len_ptr,
                           ReturnValue* return_value = ThrowException) const;

      /**
       * C_VerifySignatureInit initializes a verification operation, where the
       * signature is included as part of the initialization.
       *
       * @param session the session's handle
       * @param mechanism_ptr the verification mechanism
       * @param key verification key
       * @param signature_ptr signature
       * @param signature_len signature length
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_VerifySignatureInit(SessionHandle session,
                                 const Mechanism* mechanism_ptr,
                                 ObjectHandle key,
                                 const Byte* signature_ptr,
                                 Ulong signature_len,
                                 ReturnValue* return_value = ThrowException);

      /**
       * C_VerifySignature verifies a signature in a single-part operation, where the
       * signature is an appendix to the data.
       *
       * @param session the session's handle
       * @param data_ptr signed data
       * @param data_len length of signed data
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_VerifySignature(SessionHandle session,
                             const Byte* data_ptr,
                             Ulong data_len,
                             ReturnValue* return_value = ThrowException);

      /**
       * C_VerifySignatureUpdate continues a multiple-part verification operation,
       * processing another data part.
       *
       * @param session the session's handle
       * @param part_ptr signed data
       * @param part_len length of signed data
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_VerifySignatureUpdate(SessionHandle session,
                                   const Byte* part_ptr,
                                   Ulong part_len,
                                   ReturnValue* return_value = ThrowException);

      /**
       * C_VerifySignatureFinal finishes a multiple-part verification operation,
       * checking the signature.
       *
       * @param session the session's handle
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_VerifySignatureFinal(SessionHandle session, ReturnValue* return_value = ThrowException);

      /*********** Message-based functions for verifying signatures and MACs ************/

      /**
       * C_MessageVerifyInit initializes a message-based verification process,
       * preparing a session for one or more verification operations (where the
       * signature is an appendix to the data) that use the same verification
       * mechanism and verification key.
       *
       * @param session the session's handle
       * @param mechanism_ptr the signing mechanism
       * @param key handle of signing key
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_MessageVerifyInit(SessionHandle session,
                               const Mechanism* mechanism_ptr,
                               ObjectHandle key,
                               ReturnValue* return_value = ThrowException);

      /**
       * C_VerifyMessage verifies a signature on a message in a single part operation,
       * where the signature is an appendix to the data. C_MessageVerifyInit must
       * previously been called on the session.
       *
       * @param session the session's handle
       * @param parameter_ptr message specific parameter
       * @param parameter_len length of message specific parameter
       * @param data_ptr data to sign
       * @param data_len data to sign length
       * @param signature_ptr signature
       * @param signature_len signature length
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_VerifyMessage(SessionHandle session,
                           const void* parameter_ptr,
                           Ulong parameter_len,
                           const Byte* data_ptr,
                           Ulong data_len,
                           const Byte* signature_ptr,
                           Ulong signature_len,
                           ReturnValue* return_value = ThrowException);

      /**
       * C_VerifyMessageBegin begins a multiple-part message verification operation,
       * where the signature is an appendix to the message. C_MessageVerifyInit
       * must previously been called on the session.
       *
       * @param session the session's handle
       * @param parameter_ptr message specific parameter
       * @param parameter_len length of message specific parameter
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_VerifyMessageBegin(SessionHandle session,
                                const void* parameter_ptr,
                                Ulong parameter_len,
                                ReturnValue* return_value = ThrowException);

      /**
       * C_VerifyMessageNext continues a multiple-part message verification operation,
       * processing another data part, or finishes a multiple-part message
       * verification operation, checking the signature.
       *
       * @param session the session's handle
       * @param parameter_ptr message specific parameter
       * @param parameter_len length of message specific parameter
       * @param data_ptr data to sign
       * @param data_len data to sign length
       * @param signature_ptr signature
       * @param signature_len signature length
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_VerifyMessageNext(SessionHandle session,
                               const void* parameter_ptr,
                               Ulong parameter_len,
                               const Byte* data_ptr,
                               Ulong data_len,
                               const Byte* signature_ptr,
                               Ulong signature_len,
                               ReturnValue* return_value = ThrowException);

      /**
       * C_MessageVerifyFinal finishes a message-based verification process.
       *
       * @param session the session's handle
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_MessageVerifyFinal(SessionHandle session, ReturnValue* return_value = ThrowException);

      /****************************** Dual-purpose cryptographic functions ******************************/

      /**
      * C_DigestEncryptUpdate continues a multiple-part digesting and encryption operation.
      * @param session session's handle
      * @param part_ptr the plaintext data
      * @param part_len plaintext length
      * @param encrypted_part_ptr gets ciphertext
      * @param encrypted_part_len_ptr gets c-text length
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li DataLenRange \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionCanceled \li FunctionFailed
      *     \li GeneralError \li HostMemory \li OK
      *     \li OperationNotInitialized \li SessionClosed \li SessionHandleInvalid
      * @return true on success, false otherwise
      */
      bool C_DigestEncryptUpdate(SessionHandle session,
                                 const Byte* part_ptr,
                                 Ulong part_len,
                                 Byte* encrypted_part_ptr,
                                 Ulong* encrypted_part_len_ptr,
                                 ReturnValue* return_value = ThrowException) const;

      /**
      * C_DecryptDigestUpdate continues a multiple-part decryption and digesting operation.
      * @param session session's handle
      * @param encrypted_part_ptr ciphertext
      * @param encrypted_part_len ciphertext length
      * @param part_ptr gets plaintext
      * @param part_len_ptr gets plaintext len
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li DeviceError \li DeviceMemory \li DeviceRemoved
      *     \li EncryptedDataInvalid \li EncryptedDataLenRange \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li OK \li OperationNotInitialized \li SessionClosed
      *     \li SessionHandleInvalid
      * @return true on success, false otherwise
      */
      bool C_DecryptDigestUpdate(SessionHandle session,
                                 const Byte* encrypted_part_ptr,
                                 Ulong encrypted_part_len,
                                 Byte* part_ptr,
                                 Ulong* part_len_ptr,
                                 ReturnValue* return_value = ThrowException) const;

      /**
      * C_SignEncryptUpdate continues a multiple-part signing and encryption operation.
      * @param session session's handle
      * @param part_ptr the plaintext data
      * @param part_len plaintext length
      * @param encrypted_part_ptr gets ciphertext
      * @param encrypted_part_len_ptr gets c-text length
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li DataLenRange \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li FunctionCanceled \li FunctionFailed
      *     \li GeneralError \li HostMemory \li OK
      *     \li OperationNotInitialized \li SessionClosed \li SessionHandleInvalid
      *     \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_SignEncryptUpdate(SessionHandle session,
                               const Byte* part_ptr,
                               Ulong part_len,
                               Byte* encrypted_part_ptr,
                               Ulong* encrypted_part_len_ptr,
                               ReturnValue* return_value = ThrowException) const;

      /**
      * C_DecryptVerifyUpdate continues a multiple-part decryption and verify operation.
      * @param session session's handle
      * @param encrypted_part_ptr ciphertext
      * @param encrypted_part_len ciphertext length
      * @param part_ptr gets plaintext
      * @param part_len_ptr gets p-text length
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li DataLenRange \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li EncryptedDataInvalid \li EncryptedDataLenRange
      *     \li FunctionCanceled \li FunctionFailed \li GeneralError
      *     \li HostMemory \li OK \li OperationNotInitialized
      *     \li SessionClosed \li SessionHandleInvalid
      * @return true on success, false otherwise
      */
      bool C_DecryptVerifyUpdate(SessionHandle session,
                                 const Byte* encrypted_part_ptr,
                                 Ulong encrypted_part_len,
                                 Byte* part_ptr,
                                 Ulong* part_len_ptr,
                                 ReturnValue* return_value = ThrowException) const;

      /****************************** Key management functions ******************************/

      /**
      * C_GenerateKey generates a secret key, creating a new key object.
      * @param session the session's handle
      * @param mechanism_ptr key generation mech.
      * @param attribute_template_ptr template for new key
      * @param count # of attrs in template
      * @param key_ptr gets handle of new key
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li AttributeReadOnly \li AttributeTypeInvalid
      *     \li AttributeValueInvalid \li CryptokiNotInitialized \li CurveNotSupported
      *     \li DeviceError \li DeviceMemory \li DeviceRemoved
      *     \li FunctionCanceled \li FunctionFailed \li GeneralError
      *     \li HostMemory \li MechanismInvalid \li MechanismParamInvalid
      *     \li OK \li OperationActive \li PinExpired
      *     \li SessionClosed \li SessionHandleInvalid \li SessionReadOnly
      *     \li TemplateIncomplete \li TemplateInconsistent \li TokenWriteProtected
      *     \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_GenerateKey(SessionHandle session,
                         const Mechanism* mechanism_ptr,
                         Attribute* attribute_template_ptr,
                         Ulong count,
                         ObjectHandle* key_ptr,
                         ReturnValue* return_value = ThrowException) const;

      /**
      * C_GenerateKeyPair generates a public-key/private-key pair, creating new key objects.
      * @param session session handle
      * @param mechanism_ptr key-gen mech.
      * @param public_key_template_ptr template for pub. key
      * @param public_key_attribute_count # pub. attrs.
      * @param private_key_template_ptr template for priv. key
      * @param private_key_attribute_count # priv.  attrs.
      * @param public_key_ptr gets pub. key handle
      * @param private_key_ptr gets priv. key handle
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li AttributeReadOnly \li AttributeTypeInvalid
      *     \li AttributeValueInvalid \li CryptokiNotInitialized \li CurveNotSupported
      *     \li DeviceError \li DeviceMemory \li DeviceRemoved
      *     \li DomainParamsInvalid \li FunctionCanceled \li FunctionFailed
      *     \li GeneralError \li HostMemory \li MechanismInvalid
      *     \li MechanismParamInvalid \li OK \li OperationActive
      *     \li PinExpired \li SessionClosed \li SessionHandleInvalid
      *     \li SessionReadOnly \li TemplateIncomplete \li TemplateInconsistent
      *     \li TokenWriteProtected \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_GenerateKeyPair(SessionHandle session,
                             const Mechanism* mechanism_ptr,
                             Attribute* public_key_template_ptr,
                             Ulong public_key_attribute_count,
                             Attribute* private_key_template_ptr,
                             Ulong private_key_attribute_count,
                             ObjectHandle* public_key_ptr,
                             ObjectHandle* private_key_ptr,
                             ReturnValue* return_value = ThrowException) const;

      /**
      * C_WrapKey wraps (i.e., encrypts) a key.
      * @param session the session's handle
      * @param mechanism_ptr the wrapping mechanism
      * @param wrapping_key wrapping key
      * @param key key to be wrapped
      * @param wrapped_key_ptr gets wrapped key
      * @param wrapped_key_len_ptr gets wrapped key size
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li BufferTooSmall \li CryptokiNotInitialized
      *     \li DeviceError \li DeviceMemory \li DeviceRemoved
      *     \li FunctionCanceled \li FunctionFailed \li GeneralError
      *     \li HostMemory \li KeyHandleInvalid \li KeyNotWrappable
      *     \li KeySizeRange \li KeyUnextractable \li MechanismInvalid
      *     \li MechanismParamInvalid \li OK \li OperationActive
      *     \li PinExpired \li SessionClosed \li SessionHandleInvalid
      *     \li UserNotLoggedIn \li WrappingKeyHandleInvalid \li WrappingKeySizeRange
      *     \li WrappingKeyTypeInconsistent
      * @return true on success, false otherwise
      */
      bool C_WrapKey(SessionHandle session,
                     const Mechanism* mechanism_ptr,
                     ObjectHandle wrapping_key,
                     ObjectHandle key,
                     Byte* wrapped_key_ptr,
                     Ulong* wrapped_key_len_ptr,
                     ReturnValue* return_value = ThrowException) const;

      /**
      * C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new key object.
      * @param session session's handle
      * @param mechanism_ptr unwrapping mech.
      * @param unwrapping_key unwrapping key
      * @param wrapped_key_ptr the wrapped key
      * @param wrapped_key_len wrapped key len
      * @param attribute_template_ptr new key template
      * @param attribute_count template length
      * @param key_ptr gets new handle
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li AttributeReadOnly \li AttributeTypeInvalid
      *     \li AttributeValueInvalid \li BufferTooSmall \li CryptokiNotInitialized
      *     \li CurveNotSupported \li DeviceError \li DeviceMemory
      *     \li DeviceRemoved \li DomainParamsInvalid \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li MechanismInvalid \li MechanismParamInvalid \li OK
      *     \li OperationActive \li PinExpired \li SessionClosed
      *     \li SessionHandleInvalid \li SessionReadOnly \li TemplateIncomplete
      *     \li TemplateInconsistent \li TokenWriteProtected \li UnwrappingKeyHandleInvalid
      *     \li UnwrappingKeySizeRange \li UnwrappingKeyTypeInconsistent \li UserNotLoggedIn
      *     \li WrappedKeyInvalid \li WrappedKeyLenRange
      * @return true on success, false otherwise
      */
      bool C_UnwrapKey(SessionHandle session,
                       const Mechanism* mechanism_ptr,
                       ObjectHandle unwrapping_key,
                       const Byte* wrapped_key_ptr,
                       Ulong wrapped_key_len,
                       Attribute* attribute_template_ptr,
                       Ulong attribute_count,
                       ObjectHandle* key_ptr,
                       ReturnValue* return_value = ThrowException) const;

      /**
      * C_DeriveKey derives a key from a base key, creating a new key object.
      * @param session session's handle
      * @param mechanism_ptr key deriv. mech.
      * @param base_key base key
      * @param attribute_template_ptr new key template
      * @param attribute_count template length
      * @param key_ptr gets new handle
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li AttributeReadOnly \li AttributeTypeInvalid
      *     \li AttributeValueInvalid \li CryptokiNotInitialized \li CurveNotSupported
      *     \li DeviceError \li DeviceMemory \li DeviceRemoved
      *     \li DomainParamsInvalid \li FunctionCanceled \li FunctionFailed
      *     \li GeneralError \li HostMemory \li KeyHandleInvalid
      *     \li KeySizeRange \li KeyTypeInconsistent \li MechanismInvalid
      *     \li MechanismParamInvalid \li OK \li OperationActive
      *     \li PinExpired \li SessionClosed \li SessionHandleInvalid
      *     \li SessionReadOnly \li TemplateIncomplete \li TemplateInconsistent
      *     \li TokenWriteProtected \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_DeriveKey(SessionHandle session,
                       const Mechanism* mechanism_ptr,
                       ObjectHandle base_key,
                       Attribute* attribute_template_ptr,
                       Ulong attribute_count,
                       ObjectHandle* key_ptr,
                       ReturnValue* return_value = ThrowException) const;

      /**
       * C_EncapulateKey creates a new secret key object from a public key using a
       * KEM.
       *
       * @param session the session's handle
       * @param mechanism_ptr the encapsulation mechanism
       * @param public_key the encapsulating key
       * @param template_ptr new key template
       * @param attribute_count template length
       * @param key_ptr the encapsulated key
       * @param ciphertext_ptr the wrapped key
       * @param ciphertext_len_ptr the wrapped key size
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_EncapsulateKey(SessionHandle session,
                            const Mechanism* mechanism_ptr,
                            ObjectHandle public_key,
                            Attribute* template_ptr,
                            Ulong attribute_count,
                            ObjectHandle* key_ptr,
                            Byte* ciphertext_ptr,
                            Ulong* ciphertext_len_ptr,
                            ReturnValue* return_value = ThrowException);

      /**
       * C_DecapsulateKey creates a new secret key object based on the private key and
       * ciphertext generated by a prior encapsulate operation. This new key
       * (called a ‘shared key’ in most KEM documentation) is identical to the
       * key returned by C_EncapsulateKey when it was called with the matching public
       * key and returned the same cipher text. This function is a KEM style
       * function.
       *
       * @param session the session's handle
       * @param mechanism_ptr the decapsulation mechanism
       * @param private_key the decapsulating key
       * @param ciphertext_ptr the wrapped key
       * @param ciphertext_len the wrapped key size
       * @param template_ptr new key template
       * @param attribute_count template length
       * @param key_ptr the decapsulated key
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_DecapsulateKey(SessionHandle session,
                            const Mechanism* mechanism_ptr,
                            ObjectHandle private_key,
                            const Byte* ciphertext_ptr,
                            Ulong ciphertext_len,
                            Attribute* template_ptr,
                            Ulong attribute_count,
                            ObjectHandle* key_ptr,
                            ReturnValue* return_value = ThrowException);

      /****************************** Random number generation functions ******************************/

      /**
      * C_SeedRandom mixes additional seed material into the token's random number generator.
      * @param session the session's handle
      * @param seed_ptr the seed material
      * @param seed_len length of seed material
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li OK \li OperationActive \li RandomSeedNotSupported
      *     \li RandomNoRng \li SessionClosed \li SessionHandleInvalid
      *     \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_SeedRandom(SessionHandle session,
                        const Byte* seed_ptr,
                        Ulong seed_len,
                        ReturnValue* return_value = ThrowException) const;

      /**
      * C_GenerateRandom generates random data.
      * @param session the session's handle
      * @param random_data_ptr receives the random data
      * @param random_len # of bytes to generate
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li ArgumentsBad \li CryptokiNotInitialized \li DeviceError
      *     \li DeviceMemory \li DeviceRemoved \li FunctionCanceled
      *     \li FunctionFailed \li GeneralError \li HostMemory
      *     \li OK \li OperationActive \li RandomNoRng
      *     \li SessionClosed \li SessionHandleInvalid \li UserNotLoggedIn
      * @return true on success, false otherwise
      */
      bool C_GenerateRandom(SessionHandle session,
                            Byte* random_data_ptr,
                            Ulong random_len,
                            ReturnValue* return_value = ThrowException) const;

      /****************************** Parallel function management functions ******************************/

      /**
      * C_GetFunctionStatus is a legacy function; it obtains an updated status of a function running in parallel with an application.
      * @param session the session's handle
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li CryptokiNotInitialized \li FunctionFailed \li FunctionNotParallel
      *     \li GeneralError \li HostMemory \li SessionHandleInvalid
      *     \li SessionClosed
      * @return true on success, false otherwise
      */
      bool C_GetFunctionStatus(SessionHandle session, ReturnValue* return_value = ThrowException) const;

      /**
      * C_CancelFunction is a legacy function; it cancels a function running in parallel.
      * @param session the session's handle
      * @param return_value default value (`ThrowException`): throw exception on error.
      * if a non-NULL pointer is passed: return_value receives the return value of the PKCS #11 function and no exception is thrown.
      * At least the following PKCS #11 return values may be returned:
      *     \li CryptokiNotInitialized \li FunctionFailed \li FunctionNotParallel
      *     \li GeneralError \li HostMemory \li SessionHandleInvalid
      *     \li SessionClosed
      * @return true on success, false otherwise
      */
      bool C_CancelFunction(SessionHandle session, ReturnValue* return_value = ThrowException) const;

      /******************* Asynchronous function management functions *******************/

      /**
       * C_AsyncComplete checks if the function identified by function_name_ptr has
       * completed an asynchronous operation and, if so, returns the associated
       * result(s).
       *
       * @param session the session's handle
       * @param function_name_ptr pkcs11 function name
       * @param result_ptr operation result
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_AsyncComplete(SessionHandle session,
                           const Utf8Char* function_name_ptr,
                           AsyncData* result_ptr,
                           ReturnValue* return_value = ThrowException);

      /**
       * C_AsyncGetID is used to persist an operation past a C_Finalize call and allow
       * another instance of the client to reconnect after a call to
       * C_Initialize. C_AsyncGetID places a module dependent identifier for
       * the asynchronous operation being performed by the function identified by
       * function_name_ptr.
       *
       * @param session the session's handle
       * @param function_name_ptr pkcs11 function name
       * @param id_ptr persistent operation id
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_AsyncGetID(SessionHandle session,
                        const Utf8Char* function_name_ptr,
                        Ulong* id_ptr,
                        ReturnValue* return_value = ThrowException);

      /**
       * C_AsyncJoin checks if the function identified by function_name_ptr and id is a
       * valid asynchronous operation and, if so, reconnects the client application to
       * the module using the buffer specified by data_ptr and data_len in place of those
       * passed into the original call to function_name_ptr.
       *
       * @param session the session's handle
       * @param function_name_ptr pkcs11 function name
       * @param id persistent operation id
       * @param data_ptr location for the data
       * @param data_len data length
       * @param return_value default value (`ThrowException`): throw exception on error
       * @return true on success, false otherwise
       */
      bool C_AsyncJoin(SessionHandle session,
                       const Utf8Char* function_name_ptr,
                       Ulong id,
                       Byte* data_ptr,
                       Ulong data_len,
                       ReturnValue* return_value = ThrowException);

      /**
      * Return the PKCS11 function list that this LowLevel class contains.
      *
      * This is primarily useful when invoking vendor specific extension
      * functions which are not supported directly by LowLevel or the higher
      * level PKCS11 API.
      */
      BOTAN_DEPRECATED("Use get_interface().func_2_40()") FunctionList* get_functions() const;

      const InterfaceWrapper& get_interface() { return *m_interface_wrapper; }

   protected:
      /**
      * it is possible for an application to inherit from LowLevel in order to
      * implement wrappers for vendor specific extensions using the same error
      * handling mechanisms as the rest of the library.
      */
      static bool handle_return_value(CK_RV function_result, ReturnValue* return_value);

   private:
      std::unique_ptr<InterfaceWrapper> m_interface_wrapper;
};

class BOTAN_PUBLIC_API(2, 0) PKCS11_Error : public Exception {
   public:
      explicit PKCS11_Error(std::string_view what) : Exception("PKCS11 error", what) {}

      ErrorType error_type() const noexcept override { return ErrorType::Pkcs11Error; }
};

class BOTAN_PUBLIC_API(2, 0) PKCS11_ReturnError final : public PKCS11_Error {
   public:
      explicit PKCS11_ReturnError(ReturnValue return_val);

      inline ReturnValue get_return_value() const { return m_return_val; }

      int error_code() const noexcept override { return static_cast<int>(m_return_val); }

   private:
      const ReturnValue m_return_val;
};

}  // namespace PKCS11

}  // namespace Botan

#endif
