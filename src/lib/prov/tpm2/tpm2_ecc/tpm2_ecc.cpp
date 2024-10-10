/*
* TPM 2.0 ECC Key Wrappres
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_ecc.h>

#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_algo_mappings.h>
#include <botan/internal/tpm2_hash.h>
#include <botan/internal/tpm2_pkops.h>
#include <botan/internal/tpm2_util.h>

#include <tss2/tss2_esys.h>

namespace Botan::TPM2 {

EC_PublicKey::EC_PublicKey(Object handle, SessionBundle sessions, const TPM2B_PUBLIC* public_blob) :
      EC_PublicKey(std::move(handle), std::move(sessions), ecc_pubkey_from_tss2_public(public_blob)) {}

EC_PublicKey::EC_PublicKey(Object handle, SessionBundle sessions, std::pair<EC_Group, EC_AffinePoint> public_key) :
      Botan::TPM2::PublicKey(std::move(handle), std::move(sessions)),
      Botan::EC_PublicKey(std::move(public_key.first), public_key.second) {}

EC_PrivateKey::EC_PrivateKey(Object handle,
                             SessionBundle sessions,
                             const TPM2B_PUBLIC* public_blob,
                             std::span<const uint8_t> private_blob) :
      EC_PrivateKey(std::move(handle), std::move(sessions), ecc_pubkey_from_tss2_public(public_blob), private_blob) {}

EC_PrivateKey::EC_PrivateKey(Object handle,
                             SessionBundle sessions,
                             std::pair<EC_Group, EC_AffinePoint> public_key,
                             std::span<const uint8_t> private_blob) :
      Botan::TPM2::PrivateKey(std::move(handle), std::move(sessions), private_blob),
      Botan::EC_PublicKey(std::move(public_key.first), public_key.second) {}

std::unique_ptr<Public_Key> EC_PrivateKey::public_key() const {
   return std::make_unique<Botan::ECDSA_PublicKey>(domain(), public_point());
}

std::vector<uint8_t> EC_PublicKey::public_key_bits() const {
   return Botan::EC_PublicKey::raw_public_key_bits();
}

std::vector<uint8_t> EC_PublicKey::raw_public_key_bits() const {
   return TPM2::PublicKey::raw_public_key_bits();
}

std::vector<uint8_t> EC_PrivateKey::public_key_bits() const {
   return Botan::EC_PublicKey::raw_public_key_bits();
}

std::vector<uint8_t> EC_PrivateKey::raw_public_key_bits() const {
   return TPM2::PrivateKey::raw_public_key_bits();
}

std::unique_ptr<TPM2::PrivateKey> EC_PrivateKey::create_unrestricted_transient(const std::shared_ptr<Context>& ctx,
                                                                               const SessionBundle& sessions,
                                                                               std::span<const uint8_t> auth_value,
                                                                               const TPM2::PrivateKey& parent,
                                                                               const EC_Group& group) {
   // TODO: Code duplication from RSA_PrivateKey::create_unrestricted_transient
   BOTAN_ARG_CHECK(parent.is_parent(), "The passed key cannot be used as a parent key");

   const auto curve_id = get_tpm2_curve_id(group.get_curve_oid());
   if(!curve_id) {
      throw Invalid_Argument("Unsupported ECC curve");
   }

   TPM2B_SENSITIVE_CREATE sensitive_data = {
      .size = 0,  // ignored
      .sensitive =
         {
            .userAuth = copy_into<TPM2B_AUTH>(auth_value),

            // Architecture Document, Section 25.2.3
            //   When an asymmetric key is created, the caller is not allowed to
            //   provide the sensitive data of the key.
            .data = init_empty<TPM2B_SENSITIVE_DATA>(),
         },
   };

   TPMT_PUBLIC key_template = {
      .type = TPM2_ALG_ECC,

      // This is the algorithm for fingerprinting the newly created public key.
      // For best compatibility we always use SHA-256.
      .nameAlg = TPM2_ALG_SHA256,

      // This sets up the key to be both a decryption and a signing key, forbids
      // its duplication (fixed_tpm, fixed_parent) and ensures that the key's
      // private portion can be used only by a user with an HMAC or password
      // session.
      .objectAttributes = ObjectAttributes::render({
         .fixed_tpm = true,
         .fixed_parent = true,
         .sensitive_data_origin = true,
         .user_with_auth = true,
         .decrypt = true,  // TODO: Shall we set this?
         .sign_encrypt = true,
      }),

      // We currently do not support policy-based authorization
      .authPolicy = init_empty<TPM2B_DIGEST>(),
      .parameters =
         {
            .eccDetail =
               {
                  // Structures Document (Part 2), Section 12.2.3.5
                  //   If the key is not a restricted decryption key, this field
                  //   shall be set to TPM_ALG_NULL.
                  //
                  // TODO: Once we stop supporting TSS < 4.0, we could use
                  //       `.keyBits = {.null = {}}, .mode = {.null = {}}`
                  //       which better reflects our intention here.
                  .symmetric =
                     {
                        .algorithm = TPM2_ALG_NULL,
                        .keyBits = {.sym = 0},
                        .mode = {.sym = TPM2_ALG_NULL},
                     },

                  // Structures Document (Part 2), Section 12.2.3.6
                  //   If the decrypt attribute of the key is SET, then this shall be a
                  // valid key exchange scheme or TPM_ALG_NULL
                  //
                  // TODO: Once we stop supporting TSS < 4.0, we could use
                  //       `.details = {.null = {}}`
                  //       which better reflects our intention here.
                  .scheme =
                     {
                        .scheme = TPM2_ALG_NULL,
                        .details = {.anySig = {.hashAlg = TPM2_ALG_NULL}},
                     },
                  .curveID = curve_id.value(),

                  // Structures Document (Part 2), Section 12.2.3.6
                  // If the kdf parameter associated with curveID is not
                  // TPM_ALG_NULL then this is required to be NULL.
                  // NOTE There are currently no commands where this parameter
                  // has effect and, in the reference code, this field needs to
                  // be set to TPM_ALG_NULL
                  // TODO: Easier initialization?
                  .kdf = {.scheme = TPM2_ALG_NULL, .details = {.kdf2 = {.hashAlg = TPM2_ALG_NULL}}},
               },
         },

      // For creating an asymmetric key this value is not used.
      .unique = {.ecc = {}},
   };

   return create_transient_from_template(
      ctx, sessions, parent.handles().transient_handle(), key_template, sensitive_data);
}

namespace {

SignatureAlgorithmSelection make_signature_scheme(std::string_view hash_name) {
   return {
      .signature_scheme =
         TPMT_SIG_SCHEME{
            .scheme = TPM2_ALG_ECDSA,  // Only support ECDSA
            .details = {.any = {.hashAlg = get_tpm2_hash_type(hash_name)}},
         },
      .hash_name = std::string(hash_name),
      .padding = std::nullopt,
   };
}

size_t signature_length_for_key_handle(const SessionBundle& sessions, const Object& object) {
   const auto curve_id = object._public_info(sessions, TPM2_ALG_ECDSA).pub->publicArea.parameters.eccDetail.curveID;

   const auto order_bytes = curve_id_order_byte_size(curve_id);
   if(!order_bytes) {
      throw Invalid_Argument(Botan::fmt("Unsupported ECC curve: {}", curve_id));
   };
   return 2 * order_bytes.value();
}

class EC_Signature_Operation final : public Signature_Operation {
   public:
      EC_Signature_Operation(const Object& object, const SessionBundle& sessions, std::string_view hash) :
            Signature_Operation(object, sessions, make_signature_scheme(hash)) {}

      size_t signature_length() const override { return signature_length_for_key_handle(sessions(), key_handle()); }

      AlgorithmIdentifier algorithm_identifier() const override {
         // Copied from ECDSA
         const std::string full_name = "ECDSA/" + hash_function();
         const OID oid = OID::from_string(full_name);
         return AlgorithmIdentifier(oid, AlgorithmIdentifier::USE_EMPTY_PARAM);
      }

   private:
      std::vector<uint8_t> marshal_signature(const TPMT_SIGNATURE& signature) const override {
         BOTAN_STATE_CHECK(signature.sigAlg == TPM2_ALG_ECDSA);

         const auto r = as_span(signature.signature.ecdsa.signatureR);
         const auto s = as_span(signature.signature.ecdsa.signatureS);
         const auto sig_len = signature_length_for_key_handle(sessions(), key_handle());
         BOTAN_ASSERT_NOMSG(sig_len % 2 == 0);
         BOTAN_ASSERT_NOMSG(r.size() == sig_len / 2 && s.size() == sig_len / 2);

         return concat<std::vector<uint8_t>>(r, s);
      }
};

class EC_Verification_Operation final : public Verification_Operation {
   public:
      EC_Verification_Operation(const Object& object, const SessionBundle& sessions, std::string_view hash) :
            Verification_Operation(object, sessions, make_signature_scheme(hash)) {}

   private:
      TPMT_SIGNATURE unmarshal_signature(std::span<const uint8_t> sig_data) const override {
         BOTAN_STATE_CHECK(scheme().scheme == TPM2_ALG_ECDSA);

         const auto sig_len = signature_length_for_key_handle(sessions(), key_handle());
         BOTAN_ARG_CHECK(sig_data.size() == sig_len, "Invalid signature length");
         BOTAN_ASSERT_NOMSG(sig_len % 2 == 0);

         return {
            .sigAlg = TPM2_ALG_ECDSA,
            .signature =
               {
                  .ecdsa =
                     {
                        .hash = scheme().details.any.hashAlg,
                        .signatureR = copy_into<TPM2B_ECC_PARAMETER>(sig_data.first(sig_len / 2)),
                        .signatureS = copy_into<TPM2B_ECC_PARAMETER>(sig_data.last(sig_len / 2)),
                     },
               },
         };
      }
};

}  // namespace

std::unique_ptr<PK_Ops::Verification> EC_PublicKey::create_verification_op(std::string_view params,
                                                                           std::string_view provider) const {
   BOTAN_UNUSED(provider);
   return std::make_unique<EC_Verification_Operation>(handles(), sessions(), params);
}

std::unique_ptr<PK_Ops::Signature> EC_PrivateKey::create_signature_op(Botan::RandomNumberGenerator& rng,
                                                                      std::string_view params,
                                                                      std::string_view provider) const {
   BOTAN_UNUSED(rng, provider);
   return std::make_unique<EC_Signature_Operation>(handles(), sessions(), params);
}

}  // namespace Botan::TPM2
