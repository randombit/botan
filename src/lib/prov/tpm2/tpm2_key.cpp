/*
* TPM 2.0 Key Wrappers' Base Class
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_key.h>

#if defined(BOTAN_HAS_TPM2_RSA_ADAPTER)
   #include <botan/tpm2_rsa.h>
#endif
#if defined(BOTAN_HAS_TPM2_ECC_ADAPTER)
   #include <botan/tpm2_ecc.h>
#endif

#include <botan/internal/fmt.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_algo_mappings.h>
#include <botan/internal/tpm2_hash.h>
#include <botan/internal/tpm2_util.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

namespace Botan::TPM2 {

#if defined(BOTAN_HAS_RSA)
Botan::RSA_PublicKey rsa_pubkey_from_tss2_public(const TPM2B_PUBLIC* public_area) {
   // TODO: this RSA_PublicKey currently takes const-refs, so we cannot benefit
   //       from moving them in place. This should be fixed in the future.
   return std::apply([](const BigInt& n, const BigInt& e) { return Botan::RSA_PublicKey(n, e); },
                     rsa_pubkey_components_from_tss2_public(public_area));
}
#endif

#if defined(BOTAN_HAS_ECC_GROUP)
std::pair<EC_Group, EC_AffinePoint> ecc_pubkey_from_tss2_public(const TPM2B_PUBLIC* public_blob) {
   BOTAN_ASSERT_NONNULL(public_blob);
   BOTAN_ARG_CHECK(public_blob->publicArea.type == TPM2_ALG_ECC, "Public blob is not an ECC key");

   const auto curve_id = public_blob->publicArea.parameters.eccDetail.curveID;
   const auto curve_name = curve_id_tss2_to_botan(curve_id);
   if(!curve_name) {
      throw Invalid_Argument(Botan::fmt("Unsupported ECC curve: {}", curve_id));
   }

   auto curve = Botan::EC_Group::from_name(curve_name.value());
   // Create an EC_AffinePoint from the x and y coordinates as SEC1 uncompressed point.
   // According to the TPM2.0 specification Part 1 C.8, each coordinate is already padded to the curve's size.
   auto point = EC_AffinePoint::deserialize(curve,
                                            concat(std::vector<uint8_t>({0x04}),
                                                   as_span(public_blob->publicArea.unique.ecc.x),
                                                   as_span(public_blob->publicArea.unique.ecc.y)));
   if(!point) {
      throw Invalid_Argument("Invalid ECC Point");
   }
   return {std::move(curve), std::move(point.value())};
}
#endif

namespace {

Object load_persistent_object(const std::shared_ptr<Context>& ctx,
                              TPM2_HANDLE persistent_object_handle,
                              std::span<const uint8_t> auth_value,
                              const SessionBundle& sessions) {
   BOTAN_ARG_CHECK(
      TPM2_PERSISTENT_FIRST <= persistent_object_handle && persistent_object_handle <= TPM2_PERSISTENT_LAST,
      "persistent_object_handle out of range");
   BOTAN_ASSERT_NONNULL(ctx);
   const bool is_persistent = value_exists(ctx->persistent_handles(), persistent_object_handle);
   BOTAN_STATE_CHECK(is_persistent);

   Object object(ctx);

   check_rc("Esys_TR_FromTPMPublic",
            Esys_TR_FromTPMPublic(
               *ctx, persistent_object_handle, sessions[0], sessions[1], sessions[2], out_transient_handle(object)));

   if(!auth_value.empty()) {
      const auto user_auth = copy_into<TPM2B_AUTH>(auth_value);
      check_rc("Esys_TR_SetAuth", Esys_TR_SetAuth(*ctx, object.transient_handle(), &user_auth));
   }

   check_rc("Esys_TR_GetTpmHandle",
            Esys_TR_GetTpmHandle(*ctx, object.transient_handle(), out_persistent_handle(object)));

   const auto key_type = object._public_info(sessions).pub->publicArea.type;
   BOTAN_ARG_CHECK(key_type == TPM2_ALG_RSA || key_type == TPM2_ALG_ECC,
                   "persistent object is neither RSA nor ECC public key");

   return object;
}

std::vector<uint8_t> marshal_public_blob(const TPM2B_PUBLIC* public_data) {
   size_t bytes_required = 0;
   std::vector<uint8_t> marshalled_blob(sizeof(TPM2B_PUBLIC));
   check_rc("Tss2_MU_TPM2B_PUBLIC_Marshal",
            Tss2_MU_TPM2B_PUBLIC_Marshal(public_data, marshalled_blob.data(), marshalled_blob.size(), &bytes_required));
   marshalled_blob.resize(bytes_required);
   marshalled_blob.shrink_to_fit();
   return marshalled_blob;
}

TPM2B_PUBLIC unmarshal_public_blob(std::span<const uint8_t> marshalled_blob) {
   TPM2B_PUBLIC public_data{};
   size_t offset = 0;
   check_rc("Tss2_MU_TPM2B_PUBLIC_Unmarshal",
            Tss2_MU_TPM2B_PUBLIC_Unmarshal(marshalled_blob.data(), marshalled_blob.size(), &offset, &public_data));
   BOTAN_ASSERT_NOMSG(offset == marshalled_blob.size());
   return public_data;
}

TPM2B_TEMPLATE marshal_template(const TPMT_PUBLIC& key_template) {
   TPM2B_TEMPLATE result = {};
   size_t offset = 0;
   check_rc("Tss2_MU_TPMT_PUBLIC_Marshal",
            Tss2_MU_TPMT_PUBLIC_Marshal(&key_template, result.buffer, sizeof(TPMT_PUBLIC), &offset));
   BOTAN_ASSERT_NOMSG(offset <= sizeof(result.buffer));
   result.size = static_cast<uint16_t>(offset);
   return result;
}

}  // namespace

std::unique_ptr<PublicKey> PublicKey::load_persistent(const std::shared_ptr<Context>& ctx,
                                                      TPM2_HANDLE persistent_object_handle,
                                                      const SessionBundle& sessions) {
   return create(load_persistent_object(ctx, persistent_object_handle, {}, sessions), sessions);
}

std::unique_ptr<PublicKey> PublicKey::load_transient(const std::shared_ptr<Context>& ctx,
                                                     std::span<const uint8_t> public_blob,
                                                     const SessionBundle& sessions) {
   const auto public_data = unmarshal_public_blob(public_blob);

   BOTAN_ASSERT_NONNULL(ctx);

   Object handle(ctx);
   check_rc("Esys_LoadExternal",
            Esys_LoadExternal(*ctx,
                              sessions[0],
                              sessions[1],
                              sessions[2],
                              nullptr /* no private data to be loaded */,
                              &public_data,
                              TPM2_RH_NULL,
                              out_transient_handle(handle)));
   return create(std::move(handle), sessions);
}

std::vector<uint8_t> PublicKey::raw_public_key_bits() const {
   return marshal_public_blob(m_handle._public_info(m_sessions).pub.get());
}

std::unique_ptr<PublicKey> PublicKey::create(Object handles, const SessionBundle& sessions) {
   [[maybe_unused]] const auto* pubinfo = handles._public_info(sessions).pub.get();
#if defined(BOTAN_HAS_TPM2_RSA_ADAPTER)
   if(pubinfo->publicArea.type == TPM2_ALG_RSA) {
      return std::unique_ptr<PublicKey>(new RSA_PublicKey(std::move(handles), sessions, pubinfo));
   }
#endif
#if defined(BOTAN_HAS_TPM2_ECC_ADAPTER)
   if(pubinfo->publicArea.type == TPM2_ALG_ECC) {
      return std::unique_ptr<PublicKey>(new EC_PublicKey(std::move(handles), sessions, pubinfo));
   }
#endif

   throw Not_Implemented(Botan::fmt("Loaded a {} public key of an unsupported type",
                                    handles.has_persistent_handle() ? "persistent" : "transient"));
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

std::unique_ptr<PrivateKey> PrivateKey::load_persistent(const std::shared_ptr<Context>& ctx,
                                                        TPM2_HANDLE persistent_object_handle,
                                                        std::span<const uint8_t> auth_value,
                                                        const SessionBundle& sessions) {
   return create(load_persistent_object(ctx, persistent_object_handle, auth_value, sessions),
                 sessions,
                 nullptr /* pull public info from handle */,
                 {} /* persistent keys don't have an encrypted private blob */);
}

std::unique_ptr<PrivateKey> PrivateKey::load_transient(const std::shared_ptr<Context>& ctx,
                                                       std::span<const uint8_t> auth_value,
                                                       const TPM2::PrivateKey& parent,
                                                       std::span<const uint8_t> public_blob,
                                                       std::span<const uint8_t> private_blob,
                                                       const SessionBundle& sessions) {
   BOTAN_ASSERT_NONNULL(ctx);
   Object handle(ctx);

   const auto public_data = unmarshal_public_blob(public_blob);
   const auto private_data = copy_into<TPM2B_PRIVATE>(private_blob);

   check_rc("Esys_Load",
            Esys_Load(*ctx,
                      parent.handles().transient_handle(),
                      sessions[0],
                      sessions[1],
                      sessions[2],
                      &private_data,
                      &public_data,
                      out_transient_handle(handle)));

   if(!auth_value.empty()) {
      const auto user_auth = copy_into<TPM2B_AUTH>(auth_value);
      check_rc("Esys_TR_SetAuth", Esys_TR_SetAuth(*ctx, handle.transient_handle(), &user_auth));
   }

   return create(std::move(handle), sessions, nullptr /* pull public info from handle */, private_blob);
}

std::unique_ptr<PrivateKey> PrivateKey::create_transient_from_template(const std::shared_ptr<Context>& ctx,
                                                                       const SessionBundle& sessions,
                                                                       ESYS_TR parent,
                                                                       const TPMT_PUBLIC& key_template,
                                                                       const TPM2B_SENSITIVE_CREATE& sensitive_data) {
   BOTAN_ASSERT_NONNULL(ctx);

   switch(key_template.type) {
      case TPM2_ALG_RSA:
#if not defined(BOTAN_HAS_TPM2_RSA_ADAPTER)
         throw Not_Implemented("TPM2-based RSA keys are not supported in this build");
#endif
         break;
      case TPM2_ALG_ECC:
#if not defined(BOTAN_HAS_TPM2_ECC_ADAPTER)
         throw Not_Implemented("TPM2-based ECC keys are not supported in this build");
#endif
         break;
      default:
         throw Invalid_Argument("Unsupported key type");
   }

   const auto marshalled_template = marshal_template(key_template);

   Object handle(ctx);
   unique_esys_ptr<TPM2B_PRIVATE> private_bytes;
   unique_esys_ptr<TPM2B_PUBLIC> public_info;

   // Esys_CreateLoaded can create different object types depending on the type
   // of the parent passed in. Namely, this will create a Primary object if the
   // parent is referencing a Primary Seed; an Ordinary Object if the parent is
   // referencing a Storage Parent; and a Derived Object if the parent is
   // referencing a Derivation Parent.
   //
   // See the Architecture Document, Section 27.1.
   check_rc("Esys_CreateLoaded",
            Esys_CreateLoaded(*ctx,
                              parent,
                              sessions[0],
                              sessions[1],
                              sessions[2],
                              &sensitive_data,
                              &marshalled_template,
                              out_transient_handle(handle),
                              out_ptr(private_bytes),
                              out_ptr(public_info)));
   BOTAN_ASSERT_NONNULL(private_bytes);
   BOTAN_ASSERT_NOMSG(public_info->publicArea.type == key_template.type);
   BOTAN_ASSERT_NOMSG(handle.has_transient_handle());

   return create(std::move(handle), sessions, public_info.get(), as_span(*private_bytes));
}

secure_vector<uint8_t> PrivateKey::raw_private_key_bits() const {
   BOTAN_STATE_CHECK(!m_handle.has_persistent_handle());
   BOTAN_ASSERT_NOMSG(!m_private_blob.empty());
   return Botan::lock(m_private_blob);
}

std::vector<uint8_t> PrivateKey::raw_public_key_bits() const {
   return marshal_public_blob(m_handle._public_info(m_sessions).pub.get());
}

bool PrivateKey::is_parent() const {
   // Architectural Document, Section 4.54
   //   any object with the decrypt and restricted attributes SET and the sign
   //   attribute CLEAR
   const auto attrs = m_handle.attributes(m_sessions);
   return attrs.decrypt && attrs.restricted && !attrs.sign_encrypt;
}

std::unique_ptr<PrivateKey> PrivateKey::create(Object handles,
                                               [[maybe_unused]] const SessionBundle& sessions,
                                               [[maybe_unused]] const TPM2B_PUBLIC* public_info,
                                               [[maybe_unused]] std::span<const uint8_t> private_blob) {
   if(!public_info) {
      public_info = handles._public_info(sessions).pub.get();
   }

#if defined(BOTAN_HAS_TPM2_RSA_ADAPTER)
   if(public_info->publicArea.type == TPM2_ALG_RSA) {
      return std::unique_ptr<RSA_PrivateKey>(
         new RSA_PrivateKey(std::move(handles), sessions, public_info, private_blob));
   }
#endif

#if defined(BOTAN_HAS_TPM2_ECC_ADAPTER)
   if(public_info->publicArea.type == TPM2_ALG_ECC) {
      return std::unique_ptr<EC_PrivateKey>(new EC_PrivateKey(std::move(handles), sessions, public_info, private_blob));
   }
#endif

   throw Not_Implemented(Botan::fmt("Loaded a {} private key of an unsupported type",
                                    handles.has_persistent_handle() ? "persistent" : "transient"));
}

}  // namespace Botan::TPM2
