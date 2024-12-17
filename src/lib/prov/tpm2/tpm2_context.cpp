/*
* TPM 2 interface
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_context.h>

#include <botan/tpm2_key.h>
#include <botan/tpm2_session.h>

#include <botan/internal/fmt.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_algo_mappings.h>
#include <botan/internal/tpm2_util.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tctildr.h>

#if defined(BOTAN_HAS_TPM2_CRYPTO_BACKEND)
   #include <botan/tpm2_crypto_backend.h>
   #include <botan/internal/tpm2_crypto_backend_impl.h>
#endif

namespace Botan::TPM2 {

namespace {

constexpr TPM2_HANDLE storage_root_key_handle = TPM2_HR_PERSISTENT + 1;

}  // namespace

struct Context::Impl {
      ESYS_CONTEXT* m_ctx;  /// m_ctx may be owned by the library user (see m_external)
      bool m_external;

#if defined(BOTAN_HAS_TPM2_CRYPTO_BACKEND)
      std::unique_ptr<CryptoCallbackState> m_crypto_callback_state;
#endif
};

bool Context::supports_botan_crypto_backend() noexcept {
#if defined(BOTAN_HAS_TPM2_CRYPTO_BACKEND)
   return Botan::TPM2::supports_botan_crypto_backend();
#else
   return false;
#endif
}

std::shared_ptr<Context> Context::create(const std::string& tcti_nameconf) {
   const auto nameconf_ptr = tcti_nameconf.c_str();

   TSS2_TCTI_CONTEXT* tcti_ctx = nullptr;
   ESYS_CONTEXT* esys_ctx = nullptr;
   check_rc("TCTI Initialization", Tss2_TctiLdr_Initialize(nameconf_ptr, &tcti_ctx));
   BOTAN_ASSERT_NONNULL(tcti_ctx);
   check_rc("TPM2 Initialization", Esys_Initialize(&esys_ctx, tcti_ctx, nullptr /* ABI version */));
   BOTAN_ASSERT_NONNULL(esys_ctx);

   // We cannot std::make_shared as the constructor is private
   return std::shared_ptr<Context>(new Context(esys_ctx, false /* context is managed by us */));
}

std::shared_ptr<Context> Context::create(std::optional<std::string> tcti, std::optional<std::string> conf) {
   const auto tcti_ptr = tcti.has_value() ? tcti->c_str() : nullptr;
   const auto conf_ptr = conf.has_value() ? conf->c_str() : nullptr;

   TSS2_TCTI_CONTEXT* tcti_ctx = nullptr;
   ESYS_CONTEXT* esys_ctx = nullptr;
   check_rc("TCTI Initialization", Tss2_TctiLdr_Initialize_Ex(tcti_ptr, conf_ptr, &tcti_ctx));
   BOTAN_ASSERT_NONNULL(tcti_ctx);
   check_rc("TPM2 Initialization", Esys_Initialize(&esys_ctx, tcti_ctx, nullptr /* ABI version */));
   BOTAN_ASSERT_NONNULL(esys_ctx);

   // We cannot std::make_shared as the constructor is private
   return std::shared_ptr<Context>(new Context(esys_ctx, false /* context is managed by us */));
}

std::shared_ptr<Context> Context::create(ESYS_CONTEXT* esys_ctx) {
   BOTAN_ARG_CHECK(esys_ctx != nullptr, "provided esys_ctx must not be null");

   // We cannot std::make_shared as the constructor is private
   return std::shared_ptr<Context>(new Context(esys_ctx, true /* context is managed externally */));
}

Context::Context(ESYS_CONTEXT* ctx, bool external) : m_impl(std::make_unique<Impl>()) {
   m_impl->m_ctx = ctx;
   m_impl->m_external = external;
   BOTAN_ASSERT_NONNULL(m_impl->m_ctx);
}

Context::Context(Context&&) noexcept = default;
Context& Context::operator=(Context&&) noexcept = default;

void Context::use_botan_crypto_backend(const std::shared_ptr<Botan::RandomNumberGenerator>& rng) {
#if defined(BOTAN_HAS_TPM2_CRYPTO_BACKEND)
   BOTAN_STATE_CHECK(!uses_botan_crypto_backend());
   m_impl->m_crypto_callback_state = Botan::TPM2::use_botan_crypto_backend(esys_context(), rng);
#else
   BOTAN_UNUSED(rng);
   throw Not_Implemented("This build of botan does not provide the TPM2 crypto backend");
#endif
}

bool Context::uses_botan_crypto_backend() const noexcept {
#if defined(BOTAN_HAS_TPM2_CRYPTO_BACKEND)
   return m_impl->m_crypto_callback_state != nullptr;
#else
   return false;
#endif
}

#if defined(BOTAN_HAS_TPM2_CRYPTO_BACKEND)
CryptoCallbackState& Context::crypto_callback_state() {
   BOTAN_ASSERT_NONNULL(m_impl->m_crypto_callback_state);
   return *m_impl->m_crypto_callback_state;
}
#endif

ESYS_CONTEXT* Context::esys_context() noexcept {
   return m_impl->m_ctx;
}

namespace {

uint32_t get_tpm_property(ESYS_CONTEXT* ctx, TPM2_PT property) {
   // We expect to retrieve a single piece of information, not a list.
   constexpr uint32_t property_count = 1;
   constexpr TPM2_CAP capability = TPM2_CAP_TPM_PROPERTIES;

   unique_esys_ptr<TPMS_CAPABILITY_DATA> capability_data;
   check_rc("Esys_GetCapability",
            Esys_GetCapability(ctx,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               capability,
                               property,
                               property_count,
                               nullptr /* more data? - we don't care here */,
                               out_ptr(capability_data)));
   BOTAN_ASSERT_NONNULL(capability_data);
   BOTAN_ASSERT_NOMSG(capability_data->capability == capability);
   BOTAN_ASSERT_NOMSG(capability_data->data.tpmProperties.count == property_count);
   BOTAN_ASSERT_NOMSG(capability_data->data.tpmProperties.tpmProperty[0].property == property);

   return capability_data->data.tpmProperties.tpmProperty[0].value;
}

template <TPM2_CAP capability, typename ReturnT>
[[nodiscard]] std::vector<ReturnT> get_tpm_property_list(ESYS_CONTEXT* ctx, TPM2_PT property, uint32_t count) {
   auto extract = [](const TPMU_CAPABILITIES& caps, uint32_t max_count) {
      std::vector<ReturnT> result;
      if constexpr(capability == TPM2_CAP_HANDLES) {
         const auto to_read = std::min(caps.handles.count, max_count);
         result.reserve(to_read);
         for(size_t i = 0; i < to_read; ++i) {
            result.push_back(caps.handles.handle[i]);
         }
      } else if constexpr(capability == TPM2_CAP_ALGS) {
         const auto to_read = std::min(caps.algorithms.count, max_count);
         result.reserve(to_read);
         for(size_t i = 0; i < to_read; ++i) {
            // TODO: This also contains an algProperties.algProperties bitfield
            //       that defines some characteristics of the algorithm.
            //       Currently, we don't need that information and ignore it.
            result.push_back(caps.algorithms.algProperties[i].alg);
         }
      } else {
         // TODO: support reading other capability types as needed
         static_assert(capability != TPM2_CAP_HANDLES, "Unsupported capability");
      }
      return result;
   };

   TPMI_YES_NO more_data = TPM2_YES;
   std::vector<ReturnT> properties;
   while(more_data == TPM2_YES && count > 0) {
      unique_esys_ptr<TPMS_CAPABILITY_DATA> capability_data;
      check_rc("Esys_GetCapability",
               Esys_GetCapability(ctx,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  capability,
                                  property,
                                  count,
                                  &more_data,
                                  out_ptr(capability_data)));
      BOTAN_ASSERT_NONNULL(capability_data);
      BOTAN_ASSERT_NOMSG(capability_data->capability == capability);

      const auto new_properties = extract(capability_data->data, count);
      BOTAN_ASSERT_NOMSG(new_properties.size() <= count);
      properties.insert(properties.end(), new_properties.begin(), new_properties.end());
      count -= checked_cast_to<uint32_t>(new_properties.size());
   }

   return properties;
}

}  // namespace

std::string Context::vendor() const {
   constexpr std::array properties = {
      TPM2_PT_VENDOR_STRING_1, TPM2_PT_VENDOR_STRING_2, TPM2_PT_VENDOR_STRING_3, TPM2_PT_VENDOR_STRING_4};
   std::array<uint8_t, properties.size() * 4 + 1 /* ensure zero-termination */> vendor_string{};

   BufferStuffer bs(vendor_string);

   // The vendor name is transported in several uint32_t fields that are
   // loaded as big-endian bytes and concatenated to form the vendor string.
   for(auto prop : properties) {
      bs.append(store_be(get_tpm_property(m_impl->m_ctx, prop)));
   }

   BOTAN_ASSERT_NOMSG(bs.remaining_capacity() == 1);  // the ensured zero-termination
   return std::string(cast_uint8_ptr_to_char(vendor_string.data()));
}

std::string Context::manufacturer() const {
   std::array<uint8_t, 4 + 1 /* ensure zero termination */> manufacturer_data{};
   store_be(std::span{manufacturer_data}.first<4>(), get_tpm_property(m_impl->m_ctx, TPM2_PT_MANUFACTURER));
   return std::string(cast_uint8_ptr_to_char(manufacturer_data.data()));
}

bool Context::supports_algorithm(std::string_view algo_name) const {
   // Go through all the string mappings we have available and check if we
   // can find the algorithm name in any of them. If we do, we can check if
   // the TPM supports the required algorithms.
   const auto required_alg_ids = [&]() -> std::vector<TPM2_ALG_ID> {
      std::vector<TPM2_ALG_ID> result;
      if(auto algo_id = asymmetric_algorithm_botan_to_tss2(algo_name)) {
         result.push_back(algo_id.value());
      }

      if(auto hash_id = hash_algo_botan_to_tss2(algo_name)) {
         result.push_back(hash_id.value());
      }

      if(auto block_id = block_cipher_botan_to_tss2(algo_name)) {
         result.push_back(block_id->first);
      }

      if(auto cipher_mode_id = cipher_mode_botan_to_tss2(algo_name)) {
         result.push_back(cipher_mode_id.value());
      }

      if(auto cipher_spec = cipher_botan_to_tss2(algo_name)) {
         result.push_back(cipher_spec->algorithm);
         result.push_back(cipher_spec->mode.sym);
      }

      if(auto sig_padding = rsa_signature_padding_botan_to_tss2(algo_name)) {
         result.push_back(sig_padding.value());
      }

      if(auto sig = rsa_signature_scheme_botan_to_tss2(algo_name)) {
         result.push_back(sig->scheme);
         result.push_back(sig->details.any.hashAlg);
      }

      if(auto enc_scheme = rsa_encryption_scheme_botan_to_tss2(algo_name)) {
         result.push_back(enc_scheme->scheme);
         if(enc_scheme->scheme == TPM2_ALG_OAEP) {
            result.push_back(enc_scheme->details.oaep.hashAlg);
         }
      }

      if(auto enc_id = rsa_encryption_padding_botan_to_tss2(algo_name)) {
         result.push_back(enc_id.value());
      }

      return result;
   }();

   if(required_alg_ids.empty()) {
      // The algorithm name is not known to us, so we cannot check for support.
      return false;
   }

   const auto algo_caps =
      get_tpm_property_list<TPM2_CAP_ALGS, TPM2_ALG_ID>(m_impl->m_ctx, TPM2_ALG_FIRST, TPM2_MAX_CAP_ALGS);

   return std::all_of(
      required_alg_ids.begin(), required_alg_ids.end(), [&](TPM2_ALG_ID id) { return value_exists(algo_caps, id); });
}

size_t Context::max_random_bytes_per_request() const {
   return get_tpm_property(m_impl->m_ctx, TPM2_PT_MAX_DIGEST);
}

std::unique_ptr<TPM2::PrivateKey> Context::storage_root_key(std::span<const uint8_t> auth_value,
                                                            const SessionBundle& sessions) {
   return TPM2::PrivateKey::load_persistent(shared_from_this(), storage_root_key_handle, auth_value, sessions);
}

std::vector<ESYS_TR> Context::transient_handles() const {
   return get_tpm_property_list<TPM2_CAP_HANDLES, ESYS_TR>(m_impl->m_ctx, TPM2_TRANSIENT_FIRST, TPM2_MAX_CAP_HANDLES);
}

std::optional<TPM2_HANDLE> Context::find_free_persistent_handle() const {
   const auto occupied_handles = persistent_handles();

   // This is modeled after the implementation in tpm2-tools, which also takes
   // "platform persistent" handles into account. We don't do that here, but
   // we might need to in the future.
   //
   // See: https://github.com/tpm2-software/tpm2-tools/blob/bd832d3f79/lib/tpm2_capability.c#L143-L196

   // all persistent handles are occupied
   if(occupied_handles.size() >= TPM2_MAX_CAP_HANDLES) {
      return std::nullopt;
   }

   // find the lowest handle that is not occupied
   for(TPM2_HANDLE i = TPM2_PERSISTENT_FIRST; i < TPM2_PERSISTENT_LAST; ++i) {
      if(!value_exists(occupied_handles, i)) {
         return i;
      }
   }

   BOTAN_ASSERT_UNREACHABLE();
}

std::vector<TPM2_HANDLE> Context::persistent_handles() const {
   return get_tpm_property_list<TPM2_CAP_HANDLES, TPM2_HANDLE>(
      m_impl->m_ctx, TPM2_PERSISTENT_FIRST, TPM2_MAX_CAP_HANDLES);
}

TPM2_HANDLE Context::persist(TPM2::PrivateKey& key,
                             const SessionBundle& sessions,
                             std::span<const uint8_t> auth_value,
                             std::optional<TPM2_HANDLE> persistent_handle) {
   auto& handles = key.handles();

   BOTAN_ARG_CHECK(!persistent_handle || !value_exists(persistent_handles(), persistent_handle.value()),
                   "Persistent handle already in use");
   BOTAN_ARG_CHECK(!handles.has_persistent_handle(), "Key already has a persistent handle assigned");

   // 1. Decide on the location to persist the key to.
   //    This uses either the handle provided by the caller or a free handle.
   const TPMI_DH_PERSISTENT new_persistent_handle = [&] {
      if(persistent_handle.has_value()) {
         return persistent_handle.value();
      } else {
         const auto free_persistent_handle = find_free_persistent_handle();
         BOTAN_STATE_CHECK(free_persistent_handle.has_value());
         return free_persistent_handle.value();
      }
   }();

   // 2. Persist the transient key in the TPM's NV storage
   //    This will flush the transient key handle and replace it with a new
   //    transient handle that references the persisted key.
   check_rc("Esys_EvictControl",
            Esys_EvictControl(m_impl->m_ctx,
                              ESYS_TR_RH_OWNER /*TODO: hierarchy*/,
                              handles.transient_handle(),
                              sessions[0],
                              sessions[1],
                              sessions[2],
                              new_persistent_handle,
                              out_transient_handle(handles)));
   BOTAN_ASSERT_NOMSG(handles.has_transient_handle());

   // 3. Reset the auth value of the key object
   //    This is necessary to ensure that the key object remains usable after
   //    the transient handle was recreated inside Esys_EvictControl().
   if(!auth_value.empty()) {
      const auto user_auth = copy_into<TPM2B_AUTH>(auth_value);
      check_rc("Esys_TR_SetAuth", Esys_TR_SetAuth(m_impl->m_ctx, handles.transient_handle(), &user_auth));
   }

   // 4. Update the key object with the new persistent handle
   //    This double-checks that the key was persisted at the correct location,
   //    but also brings the key object into a consistent state.
   check_rc("Esys_TR_GetTpmHandle",
            Esys_TR_GetTpmHandle(m_impl->m_ctx, handles.transient_handle(), out_persistent_handle(handles)));

   BOTAN_ASSERT_NOMSG(handles.has_persistent_handle());
   BOTAN_ASSERT_EQUAL(new_persistent_handle, handles.persistent_handle(), "key was persisted at the correct location");

   return new_persistent_handle;
}

void Context::evict(std::unique_ptr<TPM2::PrivateKey> key, const SessionBundle& sessions) {
   BOTAN_ASSERT_NONNULL(key);

   auto& handles = key->handles();
   BOTAN_ARG_CHECK(handles.has_persistent_handle(), "Key does not have a persistent handle assigned");

   // 1. Evict the key from the TPM's NV storage
   //    This will free the persistent handle, but the transient handle will
   //    still be valid.
   ESYS_TR no_new_handle = ESYS_TR_NONE;
   check_rc("Esys_EvictControl",
            Esys_EvictControl(m_impl->m_ctx,
                              ESYS_TR_RH_OWNER /*TODO: hierarchy*/,
                              handles.transient_handle(),
                              sessions[0],
                              sessions[1],
                              sessions[2],
                              0,
                              &no_new_handle));
   BOTAN_ASSERT(no_new_handle == ESYS_TR_NONE, "When deleting a key, no new handle is returned");

   // 2. The persistent key was deleted and the transient key was flushed by
   //    Esys_EvictControl().
   handles._disengage();
}

Context::~Context() {
   if(!m_impl) {
      return;
   }

#if defined(BOTAN_HAS_TPM2_CRYPTO_BACKEND)
   // If this object manages a crypto backend state object and the ESYS context
   // will live on, because it was externally provided, we have to de-register
   // this state object from the crypto callbacks.
   //
   // This will prevent the crypto backend callbacks from using a dangling
   // pointer and cause graceful errors if the externally provided ESYS context
   // is used for any action that would still need the crypto backend state.
   //
   // We deliberately do not just disable the crypto backend silently, as that
   // might give users the false impression that they continue to benefit from
   // the crypto backend while in fact they're back to the TSS' default.
   if(m_impl->m_external && uses_botan_crypto_backend()) {
      try {
         set_crypto_callbacks(esys_context(), nullptr /* reset callback state */);
      } catch(...) {
         // ignore errors in destructor
      }
      m_impl->m_crypto_callback_state.reset();
   }
#endif

   // We don't finalize contexts that were provided externally. Those are
   // expected to be handled by the library users' applications.
   if(!m_impl->m_external) {
      // If the TCTI context was initialized explicitly, Esys_GetTcti() will
      // return a pointer to the TCTI context that then has to be finalized
      // explicitly. See ESAPI Specification Section 6.3 "Esys_GetTcti".
      TSS2_TCTI_CONTEXT* tcti_ctx = nullptr;
      Esys_GetTcti(m_impl->m_ctx, &tcti_ctx);  // ignore error in destructor
      if(tcti_ctx != nullptr) {
         Tss2_TctiLdr_Finalize(&tcti_ctx);
      }

      Esys_Finalize(&m_impl->m_ctx);
   }
}

}  // namespace Botan::TPM2
