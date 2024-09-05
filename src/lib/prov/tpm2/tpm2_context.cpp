/*
* TPM 2 interface
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_context.h>

#include <botan/tpm2_session.h>

#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_algo_mappings.h>
#include <botan/internal/tpm2_util.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tctildr.h>

namespace Botan::TPM2 {

struct Context::Impl {
      TSS2_TCTI_CONTEXT* m_tcti_ctx;
      ESYS_CONTEXT* m_ctx;
};

std::shared_ptr<Context> Context::create(const std::string& tcti_nameconf) {
   // We cannot std::make_shared as the constructor is private
   return std::shared_ptr<Context>(new Context(tcti_nameconf.c_str()));
}

std::shared_ptr<Context> Context::create(std::optional<std::string> tcti, std::optional<std::string> conf) {
   const auto tcti_ptr = tcti.has_value() ? tcti->c_str() : nullptr;
   const auto conf_ptr = conf.has_value() ? conf->c_str() : nullptr;

   // We cannot std::make_shared as the constructor is private
   return std::shared_ptr<Context>(new Context(tcti_ptr, conf_ptr));
}

Context::Context(const char* tcti_nameconf) : m_impl(std::make_unique<Impl>()) {
   check_rc("TCTI Initialization", Tss2_TctiLdr_Initialize(tcti_nameconf, &m_impl->m_tcti_ctx));
   BOTAN_ASSERT_NONNULL(m_impl->m_tcti_ctx);
   check_rc("TPM2 Initialization", Esys_Initialize(&m_impl->m_ctx, m_impl->m_tcti_ctx, nullptr /* ABI version */));
   BOTAN_ASSERT_NONNULL(m_impl->m_ctx);
}

Context::Context(const char* tcti_name, const char* tcti_conf) : m_impl(std::make_unique<Impl>()) {
   check_rc("TCTI Initialization", Tss2_TctiLdr_Initialize_Ex(tcti_name, tcti_conf, &m_impl->m_tcti_ctx));
   BOTAN_ASSERT_NONNULL(m_impl->m_tcti_ctx);
   check_rc("TPM2 Initialization", Esys_Initialize(&m_impl->m_ctx, m_impl->m_tcti_ctx, nullptr /* ABI version */));
   BOTAN_ASSERT_NONNULL(m_impl->m_ctx);
}

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
      count -= new_properties.size();
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

Context::~Context() {
   if(m_impl) {
      Esys_Finalize(&m_impl->m_ctx);
      Tss2_TctiLdr_Finalize(&m_impl->m_tcti_ctx);
   }
}

}  // namespace Botan::TPM2
