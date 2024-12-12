/*
* TPM 2.0 Hash Function Wrappers
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tpm2_hash.h>

#include <botan/internal/fmt.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_algo_mappings.h>

#include <tss2/tss2_esys.h>

namespace Botan::TPM2 {

HashFunction::HashFunction(std::shared_ptr<Context> ctx,
                           std::string_view algorithm,
                           TPMI_RH_HIERARCHY hierarchy,
                           SessionBundle sessions) :
      m_hash_type(get_tpm2_hash_type(algorithm)),
      m_hierarchy(hierarchy),
      m_handle(std::move(ctx)),
      m_sessions(std::move(sessions)) {
   // When creating a new hash object we assume that the call will use it to
   // hash data and therefore setup the hash object immediately.
   lazy_setup();
}

std::string HashFunction::name() const {
   return get_botan_hash_name(m_hash_type);
}

size_t HashFunction::output_length() const {
   switch(m_hash_type) {
      case TPM2_ALG_SHA1:
         return 20;
      case TPM2_ALG_SHA256:
      case TPM2_ALG_SHA3_256:
      case TPM2_ALG_SM3_256:
         return 32;
      case TPM2_ALG_SHA384:
      case TPM2_ALG_SHA3_384:
         return 48;
      case TPM2_ALG_SHA512:
      case TPM2_ALG_SHA3_512:
         return 64;
      default:
         throw Invalid_State("TPM 2.0 hash object with unexpected hash type");
   }
}

void HashFunction::clear() {
   m_handle._reset();
}

std::unique_ptr<Botan::HashFunction> HashFunction::copy_state() const {
   throw Not_Implemented("TPM 2.0 hash functions do not support copy_state");
}

std::unique_ptr<Botan::HashFunction> HashFunction::new_object() const {
   return std::make_unique<HashFunction>(m_handle.context(), name(), m_hierarchy, m_sessions);
}

void HashFunction::lazy_setup() {
   if(m_handle.has_transient_handle()) {
      return;
   }

   const auto auth = init_empty<TPM2B_AUTH>();
   const auto rc = check_rc_expecting<TPM2_RC_HASH>("Esys_HashSequenceStart",
                                                    Esys_HashSequenceStart(*m_handle.context(),
                                                                           m_sessions[0],
                                                                           m_sessions[1],
                                                                           m_sessions[2],
                                                                           &auth,
                                                                           m_hash_type,
                                                                           out_transient_handle(m_handle)));

   if(rc == TPM2_RC_HASH) {
      throw Lookup_Error(fmt("TPM 2.0 Hash {} is not supported", name()));
   }
}

void HashFunction::add_data(std::span<const uint8_t> input) {
   lazy_setup();

   BufferSlicer slicer(input);
   while(slicer.remaining() > 0) {
      const size_t chunk = std::min(slicer.remaining(), size_t(TPM2_MAX_DIGEST_BUFFER));
      const auto data = copy_into<TPM2B_MAX_BUFFER>(slicer.take(chunk));
      check_rc(
         "Esys_SequenceUpdate",
         Esys_SequenceUpdate(
            *m_handle.context(), m_handle.transient_handle(), m_sessions[0], m_sessions[1], m_sessions[2], &data));
   }
   BOTAN_ASSERT_NOMSG(slicer.empty());
}

std::pair<unique_esys_ptr<TPM2B_DIGEST>, unique_esys_ptr<TPMT_TK_HASHCHECK>> HashFunction::final_with_ticket() {
   BOTAN_STATE_CHECK(m_handle.has_transient_handle());

   std::pair<unique_esys_ptr<TPM2B_DIGEST>, unique_esys_ptr<TPMT_TK_HASHCHECK>> result;

   const auto nodata = init_empty<TPM2B_MAX_BUFFER>();
   check_rc("Esys_SequenceComplete",
            Esys_SequenceComplete(*m_handle.context(),
                                  m_handle.transient_handle(),
                                  m_sessions[0],
                                  m_sessions[1],
                                  m_sessions[2],
                                  &nodata,
                                  m_hierarchy,
                                  out_ptr(result.first),
                                  out_ptr(result.second)));
   BOTAN_ASSERT_NONNULL(result.first);

   // Esys_SequenceComplete() destroys the underlying transient object
   // so we need to disengage it's RAII wrapper.
   m_handle._disengage();

   return result;
}

void HashFunction::final_result(std::span<uint8_t> output) {
   const auto digest_and_ticket = final_with_ticket();
   BOTAN_ASSERT_NONNULL(digest_and_ticket.first);
   BOTAN_ASSERT_NOMSG(digest_and_ticket.first->size <= output.size());
   BOTAN_DEBUG_ASSERT(digest_and_ticket.first->size == output_length());

   copy_mem(output.first(output.size()), as_span(*digest_and_ticket.first));
}

}  // namespace Botan::TPM2
