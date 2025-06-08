/*
* TPM 2 RNG interface
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_rng.h>

#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_util.h>

#include <tss2/tss2_esys.h>

namespace Botan::TPM2 {

RandomNumberGenerator::RandomNumberGenerator(std::shared_ptr<Context> ctx, SessionBundle sessions) :
      m_ctx(std::move(ctx)), m_sessions(std::move(sessions)) {
   BOTAN_ASSERT_NONNULL(m_ctx);
   m_max_tpm2_rng_bytes = m_ctx->max_random_bytes_per_request();
}

void RandomNumberGenerator::fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) {
   constexpr size_t MAX_STIR_RANDOM_SIZE = 128;  // From specification of tpm2-tool's tpm2_stirrandom

   BufferSlicer in(input);
   while(!in.empty()) {
      const size_t chunk = std::min(in.remaining(), MAX_STIR_RANDOM_SIZE);
      const auto data = copy_into<TPM2B_SENSITIVE_DATA>(in.take(chunk));

      check_rc("Esys_StirRandom", Esys_StirRandom(*m_ctx, m_sessions[0], m_sessions[1], m_sessions[2], &data));
   }
   BOTAN_ASSERT_NOMSG(in.empty());

   BufferStuffer out(output);
   while(!out.full()) {
      unique_esys_ptr<TPM2B_DIGEST> digest = nullptr;
      const auto requested_bytes = std::min(out.remaining_capacity(), m_max_tpm2_rng_bytes);
      check_rc("Esys_GetRandom",
               Esys_GetRandom(*m_ctx,
                              m_sessions[0],
                              m_sessions[1],
                              m_sessions[2],
                              static_cast<uint16_t>(requested_bytes),
                              out_ptr(digest)));

      BOTAN_ASSERT_NOMSG(digest->size == requested_bytes);
      out.append(as_span(*digest));
   }
   BOTAN_ASSERT_NOMSG(out.full());
}

}  // namespace Botan::TPM2
