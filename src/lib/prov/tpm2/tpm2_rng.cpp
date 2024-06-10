/*
* TPM 2 RNG interface
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_rng.h>

#include <botan/internal/stl_util.h>

#include <source_location>
#include <tss2/tss2_esys.h>

namespace Botan {

namespace {
constexpr size_t MAX_STIR_RANDOM_SIZE = 128;  // From specification of tpm2-tool's tpm2_stirrandom
}  // anonymous namespace

void TPM2_RNG::fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) {
   BufferSlicer in(input);
   BufferStuffer out(output);

   while(!in.empty()) {
      TPM2B_SENSITIVE_DATA data;
      data.size = std::min(in.remaining(), MAX_STIR_RANDOM_SIZE);
      in.copy_into({data.buffer, data.size});

      check_tss2_rc("StirRandom", Esys_StirRandom(m_ctx->get(), ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &data));
   }

   while(!out.full()) {
      TPM2B_DIGEST* digest = nullptr;
      const auto requested_bytes = std::min(sizeof(digest->buffer), out.remaining_capacity());
      check_tss2_rc("GetRandom",
                    Esys_GetRandom(m_ctx->get(), ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, requested_bytes, &digest));

      BOTAN_ASSERT_NOMSG(digest->size == requested_bytes);
      out.append({digest->buffer, digest->size});

      Esys_Free(digest);
   }
}

}  // namespace Botan
