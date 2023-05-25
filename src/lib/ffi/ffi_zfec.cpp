/*
* (C) 2023 Least Authority TFA GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/internal/ffi_util.h>

#if defined(BOTAN_HAS_ZFEC)
   #include <botan/zfec.h>
#endif

extern "C" {

int botan_zfec_encode(size_t K, size_t N, const uint8_t* input, size_t size, uint8_t** outputs) {
#if defined(BOTAN_HAS_ZFEC)
   return Botan_FFI::ffi_guard_thunk(__func__, [=]() -> int {
      Botan::ZFEC(K, N).encode(input, size, [=](size_t index, const uint8_t block[], size_t blockSize) -> void {
         std::copy(block, block + blockSize, outputs[index]);
      });
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(K, N, input, size, outputs);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_zfec_decode(
   size_t K, size_t N, const size_t* indexes, uint8_t* const* const inputs, size_t shareSize, uint8_t** outputs) {
#if defined(BOTAN_HAS_ZFEC)
   return Botan_FFI::ffi_guard_thunk(__func__, [=]() -> int {
      std::map<size_t, const uint8_t*> shares;
      for(size_t k = 0; k < K; ++k) {
         shares.insert(std::pair<size_t, const uint8_t*>(indexes[k], inputs[k]));
      }
      Botan::ZFEC(K, N).decode_shares(
         shares, shareSize, [=](size_t index, const uint8_t block[], size_t blockSize) -> void {
            std::copy(block, block + blockSize, outputs[index]);
         });
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(K, N, indexes, inputs, shareSize, outputs);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}
}
