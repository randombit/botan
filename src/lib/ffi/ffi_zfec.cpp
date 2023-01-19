/*
* (C) 2015,2017,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/zfec.h>
#include <botan/internal/ffi_util.h>

extern "C" {
  int botan_zfec_encode(size_t K, size_t N, const uint8_t input[], size_t size, uint8_t **outputs, size_t *sizes) {
    return Botan_FFI::ffi_guard_thunk(__func__, [=]() -> int {
      Botan::ZFEC(K, N).encode(input, size, [=](size_t index, const uint8_t block[], size_t blockSize) -> void {
	  outputs[index] = new uint8_t[blockSize];
	  std::copy(block, block + blockSize, outputs[index]);
	  sizes[index] = blockSize;
	});
      return BOTAN_FFI_SUCCESS;
    });
  }
}
