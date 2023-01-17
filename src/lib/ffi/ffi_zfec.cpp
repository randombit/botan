/*
* (C) 2015,2017,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/zfec.h>
#include <botan/internal/ffi_util.h>

extern "C" {
  int botan_zfec_encode(size_t K, size_t N, const uint8_t input[], size_t size, uint8_t ***output, size_t **outputSizes);

  int botan_zfec_encode(size_t K, size_t N, const uint8_t input[], size_t size, uint8_t ***output, size_t **outputSizes) {
    /* Caller owns *output and everything in it and *outputSizes and everything in it
     */
    return Botan_FFI::ffi_guard_thunk(__func__, [=]() -> int {
      uint8_t **blocks = new uint8_t*[N];
      size_t *sizes = new size_t[N];

      Botan::ZFEC(K, N).encode(input, size, [=](size_t index, const uint8_t block[], size_t blockSize) -> void {
	  blocks[index] = new uint8_t[blockSize];
	  std::copy(block, block + blockSize, blocks[index]);
	  sizes[index] = blockSize;
	});

      // XXX do something
      *output = blocks;
      *outputSizes = sizes;

      return BOTAN_FFI_SUCCESS;
    });
  }
}
