/*
* Utils for calling CommonCrypto
* (C) 2018 Jose Pereira
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_INTERNAL_COMMONCRYPTO_UTILS_H_
#define BOTAN_INTERNAL_COMMONCRYPTO_UTILS_H_

#include <botan/key_spec.h>

#include <CommonCrypto/CommonCrypto.h>

namespace Botan {

struct CommonCryptor_Opts
   {
   CCAlgorithm algo;
   CCMode mode;
   CCPadding padding;
   size_t block_size;
   Key_Length_Specification key_spec{0};
   };

CommonCryptor_Opts commoncrypto_opts_from_algo(const std::string& algo, bool cipher_only);

void commoncrypto_adjust_key_size(const uint8_t key[], size_t length,
                                  const CommonCryptor_Opts& opts, secure_vector<uint8_t>& full_key);


}

#endif
