/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_KDF_XMD_H_
#define BOTAN_KDF_XMD_H_

#include <botan/types.h>
#include <string>

namespace Botan {

void BOTAN_TEST_API expand_message_xmd(std::string_view hash_fn,
                                       uint8_t output[],
                                       size_t output_len,
                                       const uint8_t input[],
                                       size_t input_len,
                                       const uint8_t domain_sep[],
                                       size_t domain_sep_len);

}

#endif
