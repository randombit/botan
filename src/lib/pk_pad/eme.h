/*
* (C) 1999-2007,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PUBKEY_EME_H_
#define BOTAN_PUBKEY_EME_H_

#include <botan/types.h>
#include <botan/internal/ct_utils.h>
#include <memory>
#include <span>
#include <string_view>

namespace Botan {

class RandomNumberGenerator;

/**
* Encoding Method for Encryption
*/
class BOTAN_TEST_API EME {
   public:
      virtual ~EME();

      /**
      * Factory method for EME (message-encoding methods for encryption) objects
      * @param algo_spec the name of the EME to create
      * @return pointer to newly allocated object of that type
      */
      static std::unique_ptr<EME> create(std::string_view algo_spec);

      /**
      * Return the maximum input size in bytes we can support
      * @param keybits the size of the key in bits
      * @return upper bound of input in bytes
      */
      virtual size_t maximum_input_size(size_t keybits) const = 0;

      /**
      * Encode an input
      * @param output buffer that is written to
      * @param input the plaintext
      * @param key_length length of the key in bits
      * @param rng a random number generator
      * @return number of bytes written to output
      */
      virtual size_t pad(std::span<uint8_t> output,
                         std::span<const uint8_t> input,
                         size_t key_length,
                         RandomNumberGenerator& rng) const = 0;

      /**
      * Decode an input
      * @param output buffer where output is placed
      * @param input the encoded plaintext
      * @return number of bytes written to output if valid,
      *  or an empty option if invalid. If an empty option is
      *  returned the contents of output are undefined
      */
      virtual CT::Option<size_t> unpad(std::span<uint8_t> output, std::span<const uint8_t> input) const = 0;
};

}  // namespace Botan

#endif
