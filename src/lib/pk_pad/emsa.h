/*
* EMSA Classes
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PUBKEY_EMSA_H_
#define BOTAN_PUBKEY_EMSA_H_

#include <botan/secmem.h>
#include <string>

namespace Botan {

class RandomNumberGenerator;
class PK_Signature_Options;

/**
* EMSA, from IEEE 1363s Encoding Method for Signatures, Appendix
*
* Any way of encoding/padding signatures
*/
class BOTAN_TEST_API EMSA {
   public:
      virtual ~EMSA() = default;

      /**
      * Factory method for EMSA (message-encoding methods for signatures
      * with appendix) objects
      * @param algo_spec the name of the EMSA to create
      * @return pointer to newly allocated object of that type, or nullptr
      */
      static std::unique_ptr<EMSA> create(std::string_view algo_spec);

      /**
      * Factory method for EMSA (message-encoding methods for signatures
      * with appendix) objects
      * @param algo_spec the name of the EMSA to create
      * @return pointer to newly allocated object of that type, or throws
      */
      static std::unique_ptr<EMSA> create_or_throw(std::string_view algo_spec);

      /**
      * Factory method for EMSA (message-encoding methods for signatures
      * with appendix) objects
      * @param options the algorithm parameters
      * @return pointer to newly allocated object of that type, or throws
      */
      static std::unique_ptr<EMSA> create_or_throw(const PK_Signature_Options& options);

      /**
      * Add more data to the signature computation
      * @param input some data
      * @param length length of input in bytes
      */
      virtual void update(const uint8_t input[], size_t length) = 0;

      /**
      * @return raw hash
      */
      virtual std::vector<uint8_t> raw_data() = 0;

      /**
      * Return the encoding of a message
      * @param msg the result of raw_data()
      * @param output_bits the desired output bit size
      * @param rng a random number generator
      * @return encoded signature
      */
      virtual std::vector<uint8_t> encoding_of(const std::vector<uint8_t>& msg,
                                               size_t output_bits,
                                               RandomNumberGenerator& rng) = 0;

      /**
      * Verify the encoding
      * @param coded the received (coded) message representative
      * @param raw the computed (local, uncoded) message representative
      * @param key_bits the size of the key in bits
      * @return true if coded is a valid encoding of raw, otherwise false
      */
      virtual bool verify(const std::vector<uint8_t>& coded, const std::vector<uint8_t>& raw, size_t key_bits) = 0;

      /**
      * Return the hash function being used by this padding scheme
      */
      virtual std::string hash_function() const = 0;

      /**
      * @return the SCAN name of the encoding/padding scheme
      */
      virtual std::string name() const = 0;
};

}  // namespace Botan

#endif
