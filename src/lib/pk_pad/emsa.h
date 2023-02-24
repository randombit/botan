/*
* EMSA Classes
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PUBKEY_EMSA_H_
#define BOTAN_PUBKEY_EMSA_H_

#include <botan/secmem.h>
#include <botan/asn1_obj.h>
#include <string>

namespace Botan {

class RandomNumberGenerator;

/**
* EMSA, from IEEE 1363s Encoding Method for Signatures, Appendix
*
* Any way of encoding/padding signatures
*/
class BOTAN_TEST_API EMSA
   {
   public:
      virtual ~EMSA() = default;

      /**
      * Factory method for EMSA (message-encoding methods for signatures
      * with appendix) objects
      * @param algo_spec the name of the EMSA to create
      * @return pointer to newly allocated object of that type, or nullptr
      */
      static std::unique_ptr<EMSA> create(const std::string& algo_spec);

      /**
      * Factory method for EMSA (message-encoding methods for signatures
      * with appendix) objects
      * @param algo_spec the name of the EMSA to create
      * @return pointer to newly allocated object of that type, or throws
      */
      static std::unique_ptr<EMSA> create_or_throw(const std::string& algo_spec);

      /**
      * Add more data to the signature computation
      * @param input some data
      * @param length length of input in bytes
      */
      virtual void update(const uint8_t input[], size_t length) = 0;

      /**
      * @return raw hash
      */
      virtual secure_vector<uint8_t> raw_data() = 0;

      /**
      * Return the encoding of a message
      * @param msg the result of raw_data()
      * @param output_bits the desired output bit size
      * @param rng a random number generator
      * @return encoded signature
      */
      virtual secure_vector<uint8_t> encoding_of(const secure_vector<uint8_t>& msg,
                                             size_t output_bits,
                                             RandomNumberGenerator& rng) = 0;

      /**
      * Verify the encoding
      * @param coded the received (coded) message representative
      * @param raw the computed (local, uncoded) message representative
      * @param key_bits the size of the key in bits
      * @return true if coded is a valid encoding of raw, otherwise false
      */
      virtual bool verify(const secure_vector<uint8_t>& coded,
                          const secure_vector<uint8_t>& raw,
                          size_t key_bits) = 0;

      /**
      * Prepare sig_algo for use in choose_sig_format for x509 certs
      *
      * @param algo_name used for checking compatibility with the encoding scheme
      *        this should match the canonical algorithm name eg "RSA", "ECDSA"
      * @param cert_hash_name is checked to equal the hash for the encoding
      * @return algorithm identifier to signatures created using this key,
      *         padding method and hash.
      */
      virtual AlgorithmIdentifier config_for_x509(const std::string& algo_name,
                                                  const std::string& cert_hash_name) const;


      /**
      * Return encoded algorithm parameters for this signature padding
      * scheme, if relevant. This should be a DER encoded blob.
      */
      virtual std::vector<uint8_t> algorithm_parameters() const;

      virtual std::string hash_function() const = 0;

      /**
      * @return the SCAN name of the encoding/padding scheme
      */
      virtual std::string name() const = 0;
   };

}

#endif
