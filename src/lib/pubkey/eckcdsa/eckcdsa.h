/*
* ECKCDSA (ISO/IEC 14888-3:2006/Cor.2:2009)
* (C) 2016 René Korthaus, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ECKCDSA_KEY_H__
#define BOTAN_ECKCDSA_KEY_H__

#include <botan/ecc_key.h>

namespace Botan {

/**
* This class represents ECKCDSA public keys.
*/
class BOTAN_DLL ECKCDSA_PublicKey : public virtual EC_PublicKey
   {
   public:

      /**
      * Construct a public key from a given public point.
      * @param dom_par the domain parameters associated with this key
      * @param public_point the public point defining this key
      */
      ECKCDSA_PublicKey(const EC_Group& dom_par,
                      const PointGFp& public_point) :
         EC_PublicKey(dom_par, public_point) {}

      ECKCDSA_PublicKey(const AlgorithmIdentifier& alg_id,
                      const secure_vector<byte>& key_bits) :
         EC_PublicKey(alg_id, key_bits) {}

      /**
      * Get this keys algorithm name.
      * @result this keys algorithm name ("ECGDSA")
      */
      std::string algo_name() const override { return "ECKCDSA"; }

      /**
      * Get the maximum number of bits allowed to be fed to this key.
      * This is the bitlength of the order of the base point.
      * @result the maximum number of input bits
      */
      size_t max_input_bits() const override
         { return domain().get_order().bits(); }

      size_t message_parts() const override { return 2; }

      size_t message_part_size() const override
         { return domain().get_order().bytes(); }

   protected:
      ECKCDSA_PublicKey() {}
   };

/**
* This class represents ECKCDSA private keys.
*/
class BOTAN_DLL ECKCDSA_PrivateKey : public ECKCDSA_PublicKey,
                                    public EC_PrivateKey
   {
   public:

      /**
      * Load a private key
      * @param alg_id the X.509 algorithm identifier
      * @param key_bits PKCS #8 structure
      */
      ECKCDSA_PrivateKey(const AlgorithmIdentifier& alg_id,
                       const secure_vector<byte>& key_bits) :
         EC_PrivateKey(alg_id, key_bits, true) {}

      /**
      * Generate a new private key
      * @param rng a random number generator
      * @param domain parameters to used for this key
      * @param x the private key (if zero, generate a new random key)
      */
      ECKCDSA_PrivateKey(RandomNumberGenerator& rng,
                       const EC_Group& domain,
                       const BigInt& x = 0) :
         EC_PrivateKey(rng, domain, x, true) {}

      bool check_key(RandomNumberGenerator& rng, bool) const override;
   };

}

#endif
