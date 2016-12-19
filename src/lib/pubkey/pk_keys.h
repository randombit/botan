/*
* PK Key Types
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PK_KEYS_H__
#define BOTAN_PK_KEYS_H__

#include <botan/secmem.h>
#include <botan/asn1_oid.h>
#include <botan/alg_id.h>
#include <botan/rng.h>
#include <botan/pk_ops_fwd.h>

namespace Botan {

class RandomNumberGenerator;

/**
* Public Key Base Class.
*/
class BOTAN_DLL Public_Key {
public:
  virtual ~Public_Key() {}

  /**
  * Get the name of the underlying public key scheme.
  * @return name of the public key scheme
  */
  virtual std::string algo_name() const = 0;

  /**
  * Return the estimated strength of the underlying key against
  * the best currently known attack. Note that this ignores anything
  * but pure attacks against the key itself and do not take into
  * account padding schemes, usage mistakes, etc which might reduce
  * the strength. However it does suffice to provide an upper bound.
  *
  * @return estimated strength in bits
  */
  virtual size_t estimated_strength() const = 0;

  /**
  * Return an integer value best approximating the length of the
  * primary security parameter. For example for RSA this will be
  * the size of the modulus, for ECDSA the size of the ECC group,
  * and for McEliece the size of the code will be returned.
  */
  virtual size_t key_length() const = 0;

  /**
  * Get the OID of the underlying public key scheme.
  * @return OID of the public key scheme
  */
  virtual OID get_oid() const;

  /**
  * Test the key values for consistency.
  * @param rng rng to use
  * @param strong whether to perform strong and lengthy version
  * of the test
  * @return true if the test is passed
  */
  virtual bool check_key(RandomNumberGenerator& rng,
                         bool strong) const = 0;


  /**
  * @return X.509 AlgorithmIdentifier for this key
  */
  virtual AlgorithmIdentifier algorithm_identifier() const = 0;

  /**
  * @return BER encoded public key bits
  */
  virtual std::vector<uint8_t> public_key_bits() const = 0;

  /**
  * @return X.509 subject key encoding for this key object
  */
  std::vector<uint8_t> subject_public_key() const;

  // Internal or non-public declarations follow

  /**
  * Returns more than 1 if the output of this algorithm
  * (ciphertext, signature) should be treated as more than one
  * value. This is used for algorithms like DSA and ECDSA, where
  * the (r,s) output pair can be encoded as either a plain binary
  * list or a TLV tagged DER encoding depending on the protocol.
  *
  * This function is public but applications should have few
  * reasons to ever call this.
  *
  * @return number of message parts
  */
  virtual size_t message_parts() const { return 1; }

  /**
  * Returns how large each of the message parts refered to
  * by message_parts() is
  *
  * This function is public but applications should have few
  * reasons to ever call this.
  *
  * @return size of the message parts in bits
  */
  virtual size_t message_part_size() const { return 0; }

  /**
  * This is an internal library function exposed on key types.
  * In almost all cases applications should use wrappers in pubkey.h
  *
  * Return an encryption operation for this key/params or throw
  *
  * @param rng a random number generator. The PK_Op may maintain a
  * reference to the RNG and use it many times. The rng must outlive
  * any operations which reference it.
  * @param params additional parameters
  * @param provider the provider to use
  */
  virtual std::unique_ptr<PK_Ops::Encryption>
  create_encryption_op(RandomNumberGenerator& rng,
                       const std::string& params,
                       const std::string& provider) const;

  /**
  * This is an internal library function exposed on key types.
  * In almost all cases applications should use wrappers in pubkey.h
  *
  * Return a KEM encryption operation for this key/params or throw
  *
  * @param rng a random number generator. The PK_Op may maintain a
  * reference to the RNG and use it many times. The rng must outlive
  * any operations which reference it.
  * @param params additional parameters
  * @param provider the provider to use
  */
  virtual std::unique_ptr<PK_Ops::KEM_Encryption>
  create_kem_encryption_op(RandomNumberGenerator& rng,
                           const std::string& params,
                           const std::string& provider) const;

  /**
  * This is an internal library function exposed on key types.
  * In almost all cases applications should use wrappers in pubkey.h
  *
  * Return a verification operation for this key/params or throw
  * @param params additional parameters
  * @param provider the provider to use
  */
  virtual std::unique_ptr<PK_Ops::Verification>
  create_verification_op(const std::string& params,
                         const std::string& provider) const;
};

/**
* Private Key Base Class
*/
class BOTAN_DLL Private_Key : public virtual Public_Key {
public:
  /**
  * @return BER encoded private key bits
  */
  virtual secure_vector<uint8_t> private_key_bits() const = 0;

  /**
  * @return PKCS #8 private key encoding for this key object
  */
  secure_vector<uint8_t> private_key_info() const;

  /**
  * @return PKCS #8 AlgorithmIdentifier for this key
  * Might be different from the X.509 identifier, but normally is not
  */
  virtual AlgorithmIdentifier pkcs8_algorithm_identifier() const
  { return algorithm_identifier(); }

  // Internal or non-public declarations follow

  /**
   * @return Hash of the PKCS #8 encoding for this key object
   */
  std::string fingerprint(const std::string& alg = "SHA") const;

  /**
  * This is an internal library function exposed on key types.
  * In almost all cases applications should use wrappers in pubkey.h
  *
  * Return an decryption operation for this key/params or throw
  *
  * @param rng a random number generator. The PK_Op may maintain a
  * reference to the RNG and use it many times. The rng must outlive
  * any operations which reference it.
  * @param params additional parameters
  * @param provider the provider to use
  *
  */
  virtual std::unique_ptr<PK_Ops::Decryption>
  create_decryption_op(RandomNumberGenerator& rng,
                       const std::string& params,
                       const std::string& provider) const;

  /**
  * This is an internal library function exposed on key types.
  * In almost all cases applications should use wrappers in pubkey.h
  *
  * Return a KEM decryption operation for this key/params or throw
  *
  * @param rng a random number generator. The PK_Op may maintain a
  * reference to the RNG and use it many times. The rng must outlive
  * any operations which reference it.
  * @param params additional parameters
  * @param provider the provider to use
  */
  virtual std::unique_ptr<PK_Ops::KEM_Decryption>
  create_kem_decryption_op(RandomNumberGenerator& rng,
                           const std::string& params,
                           const std::string& provider) const;

  /**
  * This is an internal library function exposed on key types.
  * In almost all cases applications should use wrappers in pubkey.h
  *
  * Return a signature operation for this key/params or throw
  *
  * @param rng a random number generator. The PK_Op may maintain a
  * reference to the RNG and use it many times. The rng must outlive
  * any operations which reference it.
  * @param params additional parameters
  * @param provider the provider to use
  */
  virtual std::unique_ptr<PK_Ops::Signature>
  create_signature_op(RandomNumberGenerator& rng,
                      const std::string& params,
                      const std::string& provider) const;

  /**
  * This is an internal library function exposed on key types.
  * In almost all cases applications should use wrappers in pubkey.h
  *
  * Return a key agreement operation for this key/params or throw
  *
  * @param rng a random number generator. The PK_Op may maintain a
  * reference to the RNG and use it many times. The rng must outlive
  * any operations which reference it.
  * @param params additional parameters
  * @param provider the provider to use
  */
  virtual std::unique_ptr<PK_Ops::Key_Agreement>
  create_key_agreement_op(RandomNumberGenerator& rng,
                          const std::string& params,
                          const std::string& provider) const;
};

/**
* PK Secret Value Derivation Key
*/
class BOTAN_DLL PK_Key_Agreement_Key : public virtual Private_Key {
public:
  /*
  * @return public component of this key
  */
  virtual std::vector<uint8_t> public_value() const = 0;

  virtual ~PK_Key_Agreement_Key() {}
};

/*
* Old compat typedefs
* TODO: remove these?
*/
typedef PK_Key_Agreement_Key PK_KA_Key;
typedef Public_Key X509_PublicKey;
typedef Private_Key PKCS8_PrivateKey;

}

#endif
