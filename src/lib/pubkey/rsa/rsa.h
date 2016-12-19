/*
* RSA
* (C) 1999-2008,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_RSA_H__
#define BOTAN_RSA_H__

#include <botan/bigint.h>
#include <botan/x509_key.h>

namespace Botan {

/**
* RSA Public Key
*/
class BOTAN_DLL RSA_PublicKey : public virtual Public_Key {
public:
  /**
  * Load a public key.
  * @param alg_id the X.509 algorithm identifier
  * @param key_bits DER encoded public key bits
  */
  RSA_PublicKey(const AlgorithmIdentifier& alg_id,
                const std::vector<uint8_t>& key_bits);

  /**
  * Create a public key.
  * @arg n the modulus
  * @arg e the exponent
  */
  RSA_PublicKey(const BigInt& n, const BigInt& e) :
    m_n(n), m_e(e) {}

  std::string algo_name() const override { return "RSA"; }

  bool check_key(RandomNumberGenerator& rng, bool) const override;

  AlgorithmIdentifier algorithm_identifier() const override;

  std::vector<uint8_t> public_key_bits() const override;

  /**
  * @return public modulus
  */
  const BigInt& get_n() const { return m_n; }

  /**
  * @return public exponent
  */
  const BigInt& get_e() const { return m_e; }

  size_t key_length() const override;
  size_t estimated_strength() const override;

  std::unique_ptr<PK_Ops::Encryption>
  create_encryption_op(RandomNumberGenerator& rng,
                       const std::string& params,
                       const std::string& provider) const override;

  std::unique_ptr<PK_Ops::KEM_Encryption>
  create_kem_encryption_op(RandomNumberGenerator& rng,
                           const std::string& params,
                           const std::string& provider) const override;

  std::unique_ptr<PK_Ops::Verification>
  create_verification_op(const std::string& params,
                         const std::string& provider) const override;

protected:
  RSA_PublicKey() {}

  BigInt m_n, m_e;
};

/**
* RSA Private Key
*/
class BOTAN_DLL RSA_PrivateKey : public Private_Key, public RSA_PublicKey {
public:
  /**
  * Load a private key.
  * @param alg_id the X.509 algorithm identifier
  * @param key_bits PKCS #8 structure
  */
  RSA_PrivateKey(const AlgorithmIdentifier& alg_id,
                 const secure_vector<uint8_t>& key_bits);

  /**
  * Construct a private key from the specified parameters.
  * @param p the first prime
  * @param q the second prime
  * @param e the exponent
  * @param d if specified, this has to be d with
  * exp * d = 1 mod (p - 1, q - 1). Leave it as 0 if you wish to
  * the constructor to calculate it.
  * @param n if specified, this must be n = p * q. Leave it as 0
  * if you wish to the constructor to calculate it.
  */
  RSA_PrivateKey(const BigInt& p, const BigInt& q,
                 const BigInt& e, const BigInt& d = 0,
                 const BigInt& n = 0);

  /**
  * Create a new private key with the specified bit length
  * @param rng the random number generator to use
  * @param bits the desired bit length of the private key
  * @param exp the public exponent to be used
  */
  RSA_PrivateKey(RandomNumberGenerator& rng,
                 size_t bits, size_t exp = 65537);

  bool check_key(RandomNumberGenerator& rng, bool) const override;

  /**
  * Get the first prime p.
  * @return prime p
  */
  const BigInt& get_p() const { return m_p; }

  /**
  * Get the second prime q.
  * @return prime q
  */
  const BigInt& get_q() const { return m_q; }

  /**
  * Get d with exp * d = 1 mod (p - 1, q - 1).
  * @return d
  */
  const BigInt& get_d() const { return m_d; }

  const BigInt& get_c() const { return m_c; }
  const BigInt& get_d1() const { return m_d1; }
  const BigInt& get_d2() const { return m_d2; }

  secure_vector<uint8_t> private_key_bits() const override;

  std::unique_ptr<PK_Ops::Decryption>
  create_decryption_op(RandomNumberGenerator& rng,
                       const std::string& params,
                       const std::string& provider) const override;

  std::unique_ptr<PK_Ops::KEM_Decryption>
  create_kem_decryption_op(RandomNumberGenerator& rng,
                           const std::string& params,
                           const std::string& provider) const override;

  std::unique_ptr<PK_Ops::Signature>
  create_signature_op(RandomNumberGenerator& rng,
                      const std::string& params,
                      const std::string& provider) const override;

private:
  BigInt m_d, m_p, m_q, m_d1, m_d2, m_c;
};

}

#endif
