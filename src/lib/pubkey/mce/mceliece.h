/*
 * (C) Copyright Projet SECRET, INRIA, Rocquencourt
 * (C) Bhaskar Biswas and  Nicolas Sendrier
 *
 * (C) 2014 cryptosource GmbH
 * (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 *
 */

#ifndef BOTAN_MCELIECE_KEY_H__
#define BOTAN_MCELIECE_KEY_H__

#include <botan/pk_keys.h>
#include <botan/polyn_gf2m.h>
#include <botan/exceptn.h>

namespace Botan {

class BOTAN_DLL McEliece_PublicKey : public virtual Public_Key {
public:
  explicit McEliece_PublicKey(const std::vector<uint8_t>& key_bits);

  McEliece_PublicKey(std::vector<uint8_t> const& pub_matrix, uint32_t the_t, uint32_t the_code_length) :
    m_public_matrix(pub_matrix),
    m_t(the_t),
    m_code_length(the_code_length)
  {}

  McEliece_PublicKey(const McEliece_PublicKey& other);

  secure_vector<uint8_t> random_plaintext_element(RandomNumberGenerator& rng) const;

  std::string algo_name() const override { return "McEliece"; }

  AlgorithmIdentifier algorithm_identifier() const override;

  size_t key_length() const override;
  size_t estimated_strength() const override;

  std::vector<uint8_t> public_key_bits() const override;

  bool check_key(RandomNumberGenerator&, bool) const override
  { return true; }

  uint32_t get_t() const { return m_t; }
  uint32_t get_code_length() const { return m_code_length; }
  uint32_t get_message_word_bit_length() const;
  const std::vector<uint8_t>& get_public_matrix() const { return m_public_matrix; }

  bool operator==(const McEliece_PublicKey& other) const;
  bool operator!=(const McEliece_PublicKey& other) const { return !(*this == other); }

  std::unique_ptr<PK_Ops::KEM_Encryption>
  create_kem_encryption_op(RandomNumberGenerator& rng,
                           const std::string& params,
                           const std::string& provider) const override;

protected:
  McEliece_PublicKey() : m_t(0), m_code_length(0) {}

  std::vector<uint8_t> m_public_matrix;
  uint32_t m_t;
  uint32_t m_code_length;
};

class BOTAN_DLL McEliece_PrivateKey : public virtual McEliece_PublicKey,
  public virtual Private_Key {
public:

  /**
  Generate a McEliece key pair

  Suggested parameters for a given security level (SL)

  SL=80 n=1632 t=33 - 59 KB pubkey 140 KB privkey
  SL=107 n=2480 t=45 - 128 KB pubkey 300 KB privkey
  SL=128 n=2960 t=57 - 195 KB pubkey 459 KB privkey
  SL=147 n=3408 t=67 - 265 KB pubkey 622 KB privkey
  SL=191 n=4624 t=95 - 516 KB pubkey 1234 KB privkey
  SL=256 n=6624 t=115 - 942 KB pubkey 2184 KB privkey
  */
  McEliece_PrivateKey(RandomNumberGenerator& rng, size_t code_length, size_t t);

  explicit McEliece_PrivateKey(const secure_vector<uint8_t>& key_bits);

  McEliece_PrivateKey(polyn_gf2m const& goppa_polyn,
                      std::vector<uint32_t> const& parity_check_matrix_coeffs,
                      std::vector<polyn_gf2m> const& square_root_matrix,
                      std::vector<gf2m> const& inverse_support,
                      std::vector<uint8_t> const& public_matrix);

  bool check_key(RandomNumberGenerator& rng, bool strong) const override;

  polyn_gf2m const& get_goppa_polyn() const { return m_g; }
  std::vector<uint32_t> const& get_H_coeffs() const { return m_coeffs; }
  std::vector<gf2m> const& get_Linv() const { return m_Linv; }
  std::vector<polyn_gf2m> const& get_sqrtmod() const { return m_sqrtmod; }

  inline uint32_t get_dimension() const { return m_dimension; }

  inline uint32_t get_codimension() const { return m_codimension; }

  secure_vector<uint8_t> private_key_bits() const override;

  bool operator==(const McEliece_PrivateKey& other) const;

  bool operator!=(const McEliece_PrivateKey& other) const { return !(*this == other); }

  std::unique_ptr<PK_Ops::KEM_Decryption>
  create_kem_decryption_op(RandomNumberGenerator& rng,
                           const std::string& params,
                           const std::string& provider) const override;
private:
  polyn_gf2m m_g;
  std::vector<polyn_gf2m> m_sqrtmod;
  std::vector<gf2m> m_Linv;
  std::vector<uint32_t> m_coeffs;

  uint32_t m_codimension;
  uint32_t m_dimension;
};

/**
* Estimate work factor for McEliece
* @return estimated security level for these key parameters
*/
BOTAN_DLL size_t mceliece_work_factor(size_t code_size, size_t t);

}

#endif
