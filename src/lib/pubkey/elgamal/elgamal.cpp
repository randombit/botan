/*
* ElGamal
* (C) 1999-2007,2018,2019,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/elgamal.h>

#include <botan/internal/blinding.h>
#include <botan/internal/dl_scheme.h>
#include <botan/internal/keypair.h>
#include <botan/internal/monty_exp.h>
#include <botan/internal/pk_ops_impl.h>

namespace Botan {

ElGamal_PublicKey::ElGamal_PublicKey(const DL_Group& group, const BigInt& y) {
   m_public_key = std::make_shared<DL_PublicKey>(group, y);
}

ElGamal_PublicKey::ElGamal_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) {
   m_public_key = std::make_shared<DL_PublicKey>(alg_id, key_bits, DL_Group_Format::ANSI_X9_42);
}

size_t ElGamal_PublicKey::estimated_strength() const {
   return m_public_key->estimated_strength();
}

size_t ElGamal_PublicKey::key_length() const {
   return m_public_key->p_bits();
}

AlgorithmIdentifier ElGamal_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), m_public_key->group().DER_encode(DL_Group_Format::ANSI_X9_42));
}

std::vector<uint8_t> ElGamal_PublicKey::raw_public_key_bits() const {
   return m_public_key->public_key_as_bytes();
}

std::vector<uint8_t> ElGamal_PublicKey::public_key_bits() const {
   return m_public_key->DER_encode();
}

const BigInt& ElGamal_PublicKey::get_int_field(std::string_view field) const {
   return m_public_key->get_int_field(algo_name(), field);
}

std::unique_ptr<Private_Key> ElGamal_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<ElGamal_PrivateKey>(rng, m_public_key->group());
}

bool ElGamal_PublicKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   return m_public_key->check_key(rng, strong);
}

ElGamal_PrivateKey::ElGamal_PrivateKey(RandomNumberGenerator& rng, const DL_Group& group) {
   m_private_key = std::make_shared<DL_PrivateKey>(group, rng);
   m_public_key = m_private_key->public_key();
}

ElGamal_PrivateKey::ElGamal_PrivateKey(const DL_Group& group, const BigInt& x) {
   m_private_key = std::make_shared<DL_PrivateKey>(group, x);
   m_public_key = m_private_key->public_key();
}

ElGamal_PrivateKey::ElGamal_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) {
   m_private_key = std::make_shared<DL_PrivateKey>(alg_id, key_bits, DL_Group_Format::ANSI_X9_42);
   m_public_key = m_private_key->public_key();
}

std::unique_ptr<Public_Key> ElGamal_PrivateKey::public_key() const {
   return std::unique_ptr<Public_Key>(new ElGamal_PublicKey(m_public_key));
}

const BigInt& ElGamal_PrivateKey::get_int_field(std::string_view field) const {
   return m_private_key->get_int_field(algo_name(), field);
}

secure_vector<uint8_t> ElGamal_PrivateKey::private_key_bits() const {
   return m_private_key->DER_encode();
}

secure_vector<uint8_t> ElGamal_PrivateKey::raw_private_key_bits() const {
   return m_private_key->raw_private_key_bits();
}

bool ElGamal_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   if(!m_private_key->check_key(rng, strong)) {
      return false;
   }

#if defined(BOTAN_HAS_OAEP) && defined(BOTAN_HAS_SHA_256)
   const std::string padding = "OAEP(SHA-256)";
#else
   const std::string padding = "Raw";
#endif

   return KeyPair::encryption_consistency_check(rng, *this, padding);
}

namespace {

/**
* ElGamal encryption operation
*/
class ElGamal_Encryption_Operation final : public PK_Ops::Encryption_with_EME {
   public:
      ElGamal_Encryption_Operation(const std::shared_ptr<const DL_PublicKey>& key, std::string_view eme) :
            PK_Ops::Encryption_with_EME(eme), m_key(key) {
         const size_t powm_window = 4;
         m_monty_y_p = monty_precompute(m_key->group().monty_params_p(), m_key->public_key(), powm_window);
      }

      size_t ciphertext_length(size_t /*ptext_len*/) const override { return 2 * m_key->group().p_bytes(); }

      size_t max_ptext_input_bits() const override { return m_key->group().p_bits() - 1; }

      std::vector<uint8_t> raw_encrypt(std::span<const uint8_t> ptext, RandomNumberGenerator& rng) override;

   private:
      std::shared_ptr<const DL_PublicKey> m_key;
      std::shared_ptr<const Montgomery_Exponentation_State> m_monty_y_p;
};

std::vector<uint8_t> ElGamal_Encryption_Operation::raw_encrypt(std::span<const uint8_t> ptext,
                                                               RandomNumberGenerator& rng) {
   BigInt m(ptext);

   const auto& group = m_key->group();

   if(m >= group.get_p()) {
      throw Invalid_Argument("ElGamal encryption: Input is too large");
   }

   /*
   Some weird PGP implementations generate keys using bad parameters
   which result in easily breakable encryption if short exponents are
   used during encryption. To avoid this problem, always use full size
   exponents.

   See https://eprint.iacr.org/2021/923
   */
   const size_t k_bits = group.p_bits() - 1;
   const BigInt k(rng, k_bits, false);

   const BigInt a = group.power_g_p(k, k_bits);
   const BigInt b = group.multiply_mod_p(m, monty_execute(*m_monty_y_p, k, k_bits).value());

   return unlock(BigInt::encode_fixed_length_int_pair(a, b, group.p_bytes()));
}

/**
* ElGamal decryption operation
*/
class ElGamal_Decryption_Operation final : public PK_Ops::Decryption_with_EME {
   public:
      ElGamal_Decryption_Operation(const std::shared_ptr<const DL_PrivateKey>& key,
                                   std::string_view eme,
                                   RandomNumberGenerator& rng) :
            PK_Ops::Decryption_with_EME(eme),
            m_key(key),
            m_blinder(
               m_key->group()._reducer_mod_p(),
               rng,
               [](const BigInt& k) { return k; },
               [this](const BigInt& k) { return powermod_x_p(k); }) {}

      size_t plaintext_length(size_t /*ctext_len*/) const override { return m_key->group().p_bytes(); }

      secure_vector<uint8_t> raw_decrypt(std::span<const uint8_t> ctext) override;

   private:
      BigInt powermod_x_p(const BigInt& v) const { return m_key->group().power_b_p(v, m_key->private_key()); }

      std::shared_ptr<const DL_PrivateKey> m_key;
      Blinder m_blinder;
};

secure_vector<uint8_t> ElGamal_Decryption_Operation::raw_decrypt(std::span<const uint8_t> ctext) {
   const auto& group = m_key->group();

   const size_t p_bytes = group.p_bytes();

   if(ctext.size() != 2 * p_bytes) {
      throw Invalid_Argument("ElGamal decryption: Invalid message");
   }

   BigInt a(ctext.first(p_bytes));
   const BigInt b(ctext.last(p_bytes));

   if(a >= group.get_p() || b >= group.get_p()) {
      throw Invalid_Argument("ElGamal decryption: Invalid message");
   }

   a = m_blinder.blind(a);

   const BigInt r = group.multiply_mod_p(group.inverse_mod_p(powermod_x_p(a)), b);

   return m_blinder.unblind(r).serialize<secure_vector<uint8_t>>(p_bytes);
}

}  // namespace

std::unique_ptr<PK_Ops::Encryption> ElGamal_PublicKey::create_encryption_op(RandomNumberGenerator& /*rng*/,
                                                                            std::string_view params,
                                                                            std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<ElGamal_Encryption_Operation>(this->m_public_key, params);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Decryption> ElGamal_PrivateKey::create_decryption_op(RandomNumberGenerator& rng,
                                                                             std::string_view params,
                                                                             std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<ElGamal_Decryption_Operation>(this->m_private_key, params, rng);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
