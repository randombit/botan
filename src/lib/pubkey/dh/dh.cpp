/*
* Diffie-Hellman
* (C) 1999-2007,2016,2019,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/dh.h>

#include <botan/internal/blinding.h>
#include <botan/internal/dl_scheme.h>
#include <botan/internal/pk_ops_impl.h>

namespace Botan {

DH_PublicKey::DH_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) {
   m_public_key = std::make_shared<DL_PublicKey>(alg_id, key_bits, DL_Group_Format::ANSI_X9_42);
}

DH_PublicKey::DH_PublicKey(const DL_Group& group, const BigInt& y) {
   m_public_key = std::make_shared<DL_PublicKey>(group, y);
}

std::vector<uint8_t> DH_PublicKey::public_value() const {
   return m_public_key->public_key_as_bytes();
}

size_t DH_PublicKey::estimated_strength() const {
   return m_public_key->estimated_strength();
}

size_t DH_PublicKey::key_length() const {
   return m_public_key->p_bits();
}

const BigInt& DH_PublicKey::get_int_field(std::string_view field) const {
   return m_public_key->get_int_field(algo_name(), field);
}

const DL_Group& DH_PublicKey::group() const {
   return m_public_key->group();
}

AlgorithmIdentifier DH_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), m_public_key->group().DER_encode(DL_Group_Format::ANSI_X9_42));
}

std::vector<uint8_t> DH_PublicKey::raw_public_key_bits() const {
   return public_value();
}

std::vector<uint8_t> DH_PublicKey::public_key_bits() const {
   return m_public_key->DER_encode();
}

bool DH_PublicKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   return m_public_key->check_key(rng, strong);
}

std::unique_ptr<Private_Key> DH_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<DH_PrivateKey>(rng, group());
}

DH_PrivateKey::DH_PrivateKey(RandomNumberGenerator& rng, const DL_Group& group) {
   m_private_key = std::make_shared<DL_PrivateKey>(group, rng);
   m_public_key = m_private_key->public_key();
}

DH_PrivateKey::DH_PrivateKey(const DL_Group& group, const BigInt& x) {
   m_private_key = std::make_shared<DL_PrivateKey>(group, x);
   m_public_key = m_private_key->public_key();
}

DH_PrivateKey::DH_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) {
   m_private_key = std::make_shared<DL_PrivateKey>(alg_id, key_bits, DL_Group_Format::ANSI_X9_42);
   m_public_key = m_private_key->public_key();
}

std::unique_ptr<Public_Key> DH_PrivateKey::public_key() const {
   return std::unique_ptr<DH_PublicKey>(new DH_PublicKey(m_public_key));
}

std::vector<uint8_t> DH_PrivateKey::public_value() const {
   return DH_PublicKey::public_value();
}

secure_vector<uint8_t> DH_PrivateKey::private_key_bits() const {
   return m_private_key->DER_encode();
}

secure_vector<uint8_t> DH_PrivateKey::raw_private_key_bits() const {
   return m_private_key->raw_private_key_bits();
}

const BigInt& DH_PrivateKey::get_int_field(std::string_view field) const {
   return m_private_key->get_int_field(algo_name(), field);
}

namespace {

/**
* DH operation
*/
class DH_KA_Operation final : public PK_Ops::Key_Agreement_with_KDF {
   public:
      DH_KA_Operation(const std::shared_ptr<const DL_PrivateKey>& key,
                      std::string_view kdf,
                      RandomNumberGenerator& rng) :
            PK_Ops::Key_Agreement_with_KDF(kdf),
            m_key(key),
            m_key_bits(m_key->private_key().bits()),
            m_blinder(
               m_key->group().get_p(),
               rng,
               [](const BigInt& k) { return k; },
               [this](const BigInt& k) {
                  const BigInt inv_k = inverse_mod(k, group().get_p());
                  return powermod_x_p(inv_k);
               }) {}

      size_t agreed_value_size() const override { return group().p_bytes(); }

      secure_vector<uint8_t> raw_agree(const uint8_t w[], size_t w_len) override;

   private:
      const DL_Group& group() const { return m_key->group(); }

      BigInt powermod_x_p(const BigInt& v) const { return group().power_b_p(v, m_key->private_key(), m_key_bits); }

      std::shared_ptr<const DL_PrivateKey> m_key;
      std::shared_ptr<const Montgomery_Params> m_monty_p;
      const size_t m_key_bits;
      Blinder m_blinder;
};

secure_vector<uint8_t> DH_KA_Operation::raw_agree(const uint8_t w[], size_t w_len) {
   BigInt v = BigInt::from_bytes(std::span{w, w_len});

   if(v <= 1 || v >= group().get_p()) {
      throw Invalid_Argument("DH agreement - invalid key provided");
   }

   v = m_blinder.blind(v);
   v = powermod_x_p(v);
   v = m_blinder.unblind(v);

   return v.serialize<secure_vector<uint8_t>>(group().p_bytes());
}

}  // namespace

std::unique_ptr<PK_Ops::Key_Agreement> DH_PrivateKey::create_key_agreement_op(RandomNumberGenerator& rng,
                                                                              std::string_view params,
                                                                              std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<DH_KA_Operation>(this->m_private_key, params, rng);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
