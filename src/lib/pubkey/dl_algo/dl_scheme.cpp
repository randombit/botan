/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/dl_scheme.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/exceptn.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

namespace {

BigInt decode_single_bigint(std::span<const uint8_t> key_bits) {
   BigInt x;
   BER_Decoder(key_bits, BER_Decoder::Limits::DER()).decode(x).verify_end();
   return x;
}

// If false, private keys are chosen uniformly in [2, q)
bool uses_short_exponents(const DL_Group& group) {
   return !(group.has_q() && group.q_bits() >= 160 && group.q_bits() <= 384);
}

BigInt generate_private_dl_key(const DL_Group& group, RandomNumberGenerator& rng) {
   if(uses_short_exponents(group)) {
      return CT::driveby_poison(BigInt(rng, group.exponent_bits()));
   } else {
      return CT::driveby_poison(BigInt::random_integer(rng, BigInt::from_s32(2), group.get_q()));
   }
}

BigInt check_dl_private_key_input(const BigInt& x, const DL_Group& group) {
   if(!group.verify_private_element(x)) {
      throw Decoding_Error("Invalid DL private key");
   }
   return CT::driveby_poison(BigInt(x));
}

/*
* A public upper bound on the bit length of x. This reveals which of these
* ranges x is in, which for keys we generated is determined by the group.
*/
size_t dl_private_key_max_bits(const BigInt& x, const DL_Group& group) {
   const size_t exp_bits = group.exponent_bits();
   if(uses_short_exponents(group) && CT::driveby_unpoison(x < BigInt::power_of_2(exp_bits))) {
      return exp_bits;
   }
   if(group.has_q() && CT::driveby_unpoison(x < group.get_q())) {
      return group.q_bits();
   }
   return group.p_bits();
}

BigInt check_dl_public_key_input(const BigInt& y, const DL_Group& group) {
   // The subgroup check (y^q == 1 mod p) is deferred to check_key() since it can be expensive
   if(y <= 1 || y >= group.get_p() - 1) {
      throw Decoding_Error("Invalid DL public key");
   }
   return y;
}

}  // namespace

DL_PublicKey::DL_PublicKey(const DL_Group& group, const BigInt& public_key) :
      m_group(group), m_public_key(check_dl_public_key_input(public_key, m_group)) {}

DL_PublicKey::DL_PublicKey(const AlgorithmIdentifier& alg_id,
                           std::span<const uint8_t> key_bits,
                           DL_Group_Format format) :
      m_group(alg_id.parameters(), format),
      m_public_key(check_dl_public_key_input(decode_single_bigint(key_bits), m_group)) {}

std::vector<uint8_t> DL_PublicKey::public_key_as_bytes() const {
   return m_public_key.serialize(m_group.p_bytes());
}

std::vector<uint8_t> DL_PublicKey::DER_encode() const {
   std::vector<uint8_t> output;
   DER_Encoder(output).encode(m_public_key);
   return output;
}

bool DL_PublicKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   return m_group.verify_group(rng, strong) && m_group.verify_public_element(m_public_key);
}

size_t DL_PublicKey::estimated_strength() const {
   return m_group.estimated_strength();
}

size_t DL_PublicKey::p_bits() const {
   return m_group.p_bits();
}

DL_PrivateKey::DL_PrivateKey(const DL_Group& group, const BigInt& private_key) :
      m_group(group),
      m_private_key(check_dl_private_key_input(private_key, m_group)),
      m_max_private_key_bits(dl_private_key_max_bits(m_private_key, m_group)),
      m_public_key(m_group.power_g_p(m_private_key, m_max_private_key_bits)) {
   CT::unpoison_all(m_private_key, m_public_key);
}

DL_PrivateKey::DL_PrivateKey(const DL_Group& group, RandomNumberGenerator& rng) :
      m_group(group),
      m_private_key(generate_private_dl_key(group, rng)),
      m_max_private_key_bits(dl_private_key_max_bits(m_private_key, m_group)),
      m_public_key(m_group.power_g_p(m_private_key, m_max_private_key_bits)) {
   CT::unpoison_all(m_private_key, m_public_key);
}

DL_PrivateKey::DL_PrivateKey(const AlgorithmIdentifier& alg_id,
                             std::span<const uint8_t> key_bits,
                             DL_Group_Format format) :
      m_group(alg_id.parameters(), format),
      m_private_key(check_dl_private_key_input(decode_single_bigint(key_bits), m_group)),
      m_max_private_key_bits(dl_private_key_max_bits(m_private_key, m_group)),
      m_public_key(m_group.power_g_p(m_private_key, m_max_private_key_bits)) {
   CT::unpoison_all(m_private_key, m_public_key);
}

secure_vector<uint8_t> DL_PrivateKey::DER_encode() const {
   return DER_Encoder().encode(m_private_key).get_contents();
}

secure_vector<uint8_t> DL_PrivateKey::raw_private_key_bits() const {
   return m_private_key.serialize<secure_vector<uint8_t>>();
}

bool DL_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   return m_group.verify_group(rng, strong) && m_group.verify_private_element(m_private_key);
}

std::shared_ptr<DL_PublicKey> DL_PrivateKey::public_key() const {
   return std::make_shared<DL_PublicKey>(m_group, m_public_key);
}

const BigInt& DL_PublicKey::get_int_field(std::string_view algo, std::string_view field) const {
   if(field == "p") {
      return m_group.get_p();
   } else if(field == "q") {
      return m_group.get_q();
   } else if(field == "g") {
      return m_group.get_g();
   } else if(field == "y") {
      return m_public_key;
   } else {
      throw Unknown_PK_Field_Name(algo, field);
   }
}

const BigInt& DL_PrivateKey::get_int_field(std::string_view algo, std::string_view field) const {
   if(field == "p") {
      return m_group.get_p();
   } else if(field == "q") {
      return m_group.get_q();
   } else if(field == "g") {
      return m_group.get_g();
   } else if(field == "x") {
      return m_private_key;
   } else if(field == "y") {
      return m_public_key;
   } else {
      throw Unknown_PK_Field_Name(algo, field);
   }
}

}  // namespace Botan
