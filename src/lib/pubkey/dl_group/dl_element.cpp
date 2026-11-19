/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/dl_element.h>

#include <botan/dl_group.h>
#include <botan/rng.h>
#include <botan/internal/dl_group_data.h>
#include <botan/internal/mod_inv.h>
#include <botan/internal/monty_exp.h>

namespace Botan {

DL_Element::DL_Element(std::shared_ptr<const DL_Group_Data> group, Montgomery_Int v) :
      m_group(std::move(group)), m_v(std::move(v)) {}

//static
DL_Element DL_Element::from_bigint(const DL_Group& group, const BigInt& x) {
   const auto& data = group._data();
   // The Montgomery_Int constructor rejects x outside of [0,p)
   return DL_Element(data, Montgomery_Int(data->monty_params_p(), x));
}

//static
DL_Element DL_Element::random(const DL_Group& group, RandomNumberGenerator& rng) {
   return DL_Element::from_bigint(group, BigInt::random_integer(rng, BigInt::one(), group.get_p()));
}

//static
DL_Element DL_Element::g_pow(const DL_Group& group, const BigInt& k, size_t max_k_bits) {
   const auto& data = group._data();
   return DL_Element(data, data->monty_power_g_p(k, max_k_bits));
}

//static
std::optional<DL_Element> DL_Element::inverse_of_g(const DL_Group& group) {
   const auto& data = group._data();
   if(const auto& g_inv = data->g_inv()) {
      return DL_Element(data, Montgomery_Int(data->monty_params_p(), *g_inv));
   }
   return std::nullopt;
}

DL_Element DL_Element::pow(const BigInt& k, size_t max_k_bits) const {
   const auto table = monty_precompute(m_v, /*window bits=*/4);
   return DL_Element(m_group, monty_execute(*table, k, max_k_bits));
}

DL_Element DL_Element::mul(const DL_Element& x) const {
   check_same_group(x);
   secure_vector<word> ws;
   return DL_Element(m_group, m_v.mul(x.m_v, ws));
}

DL_Element DL_Element::add(const DL_Element& x) const {
   check_same_group(x);
   return DL_Element(m_group, m_v + x.m_v);
}

DL_Element DL_Element::sub(const DL_Element& x) const {
   check_same_group(x);
   return DL_Element(m_group, m_v - x.m_v);
}

DL_Element DL_Element::square() const {
   secure_vector<word> ws;
   return DL_Element(m_group, m_v.square(ws));
}

DL_Element DL_Element::invert() const {
   const BigInt inv = inverse_mod_public_prime(m_v.value(), m_group->p());
   return DL_Element(m_group, Montgomery_Int(params(), inv));
}

size_t DL_Element::bytes() const {
   return m_group->p_bytes();
}

void DL_Element::serialize_to(std::span<uint8_t> out) const {
   BOTAN_ARG_CHECK(out.size() == bytes(), "Invalid output length for DL_Element");

   const BigInt v = m_v.value();
   const auto words = v._as_span();

   for(size_t i = 0; i != out.size(); ++i) {
      const word w = words[i / sizeof(word)];
      out[out.size() - 1 - i] = static_cast<uint8_t>(w >> (8 * (i % sizeof(word))));
   }
}

BigInt DL_Element::to_bigint() const {
   return m_v.value();
}

const Montgomery_Params& DL_Element::params() const {
   return m_group->monty_params_p();
}

void DL_Element::check_same_group(const DL_Element& other) const {
   BOTAN_ARG_CHECK(m_group == other.m_group, "DL_Element group mismatch");
}

}  // namespace Botan
