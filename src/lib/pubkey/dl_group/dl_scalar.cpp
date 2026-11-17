/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/dl_scalar.h>

#include <botan/dl_group.h>
#include <botan/mem_ops.h>
#include <botan/rng.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/dl_group_data.h>
#include <botan/internal/monty_exp.h>
#include <botan/internal/mp_core.h>
#include <algorithm>

namespace Botan {

namespace {

/*
* Return x mod q for an integer in [0,p), using Horner's rule over chunks of x
* the size of q. This does a fixed amount of work for any x in [0,p).
*/
Montgomery_Int reduce_mod_q(const DL_Group_Data& group, const Montgomery_Int& x) {
   const auto& params_q = group.monty_params_q();
   const size_t p_words = group.monty_params_p().p_words();
   const size_t q_words = params_q.p_words();

   const word* q = params_q.p()._data();
   const word q_dash = params_q.p_dash();

   const BigInt x_bn = x.value();
   BOTAN_ASSERT_NOMSG(x_bn.size() >= p_words);
   const auto x_words = x_bn._as_span().first(p_words);

   secure_vector<word> t(2 * q_words);
   secure_vector<word> ws(4 * q_words);
   const auto t_lo = std::span{t}.first(q_words);
   const auto t_hi = std::span{t}.last(q_words);

   for(size_t i = ceil_division(p_words, q_words); i > 0; --i) {
      const auto chunk = x_words.subspan((i - 1) * q_words);
      const size_t chunk_len = std::min(q_words, chunk.size());

      // The high half of t is the accumulator, which is less than q, so t < q*R
      // and Montgomery reduction gives t/R mod q
      clear_mem(t_lo);
      copy_mem(t_lo.first(chunk_len), chunk.first(chunk_len));
      bigint_monty_redc_inplace(t.data(), q, q_words, q_dash, ws.data(), ws.size());

      // Multiplying by R^2 gives t mod q, and by R^3 its Montgomery form
      const BigInt& r = (i == 1) ? params_q.R3() : params_q.R2();
      bigint_monty_mul(t_hi.data(), t_lo.data(), r._data(), q, q_words, q_dash, ws.data(), ws.size());
   }

   return Montgomery_Int(params_q, t_hi);
}

}  // namespace

DL_Scalar::DL_Scalar(std::shared_ptr<const DL_Group_Data> group, Montgomery_Int v) :
      m_group(std::move(group)), m_v(std::move(v)) {}

//static
DL_Scalar DL_Scalar::from_bigint(const DL_Group& group, const BigInt& x) {
   const auto& data = group._data();
   // The Montgomery_Int constructor rejects x outside of [0,q)
   return DL_Scalar(data, Montgomery_Int(data->monty_params_q(), x));
}

//static
DL_Scalar DL_Scalar::random(const DL_Group& group, RandomNumberGenerator& rng) {
   return DL_Scalar::from_bigint(group, BigInt::random_integer(rng, BigInt::one(), group.get_q()));
}

//static
std::optional<DL_Scalar> DL_Scalar::deserialize(const DL_Group& group, std::span<const uint8_t> bytes) {
   const auto& data = group._data();
   const auto& params_q = data->monty_params_q();

   if(bytes.size() != data->q_bytes()) {
      return std::nullopt;
   }

   const BigInt x = BigInt::from_bytes(bytes);
   if(x >= data->q()) {
      return std::nullopt;
   }

   return DL_Scalar(data, Montgomery_Int(params_q, x));
}

//static
DL_Scalar DL_Scalar::from_bytes_with_trunc(const DL_Group& group, std::span<const uint8_t> bytes) {
   const auto& data = group._data();
   const auto& params_q = data->monty_params_q();

   BigInt x = BigInt::from_bytes_with_max_bits(bytes.data(), bytes.size(), data->q_bits());

   // x < 2^q_bits < 2*q
   if(x >= data->q()) {
      x -= data->q();
   }

   return DL_Scalar(data, Montgomery_Int(params_q, x));
}

//static
DL_Scalar DL_Scalar::g_pow_mod_q(const DL_Scalar& k) {
   const auto& data = *k.m_group;
   const auto gk = data.monty_power_g_p(k.to_bigint(), data.q_bits());
   return DL_Scalar(k.m_group, reduce_mod_q(data, gk));
}

//static
DL_Scalar DL_Scalar::multi_exp_mod_q_vartime(const DL_Scalar& a, const BigInt& y, const DL_Scalar& b) {
   a.check_same_group(b);
   const auto& data = *a.m_group;
   const auto v = monty_multi_exp(data.monty_params_p(), data.g(), a.to_bigint(), y, b.to_bigint());
   return DL_Scalar(a.m_group, reduce_mod_q(data, v));
}

DL_Scalar DL_Scalar::mul(const DL_Scalar& x) const {
   check_same_group(x);
   secure_vector<word> ws;
   return DL_Scalar(m_group, m_v.mul(x.m_v, ws));
}

DL_Scalar DL_Scalar::add(const DL_Scalar& x) const {
   check_same_group(x);
   return DL_Scalar(m_group, m_v + x.m_v);
}

DL_Scalar DL_Scalar::square() const {
   secure_vector<word> ws;
   return DL_Scalar(m_group, m_v.square(ws));
}

DL_Scalar DL_Scalar::invert() const {
   BOTAN_ARG_CHECK(!is_zero(), "Cannot invert zero");

   // Fermat's little theorem, with the public exponent q-2
   const auto table = monty_precompute(m_v, /*window bits=*/4);
   return DL_Scalar(m_group, monty_execute_vartime(*table, m_group->q() - 2));
}

bool DL_Scalar::is_zero() const {
   return m_v.is_zero();
}

bool DL_Scalar::is_eq(const DL_Scalar& x) const {
   check_same_group(x);
   return CT::is_equal(std::span{m_v.repr()}, std::span{x.m_v.repr()}).as_bool();
}

size_t DL_Scalar::bytes() const {
   return m_group->q_bytes();
}

void DL_Scalar::serialize_to(std::span<uint8_t> out) const {
   BOTAN_ARG_CHECK(out.size() == bytes(), "Invalid output length for DL_Scalar");

   const BigInt v = m_v.value();
   const auto words = v._as_span();

   for(size_t i = 0; i != out.size(); ++i) {
      const word w = words[i / sizeof(word)];
      out[out.size() - 1 - i] = static_cast<uint8_t>(w >> (8 * (i % sizeof(word))));
   }
}

BigInt DL_Scalar::to_bigint() const {
   return m_v.value();
}

void DL_Scalar::check_same_group(const DL_Scalar& other) const {
   BOTAN_ARG_CHECK(m_group == other.m_group, "DL_Scalar group mismatch");
}

}  // namespace Botan
