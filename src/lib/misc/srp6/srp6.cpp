/*
* SRP-6a (RFC 5054 compatatible)
* (C) 2011,2012,2019,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/srp6.h>

#include <botan/dl_group.h>
#include <botan/hash.h>
#include <botan/internal/fmt.h>

namespace Botan {

namespace {

BigInt hash_seq(HashFunction& hash_fn, size_t p_bytes, const BigInt& in1, const BigInt& in2) {
   hash_fn.update(in1.serialize(p_bytes));
   hash_fn.update(in2.serialize(p_bytes));

   return BigInt::from_bytes(hash_fn.final());
}

BigInt compute_x(HashFunction& hash_fn,
                 std::string_view identifier,
                 std::string_view password,
                 const std::vector<uint8_t>& salt) {
   hash_fn.update(identifier);
   hash_fn.update(":");
   hash_fn.update(password);

   secure_vector<uint8_t> inner_h = hash_fn.final();

   hash_fn.update(salt);
   hash_fn.update(inner_h);

   secure_vector<uint8_t> outer_h = hash_fn.final();

   return BigInt::from_bytes(outer_h);
}

}  // namespace

std::string srp6_group_identifier(const BigInt& N, const BigInt& g) {
   /*
   This function assumes that only one 'standard' SRP parameter set has
   been defined for a particular bitsize. As of this writing that is the case.
   */
   try {
      const std::string group_name = "modp/srp/" + std::to_string(N.bits());

      auto group = DL_Group::from_name(group_name);

      if(group.get_p() == N && group.get_g() == g) {
         return group_name;
      }
   } catch(...) {}

   // If we didn't return, the group was unknown or did not match
   throw Invalid_Argument("Invalid or unknown SRP group parameters");
}

std::pair<BigInt, SymmetricKey> srp6_client_agree(std::string_view identifier,
                                                  std::string_view password,
                                                  std::string_view group_id,
                                                  std::string_view hash_id,
                                                  const std::vector<uint8_t>& salt,
                                                  const BigInt& B,
                                                  RandomNumberGenerator& rng) {
   auto group = DL_Group::from_name(group_id);
   const size_t a_bits = group.exponent_bits();

   return srp6_client_agree(identifier, password, group, hash_id, salt, B, a_bits, rng);
}

std::pair<BigInt, SymmetricKey> srp6_client_agree(std::string_view identifier,
                                                  std::string_view password,
                                                  const DL_Group& group,
                                                  std::string_view hash_id,
                                                  const std::vector<uint8_t>& salt,
                                                  const BigInt& B,
                                                  const size_t a_bits,
                                                  RandomNumberGenerator& rng) {
   BOTAN_ARG_CHECK(a_bits <= group.p_bits(), "Invalid a_bits");

   const BigInt& g = group.get_g();
   const BigInt& p = group.get_p();

   const size_t p_bytes = group.p_bytes();

   if(B <= 0 || B >= p) {
      throw Decoding_Error("Invalid SRP parameter from server");
   }

   auto hash_fn = HashFunction::create_or_throw(hash_id);
   if(8 * hash_fn->output_length() >= group.p_bits()) {
      throw Invalid_Argument(fmt("Hash function {} too large for SRP6 with this group", hash_fn->name()));
   }

   const BigInt k = hash_seq(*hash_fn, p_bytes, p, g);

   const BigInt a(rng, a_bits);

   const BigInt A = group.power_g_p(a, a_bits);

   const BigInt u = hash_seq(*hash_fn, p_bytes, A, B);

   const BigInt x = compute_x(*hash_fn, identifier, password, salt);

   const BigInt g_x_p = group.power_g_p(x, hash_fn->output_length() * 8);

   const BigInt B_k_g_x_p = group.mod_p(B - group.multiply_mod_p(k, g_x_p));

   const BigInt a_ux = a + u * x;

   const size_t max_aux_bits = std::max<size_t>(a_bits + 1, 2 * 8 * hash_fn->output_length());
   BOTAN_ASSERT_NOMSG(max_aux_bits >= a_ux.bits());

   const BigInt S = group.power_b_p(B_k_g_x_p, a_ux, max_aux_bits);

   const SymmetricKey Sk(S.serialize<secure_vector<uint8_t>>(p_bytes));

   return std::make_pair(A, Sk);
}

BigInt srp6_generate_verifier(std::string_view identifier,
                              std::string_view password,
                              const std::vector<uint8_t>& salt,
                              std::string_view group_id,
                              std::string_view hash_id) {
   auto group = DL_Group::from_name(group_id);
   return srp6_generate_verifier(identifier, password, salt, group, hash_id);
}

BigInt srp6_generate_verifier(std::string_view identifier,
                              std::string_view password,
                              const std::vector<uint8_t>& salt,
                              const DL_Group& group,
                              std::string_view hash_id) {
   auto hash_fn = HashFunction::create_or_throw(hash_id);
   if(8 * hash_fn->output_length() >= group.p_bits()) {
      throw Invalid_Argument(fmt("Hash function {} too large for SRP6 with this group", hash_fn->name()));
   }

   const BigInt x = compute_x(*hash_fn, identifier, password, salt);
   return group.power_g_p(x, hash_fn->output_length() * 8);
}

BigInt SRP6_Server_Session::step1(const BigInt& v,
                                  std::string_view group_id,
                                  std::string_view hash_id,
                                  RandomNumberGenerator& rng) {
   auto group = DL_Group::from_name(group_id);
   const size_t b_bits = group.exponent_bits();
   return this->step1(v, group, hash_id, b_bits, rng);
}

BigInt SRP6_Server_Session::step1(
   const BigInt& v, const DL_Group& group, std::string_view hash_id, size_t b_bits, RandomNumberGenerator& rng) {
   BOTAN_ARG_CHECK(b_bits <= group.p_bits(), "Invalid b_bits");

   BOTAN_STATE_CHECK(!m_group);
   m_group = std::make_unique<DL_Group>(group);

   const BigInt& g = m_group->get_g();
   const BigInt& p = m_group->get_p();

   m_v = v;
   m_b = BigInt(rng, b_bits);
   m_hash_id = hash_id;

   auto hash_fn = HashFunction::create_or_throw(hash_id);
   if(8 * hash_fn->output_length() >= m_group->p_bits()) {
      throw Invalid_Argument(fmt("Hash function {} too large for SRP6 with this group", hash_fn->name()));
   }

   const BigInt k = hash_seq(*hash_fn, m_group->p_bytes(), p, g);
   m_B = m_group->mod_p(v * k + m_group->power_g_p(m_b, b_bits));

   return m_B;
}

SymmetricKey SRP6_Server_Session::step2(const BigInt& A) {
   BOTAN_STATE_CHECK(m_group);

   if(A <= 0 || A >= m_group->get_p()) {
      throw Decoding_Error("Invalid SRP parameter from client");
   }

   auto hash_fn = HashFunction::create_or_throw(m_hash_id);
   if(8 * hash_fn->output_length() >= m_group->p_bits()) {
      throw Invalid_Argument(fmt("Hash function {} too large for SRP6 with this group", hash_fn->name()));
   }

   const BigInt u = hash_seq(*hash_fn, m_group->p_bytes(), A, m_B);

   const BigInt vup = m_group->power_b_p(m_v, u, m_group->p_bits());
   const BigInt S = m_group->power_b_p(m_group->multiply_mod_p(A, vup), m_b, m_group->p_bits());

   return SymmetricKey(S.serialize<secure_vector<uint8_t>>(m_group->p_bytes()));
}

}  // namespace Botan
