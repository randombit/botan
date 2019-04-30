/*
* SRP-6a (RFC 5054 compatatible)
* (C) 2011,2012,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/srp6.h>
#include <botan/hash.h>
#include <botan/dl_group.h>
#include <botan/numthry.h>

namespace Botan {

namespace {

BigInt hash_seq(const std::string& hash_id,
                size_t pad_to,
                const BigInt& in1,
                const BigInt& in2)
   {
   std::unique_ptr<HashFunction> hash_fn(HashFunction::create_or_throw(hash_id));

   hash_fn->update(BigInt::encode_1363(in1, pad_to));
   hash_fn->update(BigInt::encode_1363(in2, pad_to));

   return BigInt::decode(hash_fn->final());
   }

BigInt compute_x(const std::string& hash_id,
                 const std::string& identifier,
                 const std::string& password,
                 const std::vector<uint8_t>& salt)
   {
   std::unique_ptr<HashFunction> hash_fn(HashFunction::create_or_throw(hash_id));

   hash_fn->update(identifier);
   hash_fn->update(":");
   hash_fn->update(password);

   secure_vector<uint8_t> inner_h = hash_fn->final();

   hash_fn->update(salt);
   hash_fn->update(inner_h);

   secure_vector<uint8_t> outer_h = hash_fn->final();

   return BigInt::decode(outer_h);
   }

}

std::string srp6_group_identifier(const BigInt& N, const BigInt& g)
   {
   /*
   This function assumes that only one 'standard' SRP parameter set has
   been defined for a particular bitsize. As of this writing that is the case.
   */
   try
      {
      const std::string group_name = "modp/srp/" + std::to_string(N.bits());

      DL_Group group(group_name);

      if(group.get_p() == N && group.get_g() == g)
         return group_name;
      }
   catch(...)
      {
      }

   // If we didn't return, the group was unknown or did not match
   throw Invalid_Argument("Invalid or unknown SRP group parameters");
   }

std::pair<BigInt, SymmetricKey>
srp6_client_agree(const std::string& identifier,
                  const std::string& password,
                  const std::string& group_id,
                  const std::string& hash_id,
                  const std::vector<uint8_t>& salt,
                  const BigInt& B,
                  RandomNumberGenerator& rng)
   {
   DL_Group group(group_id);
   const size_t a_bits = group.exponent_bits();

   return srp6_client_agree(identifier, password, group, hash_id, salt, B, a_bits, rng);
   }

std::pair<BigInt, SymmetricKey>
srp6_client_agree(const std::string& identifier,
                  const std::string& password,
                  const DL_Group& group,
                  const std::string& hash_id,
                  const std::vector<uint8_t>& salt,
                  const BigInt& B,
                  const size_t a_bits,
                  RandomNumberGenerator& rng)
   {
   const BigInt& g = group.get_g();
   const BigInt& p = group.get_p();

   const size_t p_bytes = group.p_bytes();

   if(B <= 0 || B >= p)
      throw Decoding_Error("Invalid SRP parameter from server");

   const BigInt k = hash_seq(hash_id, p_bytes, p, g);

   const BigInt a(rng, a_bits);

   const BigInt A = group.power_g_p(a, a_bits);

   const BigInt u = hash_seq(hash_id, p_bytes, A, B);

   const BigInt x = compute_x(hash_id, identifier, password, salt);

   const BigInt S = power_mod(group.mod_p(B - (k * power_mod(g, x, p))),
                              group.mod_p(a + (u * x)), p);

   const SymmetricKey Sk(BigInt::encode_1363(S, p_bytes));

   return std::make_pair(A, Sk);
   }

BigInt generate_srp6_verifier(const std::string& identifier,
                              const std::string& password,
                              const std::vector<uint8_t>& salt,
                              const std::string& group_id,
                              const std::string& hash_id)
   {
   DL_Group group(group_id);
   return generate_srp6_verifier(identifier, password, salt, group, hash_id);
   }

BigInt generate_srp6_verifier(const std::string& identifier,
                              const std::string& password,
                              const std::vector<uint8_t>& salt,
                              const DL_Group& group,
                              const std::string& hash_id)
   {
   const BigInt x = compute_x(hash_id, identifier, password, salt);
   // FIXME: x should be size of hash fn so avoid computing x.bits() here
   return group.power_g_p(x, x.bits());
   }

BigInt SRP6_Server_Session::step1(const BigInt& v,
                                  const std::string& group_id,
                                  const std::string& hash_id,
                                  RandomNumberGenerator& rng)
   {
   DL_Group group(group_id);
   const size_t b_bits = group.exponent_bits();

   return this->step1(v, group, hash_id, b_bits, rng);
   }

BigInt SRP6_Server_Session::step1(const BigInt& v,
                                  const DL_Group& group,
                                  const std::string& hash_id,
                                  size_t b_bits,
                                  RandomNumberGenerator& rng)
   {
   const BigInt& g = group.get_g();
   const BigInt& p = group.get_p();

   m_p_bytes = p.bytes();
   m_v = v;
   m_b = BigInt(rng, b_bits);
   m_p = p;
   m_hash_id = hash_id;

   const BigInt k = hash_seq(hash_id, m_p_bytes, p, g);

   m_B = group.mod_p(v*k + group.power_g_p(m_b, b_bits));

   return m_B;
   }

SymmetricKey SRP6_Server_Session::step2(const BigInt& A)
   {
   if(A <= 0 || A >= m_p)
      throw Decoding_Error("Invalid SRP parameter from client");

   const BigInt u = hash_seq(m_hash_id, m_p_bytes, A, m_B);

   const BigInt S = power_mod(A * power_mod(m_v, u, m_p), m_b, m_p);

   return BigInt::encode_1363(S, m_p_bytes);
   }

}
