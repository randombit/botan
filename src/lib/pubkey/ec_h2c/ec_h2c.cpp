/*
* (C) 2019,2020,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ec_h2c.h>

#include <botan/ec_group.h>
#include <botan/hash.h>
#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/internal/fmt.h>

namespace Botan {

void expand_message_xmd(std::string_view hash_fn,
                        uint8_t output[],
                        size_t output_len,
                        const uint8_t input[],
                        size_t input_len,
                        const uint8_t domain_sep[],
                        size_t domain_sep_len) {
   if(domain_sep_len > 0xFF) {
      throw Invalid_Argument("expand_message_xmd domain seperator too long");
   }

   auto hash = HashFunction::create_or_throw(hash_fn);
   const size_t block_size = hash->hash_block_size();
   if(block_size == 0) {
      throw Invalid_Argument(fmt("expand_message_xmd cannot be used with {}", hash_fn));
   }

   const size_t hash_output_size = hash->output_length();
   if(output_len > 255 * hash_output_size || output_len > 0xFFFF) {
      throw Invalid_Argument("expand_message_xmd requested output length too long");
   }

   // Compute b_0 = H(msg_prime) = H(Z_pad || msg || l_i_b_str || 0x00 || DST_prime)

   hash->update(std::vector<uint8_t>(block_size));
   hash->update(input, input_len);
   hash->update_be(static_cast<uint16_t>(output_len));
   hash->update(0x00);
   hash->update(domain_sep, domain_sep_len);
   hash->update(static_cast<uint8_t>(domain_sep_len));

   const secure_vector<uint8_t> b_0 = hash->final();

   // Compute b_1 = H(b_0 || 0x01 || DST_prime)

   hash->update(b_0);
   hash->update(0x01);
   hash->update(domain_sep, domain_sep_len);
   hash->update(static_cast<uint8_t>(domain_sep_len));

   secure_vector<uint8_t> b_i = hash->final();

   uint8_t cnt = 2;
   while(output_len > 0) {
      const size_t produced = std::min(output_len, hash_output_size);

      copy_mem(output, b_i.data(), produced);
      output += produced;
      output_len -= produced;

      // Now compute the next b_i

      b_i ^= b_0;
      hash->update(b_i);
      hash->update(cnt);
      hash->update(domain_sep, domain_sep_len);
      hash->update(static_cast<uint8_t>(domain_sep_len));
      hash->final(b_i.data());
      cnt += 1;
   }
}

namespace {

std::vector<BigInt> hash_to_field(const EC_Group& group,
                                  const Modular_Reducer& mod_p,
                                  std::string_view hash_fn,
                                  uint8_t count,
                                  const uint8_t input[],
                                  size_t input_len,
                                  const uint8_t domain_sep[],
                                  size_t domain_sep_len) {
   const size_t k = (group.get_order_bits() + 1) / 2;
   const size_t L = (group.get_p_bits() + k + 7) / 8;

   std::vector<BigInt> results;
   results.reserve(count);

   secure_vector<uint8_t> output(L * count);
   expand_message_xmd(hash_fn, output.data(), output.size(), input, input_len, domain_sep, domain_sep_len);

   for(size_t i = 0; i != count; ++i) {
      BigInt v(&output[i * L], L);
      results.push_back(mod_p.reduce(v));
   }

   return results;
}

BigInt sswu_z(const EC_Group& group) {
   const BigInt& p = group.get_p();
   const OID& oid = group.get_curve_oid();

   if(oid == OID{1, 2, 840, 10045, 3, 1, 7}) {  // secp256r1
      return p - 10;
   }
   if(oid == OID{1, 3, 132, 0, 34}) {  // secp384r1
      return p - 12;
   }
   if(oid == OID{1, 3, 132, 0, 35}) {  // secp521r1
      return p - 4;
   }

   return 0;
}

BigInt ct_choose(bool first, const BigInt& x, const BigInt& y) {
   BigInt z = y;
   z.ct_cond_assign(first, x);
   return z;
}

EC_Point map_to_curve_sswu(const EC_Group& group, const Modular_Reducer& mod_p, const BigInt& u) {
   const BigInt& p = group.get_p();
   const BigInt& A = group.get_a();
   const BigInt& B = group.get_b();
   const BigInt Z = sswu_z(group);

   if(Z.is_zero() || A.is_zero() || B.is_zero() || p % 4 != 3) {
      throw Invalid_Argument("map_to_curve_sswu does not support this curve");
   }

   // These values could be precomputed:
   const BigInt c1 = mod_p.multiply(p - B, inverse_mod(A, p));
   const BigInt c2 = mod_p.multiply(p - 1, inverse_mod(Z, p));

   /*
   * See Appendix F.2 of draft-irtf-cfrg-hash-to-curve
   */

   const BigInt tv1 = mod_p.multiply(Z, mod_p.square(u));
   const BigInt tv2 = mod_p.square(tv1);

   BigInt x1 = inverse_mod(tv1 + tv2, p);
   const bool e1 = x1.is_zero();
   x1 += 1;
   x1.ct_cond_assign(e1, c2);
   x1 = mod_p.multiply(x1, c1);

   // gx1 = x1^3 + A*x1 + B;
   BigInt gx1 = mod_p.square(x1);
   gx1 += A;
   gx1 = mod_p.multiply(gx1, x1);
   gx1 += B;
   gx1 = mod_p.reduce(gx1);

   const BigInt x2 = mod_p.multiply(tv1, x1);

   // gx2 = (Z * u^2)^3 * gx1
   const BigInt gx2 = mod_p.multiply(gx1, mod_p.multiply(tv1, tv2));

   // assumes p % 4 == 3
   const bool gx1_is_square = (power_mod(gx1, (p - 1) / 2, p) <= 1);

   const BigInt x = ct_choose(gx1_is_square, x1, x2);
   const BigInt y2 = ct_choose(gx1_is_square, gx1, gx2);

   // assumes p % 4 == 3
   const BigInt y = power_mod(y2, (p + 1) / 4, p);
   const BigInt neg_y = p - y;

   const bool uy_sign = u.get_bit(0) != y.get_bit(0);
   return group.point(x, ct_choose(uy_sign, neg_y, y));
}

}  // namespace

EC_Point hash_to_curve_sswu(const EC_Group& group,
                            std::string_view hash_fn,
                            const uint8_t input[],
                            size_t input_len,
                            const uint8_t domain_sep[],
                            size_t domain_sep_len,
                            bool random_oracle) {
   const Modular_Reducer mod_p(group.get_p());

   const uint8_t count = (random_oracle ? 2 : 1);

   const auto u = hash_to_field(group, mod_p, hash_fn, count, input, input_len, domain_sep, domain_sep_len);

   EC_Point pt = map_to_curve_sswu(group, mod_p, u[0]);

   for(size_t i = 1; i != u.size(); ++i) {
      pt += map_to_curve_sswu(group, mod_p, u[i]);
   }

   return pt;
}

}  // namespace Botan
