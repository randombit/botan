/**
 * (C) 2014 cryptosource GmbH
 * (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
 *
 * Distributed under the terms of the Botan license
 *
 */

#include <botan/mce_overbeck_cca2.h>
#include <botan/sha2_64.h>
#include <botan/mceliece.h>
#include <botan/internal/xor_buf.h>

namespace Botan
{

  McEliece_Overbeck_CCA2_Public_Operation::McEliece_Overbeck_CCA2_Public_Operation(const McEliece_PublicKey& public_key)
    :m_raw_pub_op(public_key, public_key.get_code_length())
  {
    if(public_key.get_message_word_bit_length() < 1024)
    {
      // k is smaller than the minimum required length for Overbeck conversion
      // using SHA-512
      throw Invalid_Argument("McEliece parameters are too small to support the Overbeck conversion with SHA-512, the dimension of the code must be at least 1024");
    }
  }


  secure_vector<byte> McEliece_Overbeck_CCA2_Public_Operation::encrypt(const byte msg[], size_t msg_len, RandomNumberGenerator& rng)
  {
    const u32bit k = m_raw_pub_op.max_input_bits();
    const u32bit l = 512; // output length of SHA-512
    const u32bit l_bytes = l/8;
    const u32bit u1_bit_length = k - l;
    const u32bit u1_length_ceil = (u1_bit_length + 7)/8; // valid lengths ensured already during construction
    const McEliece_PublicKey & key = m_raw_pub_op.get_key();
    const u32bit n = key.get_code_length();
    const u32bit n_bytes_ceil = (n+7)/8;
    const u32bit k_bytes_ceil = (k+7)/8;

    if(msg_len != l_bytes)
    {
      throw Invalid_Argument("McEliece/Overbeck message lengtth must be 64 bytes");
    }
     secure_vector<byte> u1(u1_length_ceil);
    rng.randomize(&u1[0], u1.size());
   // unused bits of final byte of u1 must be set to zero
    u32bit used = u1_bit_length % 8;
   if(used)
   {
      byte mask = (1 << used) - 1;

      u1[u1.size() - 1] &= mask;
   }

    secure_vector<byte> u2(l_bytes);
    rng.randomize(&u2[0], u2.size());

    // compute the hash of m||u1:
    SHA_512 hash;

    hash.update(msg, msg_len);
    hash.update(u2);
    secure_vector<byte> hash_m_u2 = hash.final();

    //std::cout << "enc hash_m_u2 " << hex_encode(hash_m_u2) << "\n";

    secure_vector<byte> mce_msg(k_bytes_ceil);
    std::memcpy(&mce_msg[0], &hash_m_u2[0], hash_m_u2.size());
    std::memcpy(&mce_msg[hash_m_u2.size()], &u1[0], u1.size());

// create the error vector
    secure_vector<gf2m> err_pos = create_random_error_positions(n, key.get_t(), rng);

    secure_vector<byte> err_vec = mceliece_message_parts::error_vector_from_error_positions(&err_pos[0], err_pos.size(), n);

    mceliece_message_parts parts(err_pos, mce_msg, n);

    secure_vector<byte> message_and_error_input = parts.get_concat();

    //std::cout << "enc msg_and_error " << hex_encode(message_and_error_input) << "\n";
    //std::cout << "enc h(msg_and_error) " << hex_encode(hash.process(message_and_error_input)) << "\n";

    secure_vector<byte> mce_ct = m_raw_pub_op.encrypt(&message_and_error_input[0], message_and_error_input.size(), rng);

    secure_vector<byte> result(n_bytes_ceil + 2*l_bytes);

    BOTAN_ASSERT(mce_ct.size() == (key.get_code_length()+7)/8, "Expected size");

    std::memcpy(&result[0], &mce_ct[0], mce_ct.size());


    // z2 part of the ciphertext
    SHA_512 hash2;
    secure_vector<byte> hash_u1 = hash2.process(u1);

    //std::cout << "enc hash_u1 " << hex_encode(hash_u1) << "\n";

    xor_buf(&result[mce_ct.size()], &hash_u1[0], &msg[0], l_bytes);

    // 3rd part of the overbeck ct
    SHA_512 hash3;
    secure_vector<byte> err_hash = hash3.process(err_vec);

    //std::cout << "enc err_hash " << hex_encode(err_hash) << "\n";

    const u32bit z3_offs = n_bytes_ceil + l_bytes;
    xor_buf(&result[z3_offs], &u2[0], &err_hash[0], l_bytes);

    return result;
  }

  McEliece_Overbeck_CCA2_Private_Operation::McEliece_Overbeck_CCA2_Private_Operation(const McEliece_PrivateKey& mce_key)
    :m_raw_priv_op(mce_key)
  {
    if(mce_key.get_dimension() < 1024)
    {
      // k is smaller than the minimum required length for Overbeck conversion
      // using SHA-512
      throw Invalid_Argument("McEliece parameters are too small to support the Overbeck conversion with SHA-512, the dimension of the code must be at least 1024");
    }
  }

  secure_vector<byte> McEliece_Overbeck_CCA2_Private_Operation::decrypt(const byte msg[], size_t msg_len)
  {

    const McEliece_PrivateKey& key = m_raw_priv_op.get_key();
    const u32bit k = key.get_dimension();
    const u32bit l = 512; // output length of SHA-512
    const u32bit l_bytes = l/8;
    const u32bit r_length_ceil = (k - l + 7)/8; // valid lengths ensured already during construction
    const u32bit n = key.get_code_length();
    const u32bit n_bytes_ceil = (n+7)/8;

    const u32bit z2_offs = n_bytes_ceil;
    const u32bit z3_offs = n_bytes_ceil + l_bytes;

    if(msg_len != (max_input_bits()+7)/8)
    {
      throw Invalid_Argument("wrong length of McEliece/Overbeck ciphertext");
    }
    secure_vector<byte> mce_pt_and_err  = m_raw_priv_op.decrypt(msg, n_bytes_ceil);

    SHA_512 hash;
    //std::cout << "dec msg_and_error " << hex_encode(mce_pt_and_err) << "\n";
    //std::cout << "dec h(msg_and_error) " << hex_encode(hash.process(mce_pt_and_err)) << "\n";

    mceliece_message_parts parts(&mce_pt_and_err[0], mce_pt_and_err.size(), n);

    secure_vector<byte> mce_pt = parts.get_message_word();
    secure_vector<byte> err_vec = parts.get_error_vector();

    secure_vector<byte> h(l_bytes);
    std::memcpy(&h[0], &mce_pt[0], l_bytes);
    secure_vector<byte> r(r_length_ceil);
    std::memcpy(&r[0], &mce_pt[l_bytes], r.size());

    secure_vector<byte> hash_r = hash.process(r);
    //std::cout << "dec hash_r " << hex_encode(hash_r) << "\n";

    secure_vector<byte> m(l_bytes);
    xor_buf(&m[0], &msg[z2_offs], &hash_r[0], l_bytes);

    SHA_512 hash2;
    secure_vector<byte> hash_e = hash2.process(err_vec);
    //std::cout << "dec hash_e " << hex_encode(hash_e) << "\n";
    xor_buf(&hash_e[0], &msg[z3_offs], l_bytes);
    // hash_e now is H(e) ^ z3 = u2

    SHA_512 hash3;
    hash3.update(m);
    hash3.update(hash_e);
    secure_vector<byte> h_cmp = hash3.final();

    //std::cout << "dec hash_cmp " << hex_encode(h_cmp) << "\n";
    if(h_cmp != h)
       throw Integrity_Failure("McEliece/Overbeck CCA2 check failed");
    return m;

  }

}
