/*
* Comb4P hash combiner
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/comb4p.h>
#include <botan/internal/xor_buf.h>
#include <stdexcept>

namespace Botan {

namespace {

void comb4p_round(secure_vector<byte>& out,
                  const secure_vector<byte>& in,
                  byte round_no,
                  HashFunction* h1,
                  HashFunction* h2)
   {
   h1->update(round_no);
   h2->update(round_no);

   h1->update(&in[0], in.size());
   h2->update(&in[0], in.size());

   secure_vector<byte> h_buf = h1->final();
   xor_buf(&out[0], &h_buf[0], std::min(out.size(), h_buf.size()));

   h_buf = h2->final();
   xor_buf(&out[0], &h_buf[0], std::min(out.size(), h_buf.size()));
   }

}

Comb4P::Comb4P(HashFunction* h1, HashFunction* h2) :
   hash1(h1), hash2(h2)
   {
   if(hash1->name() == hash2->name())
      throw std::invalid_argument("Comb4P: Must use two distinct hashes");

   if(hash1->output_length() != hash2->output_length())
      throw std::invalid_argument("Comb4P: Incompatible hashes " +
                                  hash1->name() + " and " +
                                  hash2->name());

   clear();
   }

size_t Comb4P::hash_block_size() const
   {
   if(hash1->hash_block_size() == hash2->hash_block_size())
      return hash1->hash_block_size();

   /*
   * Return LCM of the block sizes? This would probably be OK for
   * HMAC, which is the main thing relying on knowing the block size.
   */
   return 0;
   }

void Comb4P::clear()
   {
   hash1->clear();
   hash2->clear();

   // Prep for processing next message, if any
   hash1->update(0);
   hash2->update(0);
   }

void Comb4P::add_data(const byte input[], size_t length)
   {
   hash1->update(input, length);
   hash2->update(input, length);
   }

void Comb4P::final_result(byte out[])
   {
   secure_vector<byte> h1 = hash1->final();
   secure_vector<byte> h2 = hash2->final();

   // First round
   xor_buf(&h1[0], &h2[0], std::min(h1.size(), h2.size()));

   // Second round
   comb4p_round(h2, h1, 1, hash1, hash2);

   // Third round
   comb4p_round(h1, h2, 2, hash1, hash2);

   copy_mem(out            , &h1[0], h1.size());
   copy_mem(out + h1.size(), &h2[0], h2.size());

   // Prep for processing next message, if any
   hash1->update(0);
   hash2->update(0);
   }

}

