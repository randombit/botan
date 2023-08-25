/*
* Comb4P hash combiner
* (C) 2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/comb4p.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <botan/internal/stl_util.h>

namespace Botan {

namespace {

void comb4p_round(secure_vector<uint8_t>& out,
                  const secure_vector<uint8_t>& in,
                  uint8_t round_no,
                  HashFunction& h1,
                  HashFunction& h2) {
   h1.update(round_no);
   h2.update(round_no);

   h1.update(in.data(), in.size());
   h2.update(in.data(), in.size());

   secure_vector<uint8_t> h_buf = h1.final();
   xor_buf(out.data(), h_buf.data(), std::min(out.size(), h_buf.size()));

   h_buf = h2.final();
   xor_buf(out.data(), h_buf.data(), std::min(out.size(), h_buf.size()));
}

}  // namespace

Comb4P::Comb4P(std::unique_ptr<HashFunction> h1, std::unique_ptr<HashFunction> h2) :
      m_hash1(std::move(h1)), m_hash2(std::move(h2)) {
   if(m_hash1->name() == m_hash2->name()) {
      throw Invalid_Argument("Comb4P: Must use two distinct hashes");
   }

   if(m_hash1->output_length() != m_hash2->output_length()) {
      throw Invalid_Argument(fmt("Comb4P: Incompatible hashes {} and {}", m_hash1->name(), m_hash2->name()));
   }

   clear();
}

std::string Comb4P::name() const {
   return fmt("Comb4P({},{})", m_hash1->name(), m_hash2->name());
}

std::unique_ptr<HashFunction> Comb4P::new_object() const {
   return std::make_unique<Comb4P>(m_hash1->new_object(), m_hash2->new_object());
}

size_t Comb4P::hash_block_size() const {
   if(m_hash1->hash_block_size() == m_hash2->hash_block_size()) {
      return m_hash1->hash_block_size();
   }

   /*
   * Return LCM of the block sizes? This would probably be OK for
   * HMAC, which is the main thing relying on knowing the block size.
   */
   return 0;
}

void Comb4P::clear() {
   m_hash1->clear();
   m_hash2->clear();

   // Prep for processing next message, if any
   m_hash1->update(0);
   m_hash2->update(0);
}

std::unique_ptr<HashFunction> Comb4P::copy_state() const {
   // Can't use make_unique as this constructor is private
   std::unique_ptr<Comb4P> copy(new Comb4P);
   copy->m_hash1 = m_hash1->copy_state();
   copy->m_hash2 = m_hash2->copy_state();
   return copy;
}

void Comb4P::add_data(std::span<const uint8_t> input) {
   m_hash1->update(input);
   m_hash2->update(input);
}

void Comb4P::final_result(std::span<uint8_t> output) {
   secure_vector<uint8_t> h1 = m_hash1->final();
   secure_vector<uint8_t> h2 = m_hash2->final();

   // First round
   xor_buf(h1.data(), h2.data(), std::min(h1.size(), h2.size()));

   // Second round
   comb4p_round(h2, h1, 1, *m_hash1, *m_hash2);

   // Third round
   comb4p_round(h1, h2, 2, *m_hash1, *m_hash2);

   BufferStuffer out(output);
   copy_mem(out.next(h1.size()).data(), h1.data(), h1.size());
   copy_mem(out.next(h2.size()).data(), h2.data(), h2.size());

   // Prep for processing next message, if any
   m_hash1->update(0);
   m_hash2->update(0);
}

}  // namespace Botan
