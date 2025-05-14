/*
* CCM Mode Encryption
* (C) 2013,2018 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ccm.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

namespace Botan {

// 128-bit cipher is intrinsic to CCM definition
static const size_t CCM_BS = 16;

/*
* CCM_Mode Constructor
*/
CCM_Mode::CCM_Mode(std::unique_ptr<BlockCipher> cipher, size_t tag_size, size_t L) :
      m_tag_size(tag_size), m_L(L), m_cipher(std::move(cipher)) {
   if(m_cipher->block_size() != CCM_BS) {
      throw Invalid_Argument(m_cipher->name() + " cannot be used with CCM mode");
   }

   if(L < 2 || L > 8) {
      throw Invalid_Argument(fmt("Invalid CCM L value {}", L));
   }

   if(tag_size < 4 || tag_size > 16 || tag_size % 2 != 0) {
      throw Invalid_Argument(fmt("Invalid CCM tag length {}", tag_size));
   }
}

void CCM_Mode::clear() {
   m_cipher->clear();
   reset();
}

void CCM_Mode::reset() {
   m_nonce.clear();
   m_msg_buf.clear();
   m_ad_buf.clear();
}

std::string CCM_Mode::name() const {
   return fmt("{}/CCM({},{})", m_cipher->name(), tag_size(), L());
}

bool CCM_Mode::valid_nonce_length(size_t n) const {
   return (n == (15 - L()));
}

size_t CCM_Mode::default_nonce_length() const {
   return (15 - L());
}

size_t CCM_Mode::update_granularity() const {
   return 1;
}

size_t CCM_Mode::ideal_granularity() const {
   // Completely arbitrary
   return m_cipher->parallel_bytes();
}

bool CCM_Mode::requires_entire_message() const {
   return true;
}

Key_Length_Specification CCM_Mode::key_spec() const {
   return m_cipher->key_spec();
}

bool CCM_Mode::has_keying_material() const {
   return m_cipher->has_keying_material();
}

void CCM_Mode::key_schedule(std::span<const uint8_t> key) {
   m_cipher->set_key(key);
}

void CCM_Mode::set_associated_data_n(size_t idx, std::span<const uint8_t> ad) {
   BOTAN_ARG_CHECK(idx == 0, "CCM: cannot handle non-zero index in set_associated_data_n");

   m_ad_buf.clear();

   if(!ad.empty()) {
      // FIXME: support larger AD using length encoding rules
      BOTAN_ARG_CHECK(ad.size() < (0xFFFF - 0xFF), "Supported CCM AD length");

      m_ad_buf.push_back(get_byte<0>(static_cast<uint16_t>(ad.size())));
      m_ad_buf.push_back(get_byte<1>(static_cast<uint16_t>(ad.size())));
      m_ad_buf.insert(m_ad_buf.end(), ad.begin(), ad.end());
      while(m_ad_buf.size() % CCM_BS != 0) {
         m_ad_buf.push_back(0);  // pad with zeros to full block size
      }
   }
}

void CCM_Mode::start_msg(const uint8_t nonce[], size_t nonce_len) {
   if(!valid_nonce_length(nonce_len)) {
      throw Invalid_IV_Length(name(), nonce_len);
   }

   m_nonce.assign(nonce, nonce + nonce_len);
   m_msg_buf.clear();
}

size_t CCM_Mode::process_msg(uint8_t buf[], size_t sz) {
   BOTAN_STATE_CHECK(!m_nonce.empty());
   m_msg_buf.insert(m_msg_buf.end(), buf, buf + sz);
   return 0;  // no output until finished
}

void CCM_Mode::encode_length(uint64_t len, uint8_t out[]) {
   const size_t len_bytes = L();

   BOTAN_ASSERT_NOMSG(len_bytes >= 2 && len_bytes <= 8);

   for(size_t i = 0; i != len_bytes; ++i) {
      out[len_bytes - 1 - i] = get_byte_var(sizeof(uint64_t) - 1 - i, len);
   }

   if(len_bytes < 8 && (len >> (len_bytes * 8)) > 0) {
      throw Encoding_Error("CCM message length too long to encode in L field");
   }
}

void CCM_Mode::inc(secure_vector<uint8_t>& C) {
   for(size_t i = 0; i != C.size(); ++i) {
      if(++C[C.size() - i - 1]) {
         break;
      }
   }
}

secure_vector<uint8_t> CCM_Mode::format_b0(size_t sz) {
   if(m_nonce.size() != 15 - L()) {
      throw Invalid_State("CCM mode must set nonce");
   }
   secure_vector<uint8_t> B0(CCM_BS);

   const uint8_t b_flags =
      static_cast<uint8_t>((!m_ad_buf.empty() ? 64 : 0) + (((tag_size() / 2) - 1) << 3) + (L() - 1));

   B0[0] = b_flags;
   copy_mem(&B0[1], m_nonce.data(), m_nonce.size());
   encode_length(sz, &B0[m_nonce.size() + 1]);

   return B0;
}

secure_vector<uint8_t> CCM_Mode::format_c0() {
   if(m_nonce.size() != 15 - L()) {
      throw Invalid_State("CCM mode must set nonce");
   }
   secure_vector<uint8_t> C(CCM_BS);

   const uint8_t a_flags = static_cast<uint8_t>(L() - 1);

   C[0] = a_flags;
   copy_mem(&C[1], m_nonce.data(), m_nonce.size());

   return C;
}

size_t CCM_Encryption::finish_msg(std::span<uint8_t> buffer, size_t input_bytes) {
   const auto tag_length = tag_size();
   const auto& buffered = msg_buf();

   BOTAN_ASSERT_NOMSG(buffered.size() + input_bytes + tag_length == buffer.size());

   const auto entire_payload = buffer.first(buffered.size() + input_bytes);
   const auto tag = buffer.last(tag_length);

   const secure_vector<uint8_t>& ad = ad_buf();
   BOTAN_ARG_CHECK(ad.size() % CCM_BS == 0, "AD is block size multiple");

   const BlockCipher& E = cipher();

   // TODO: consider using std::array<> for all those block-size'ed buffers
   //       (this requires adapting more helper functions like `format_b0`, ...)
   secure_vector<uint8_t> T(CCM_BS);
   E.encrypt(format_b0(entire_payload.size()), T);

   BufferSlicer ad_bs(ad);
   while(!ad_bs.empty()) {
      xor_buf(T, ad_bs.take(CCM_BS));
      E.encrypt(T);
   }

   secure_vector<uint8_t> C = format_c0();
   secure_vector<uint8_t> S0(CCM_BS);
   E.encrypt(C, S0);
   inc(C);

   secure_vector<uint8_t> X(CCM_BS);

   // copy all buffered input into the in/out buffer if needed
   if(!buffered.empty()) {
      copy_mem(entire_payload.last(input_bytes), entire_payload.first(input_bytes));
      copy_mem(entire_payload.first(buffered.size()), buffered);
   }

   // TODO: Use BufferTransformer, once it is available
   //       See https://github.com/randombit/botan/pull/4151
   BufferSlicer payload_slicer(entire_payload);
   BufferStuffer payload_stuffer(entire_payload);

   while(!payload_slicer.empty()) {
      const size_t to_proc = std::min<size_t>(CCM_BS, payload_slicer.remaining());
      const auto in_chunk = payload_slicer.take(to_proc);
      const auto out_chunk = payload_stuffer.next(to_proc);

      xor_buf(std::span{T}.first(in_chunk.size()), in_chunk);
      E.encrypt(T);

      E.encrypt(C, X);
      xor_buf(out_chunk, std::span{X}.first(out_chunk.size()));
      inc(C);
   }

   T ^= S0;

   BOTAN_DEBUG_ASSERT(tag.size() <= T.size());
   copy_mem(tag, std::span{T}.first(tag.size()));

   reset();

   return buffer.size();
}

size_t CCM_Decryption::finish_msg(std::span<uint8_t> buffer, size_t input_bytes) {
   const auto tag_length = tag_size();
   const auto& buffered = msg_buf();

   BOTAN_ASSERT_NOMSG(buffer.size() >= tag_length);
   BOTAN_ASSERT_NOMSG(buffered.size() + input_bytes == buffer.size());

   const auto entire_payload = buffer.first(buffer.size() - tag_length);
   const auto tag = buffer.last(tag_length);

   const secure_vector<uint8_t>& ad = ad_buf();
   BOTAN_ARG_CHECK(ad.size() % CCM_BS == 0, "AD is block size multiple");

   const BlockCipher& E = cipher();

   secure_vector<uint8_t> T(CCM_BS);
   E.encrypt(format_b0(entire_payload.size()), T);

   BufferSlicer ad_bs(ad);
   while(!ad_bs.empty()) {
      xor_buf(T, ad_bs.take<CCM_BS>());
      E.encrypt(T);
   }

   secure_vector<uint8_t> C = format_c0();

   secure_vector<uint8_t> S0(CCM_BS);
   E.encrypt(C, S0);
   inc(C);

   secure_vector<uint8_t> X(CCM_BS);

   // copy all buffered input into the in/out buffer if needed
   if(!buffered.empty()) {
      copy_mem(buffer.last(input_bytes), buffer.first(input_bytes));
      copy_mem(buffer.first(buffered.size()), buffered);
   }

   // TODO: Use BufferTransformer, once it is available
   //       See https://github.com/randombit/botan/pull/4151
   BufferSlicer payload_slicer(entire_payload);
   BufferStuffer payload_stuffer(entire_payload);

   while(!payload_slicer.empty()) {
      const size_t to_proc = std::min<size_t>(CCM_BS, payload_slicer.remaining());
      const auto in_chunk = payload_slicer.take(to_proc);
      const auto out_chunk = payload_stuffer.next(to_proc);

      E.encrypt(C, X);
      xor_buf(out_chunk, std::span{X}.first(out_chunk.size()));
      inc(C);

      xor_buf(std::span{T}.first(in_chunk.size()), in_chunk);
      E.encrypt(T);
   }

   T ^= S0;

   if(!CT::is_equal(T.data(), tag.data(), tag.size()).as_bool()) {
      throw Invalid_Authentication_Tag("CCM tag check failed");
   }

   reset();

   return entire_payload.size();
}

}  // namespace Botan
