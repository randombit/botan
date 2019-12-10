/*
* CCM Mode Encryption
* (C) 2013,2018 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ccm.h>
#include <botan/loadstor.h>

namespace Botan {

// 128-bit cipher is intrinsic to CCM definition
static const size_t CCM_BS = 16;

/*
* CCM_Mode Constructor
*/
CCM_Mode::CCM_Mode(BlockCipher* cipher, size_t tag_size, size_t L) :
   m_tag_size(tag_size),
   m_L(L),
   m_cipher(cipher)
   {
   if(m_cipher->block_size() != CCM_BS)
      throw Invalid_Argument(m_cipher->name() + " cannot be used with CCM mode");

   if(L < 2 || L > 8)
      throw Invalid_Argument("Invalid CCM L value " + std::to_string(L));

   if(tag_size < 4 || tag_size > 16 || tag_size % 2 != 0)
      throw Invalid_Argument("invalid CCM tag length " + std::to_string(tag_size));
   }

void CCM_Mode::clear()
   {
   m_cipher->clear();
   reset();
   }

void CCM_Mode::reset()
   {
   m_nonce.clear();
   m_msg_buf.clear();
   m_ad_buf.clear();
   }

std::string CCM_Mode::name() const
   {
   return (m_cipher->name() + "/CCM(" + std::to_string(tag_size()) + "," + std::to_string(L())) + ")";
   }

bool CCM_Mode::valid_nonce_length(size_t n) const
   {
   return (n == (15-L()));
   }

size_t CCM_Mode::default_nonce_length() const
   {
   return (15-L());
   }

size_t CCM_Mode::update_granularity() const
   {
   /*
   This value does not particularly matter as regardless CCM_Mode::update
   buffers all input, so in theory this could be 1. However as for instance
   Transform_Filter creates update_granularity() uint8_t buffers, use a
   somewhat large size to avoid bouncing on a tiny buffer.
   */
   return m_cipher->parallel_bytes();
   }

Key_Length_Specification CCM_Mode::key_spec() const
   {
   return m_cipher->key_spec();
   }

void CCM_Mode::key_schedule(const uint8_t key[], size_t length)
   {
   m_cipher->set_key(key, length);
   }

void CCM_Mode::set_associated_data(const uint8_t ad[], size_t length)
   {
   m_ad_buf.clear();

   if(length)
      {
      // FIXME: support larger AD using length encoding rules
      BOTAN_ARG_CHECK(length < (0xFFFF - 0xFF), "Supported CCM AD length");

      m_ad_buf.push_back(get_byte(0, static_cast<uint16_t>(length)));
      m_ad_buf.push_back(get_byte(1, static_cast<uint16_t>(length)));
      m_ad_buf += std::make_pair(ad, length);
      while(m_ad_buf.size() % CCM_BS)
         m_ad_buf.push_back(0); // pad with zeros to full block size
      }
   }

void CCM_Mode::start_msg(const uint8_t nonce[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   m_nonce.assign(nonce, nonce + nonce_len);
   m_msg_buf.clear();
   }

size_t CCM_Mode::process(uint8_t buf[], size_t sz)
   {
   BOTAN_STATE_CHECK(m_nonce.size() > 0);
   m_msg_buf.insert(m_msg_buf.end(), buf, buf + sz);
   return 0; // no output until finished
   }

void CCM_Mode::encode_length(uint64_t len, uint8_t out[])
   {
   const size_t len_bytes = L();

   BOTAN_ASSERT_NOMSG(len_bytes >= 2 && len_bytes <= 8);

   for(size_t i = 0; i != len_bytes; ++i)
      out[len_bytes-1-i] = get_byte(sizeof(uint64_t)-1-i, len);

   if(len_bytes < 8 && (len >> (len_bytes*8)) > 0)
      throw Encoding_Error("CCM message length too long to encode in L field");
   }

void CCM_Mode::inc(secure_vector<uint8_t>& C)
   {
   for(size_t i = 0; i != C.size(); ++i)
      if(++C[C.size()-i-1])
         break;
   }

secure_vector<uint8_t> CCM_Mode::format_b0(size_t sz)
   {
   if(m_nonce.size() != 15-L())
      throw Invalid_State("CCM mode must set nonce");
   secure_vector<uint8_t> B0(CCM_BS);

   const uint8_t b_flags =
      static_cast<uint8_t>((m_ad_buf.size() ? 64 : 0) + (((tag_size()/2)-1) << 3) + (L()-1));

   B0[0] = b_flags;
   copy_mem(&B0[1], m_nonce.data(), m_nonce.size());
   encode_length(sz, &B0[m_nonce.size()+1]);

   return B0;
   }

secure_vector<uint8_t> CCM_Mode::format_c0()
   {
   if(m_nonce.size() != 15-L())
      throw Invalid_State("CCM mode must set nonce");
   secure_vector<uint8_t> C(CCM_BS);

   const uint8_t a_flags = static_cast<uint8_t>(L() - 1);

   C[0] = a_flags;
   copy_mem(&C[1], m_nonce.data(), m_nonce.size());

   return C;
   }

void CCM_Encryption::finish(secure_vector<uint8_t>& buffer, size_t offset)
   {
   BOTAN_ARG_CHECK(buffer.size() >= offset, "Offset is sane");

   buffer.insert(buffer.begin() + offset, msg_buf().begin(), msg_buf().end());

   const size_t sz = buffer.size() - offset;
   uint8_t* buf = buffer.data() + offset;

   const secure_vector<uint8_t>& ad = ad_buf();
   BOTAN_ARG_CHECK(ad.size() % CCM_BS == 0, "AD is block size multiple");

   const BlockCipher& E = cipher();

   secure_vector<uint8_t> T(CCM_BS);
   E.encrypt(format_b0(sz), T);

   for(size_t i = 0; i != ad.size(); i += CCM_BS)
      {
      xor_buf(T.data(), &ad[i], CCM_BS);
      E.encrypt(T);
      }

   secure_vector<uint8_t> C = format_c0();
   secure_vector<uint8_t> S0(CCM_BS);
   E.encrypt(C, S0);
   inc(C);

   secure_vector<uint8_t> X(CCM_BS);

   const uint8_t* buf_end = &buf[sz];

   while(buf != buf_end)
      {
      const size_t to_proc = std::min<size_t>(CCM_BS, buf_end - buf);

      xor_buf(T.data(), buf, to_proc);
      E.encrypt(T);

      E.encrypt(C, X);
      xor_buf(buf, X.data(), to_proc);
      inc(C);

      buf += to_proc;
      }

   T ^= S0;

   buffer += std::make_pair(T.data(), tag_size());

   reset();
   }

void CCM_Decryption::finish(secure_vector<uint8_t>& buffer, size_t offset)
   {
   BOTAN_ARG_CHECK(buffer.size() >= offset, "Offset is sane");

   buffer.insert(buffer.begin() + offset, msg_buf().begin(), msg_buf().end());

   const size_t sz = buffer.size() - offset;
   uint8_t* buf = buffer.data() + offset;

   BOTAN_ASSERT(sz >= tag_size(), "We have the tag");

   const secure_vector<uint8_t>& ad = ad_buf();
   BOTAN_ARG_CHECK(ad.size() % CCM_BS == 0, "AD is block size multiple");

   const BlockCipher& E = cipher();

   secure_vector<uint8_t> T(CCM_BS);
   E.encrypt(format_b0(sz - tag_size()), T);

   for(size_t i = 0; i != ad.size(); i += CCM_BS)
      {
      xor_buf(T.data(), &ad[i], CCM_BS);
      E.encrypt(T);
      }

   secure_vector<uint8_t> C = format_c0();

   secure_vector<uint8_t> S0(CCM_BS);
   E.encrypt(C, S0);
   inc(C);

   secure_vector<uint8_t> X(CCM_BS);

   const uint8_t* buf_end = &buf[sz - tag_size()];

   while(buf != buf_end)
      {
      const size_t to_proc = std::min<size_t>(CCM_BS, buf_end - buf);

      E.encrypt(C, X);
      xor_buf(buf, X.data(), to_proc);
      inc(C);

      xor_buf(T.data(), buf, to_proc);
      E.encrypt(T);

      buf += to_proc;
      }

   T ^= S0;

   if(!constant_time_compare(T.data(), buf_end, tag_size()))
      throw Invalid_Authentication_Tag("CCM tag check failed");

   buffer.resize(buffer.size() - tag_size());

   reset();
   }

}
