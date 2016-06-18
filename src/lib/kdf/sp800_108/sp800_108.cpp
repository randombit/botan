/*
* KDFs defined in NIST SP 800-108
* (C) 2016 Kai Michaelis
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sp800_108.h>
#include <botan/hmac.h>

#include <iterator>

namespace Botan {

SP800_108_Counter* SP800_108_Counter::make(const Spec& spec)
   {
   if(auto mac = MessageAuthenticationCode::create(spec.arg(0)))
      return new SP800_108_Counter(mac.release());

   if(auto mac = MessageAuthenticationCode::create("HMAC(" + spec.arg(0) + ")"))
      return new SP800_108_Counter(mac.release());

   return nullptr;
   }

size_t SP800_108_Counter::kdf(byte key[], size_t key_len,
                              const byte secret[], size_t secret_len,
                              const byte salt[], size_t salt_len,
                              const byte label[], size_t label_len) const
   {
      const std::size_t prf_len =  m_prf->output_length();
      const byte delim = 0;
      byte *p = key;
      uint32_t counter = 1;
      uint32_t length = key_len * 8;
      byte be_len[4] = { 0 };
      secure_vector<byte> tmp;

      store_be(length, be_len);
      m_prf->set_key(secret, secret_len);

      while(p < key + key_len && counter != 0)
         {
         const std::size_t to_copy = std::min< std::size_t >(key + key_len - p, prf_len);
         byte be_cnt[4] = { 0 };

         store_be(counter, be_cnt);

         m_prf->update(be_cnt,4);
         m_prf->update(label,label_len);
         m_prf->update(delim);
         m_prf->update(salt,salt_len);
         m_prf->update(be_len,4);
         m_prf->final(tmp);

         std::move(tmp.begin(), tmp.begin() + to_copy, p);
         ++counter;

         if (counter == 0)
            throw Invalid_Argument("Can't process more than 4GB");

         p += to_copy;
         }

   return key_len;
   }

SP800_108_Feedback* SP800_108_Feedback::make(const Spec& spec)
   {
   if(auto mac = MessageAuthenticationCode::create(spec.arg(0)))
      return new SP800_108_Feedback(mac.release());

   if(auto mac = MessageAuthenticationCode::create("HMAC(" + spec.arg(0) + ")"))
      return new SP800_108_Feedback(mac.release());

   return nullptr;
   }

size_t SP800_108_Feedback::kdf(byte key[], size_t key_len,
                               const byte secret[], size_t secret_len,
                               const byte salt[], size_t salt_len,
                               const byte label[], size_t label_len) const
   {
      const std::size_t prf_len =  m_prf->output_length();
      const std::size_t iv_len = (salt_len >= prf_len ? prf_len : 0);
      const byte delim = 0;

      byte *p = key;
      uint32_t counter = 1;
      uint32_t length = key_len * 8;
      byte be_len[4] = { 0 };
      secure_vector< byte > prev(salt, salt + iv_len);
      secure_vector< byte > ctx(salt + iv_len, salt + salt_len);

      store_be(length, be_len);
      m_prf->set_key(secret, secret_len);

      while(p < key + key_len && counter != 0)
         {
         const std::size_t to_copy = std::min< std::size_t >(key + key_len - p, prf_len);
         byte be_cnt[4] = { 0 };

         store_be(counter, be_cnt);

         m_prf->update(prev);
         m_prf->update(be_cnt,4);
         m_prf->update(label,label_len);
         m_prf->update(delim);
         m_prf->update(ctx);
         m_prf->update(be_len,4);
         m_prf->final(prev);

         std::copy(prev.begin(), prev.begin() + to_copy, p);
         ++counter;

         if (counter == 0)
            throw Invalid_Argument("Can't process more than 4GB");

         p += to_copy;
         }

   return key_len;
   }

SP800_108_Pipeline* SP800_108_Pipeline::make(const Spec& spec)
   {
   if(auto mac = MessageAuthenticationCode::create(spec.arg(0)))
      return new SP800_108_Pipeline(mac.release());

   if(auto mac = MessageAuthenticationCode::create("HMAC(" + spec.arg(0) + ")"))
      return new SP800_108_Pipeline(mac.release());

   return nullptr;
   }

size_t SP800_108_Pipeline::kdf(byte key[], size_t key_len,
                    const byte secret[], size_t secret_len,
                    const byte salt[], size_t salt_len,
                    const byte label[], size_t label_len) const
   {
      const std::size_t prf_len =  m_prf->output_length();
      const byte delim = 0;

      byte *p = key;
      uint32_t counter = 1;
      uint32_t length = key_len * 8;
      byte be_len[4] = { 0 };
      secure_vector<byte> ai, ki;

      store_be(length, be_len);
      m_prf->set_key(secret,secret_len);

      // A(0)
      std::copy(label,label + label_len,std::back_inserter(ai));
      ai.emplace_back(delim);
      std::copy(salt,salt + salt_len,std::back_inserter(ai));
      std::copy(be_len,be_len + 4,std::back_inserter(ai));

      while(p < key + key_len && counter != 0)
         {
         // A(i)
         m_prf->update(ai);
         m_prf->final(ai);

         // K(i)
         const std::size_t to_copy = std::min< std::size_t >(key + key_len - p, prf_len);
         byte be_cnt[4] = { 0 };

         store_be(counter, be_cnt);

         m_prf->update(ai);
         m_prf->update(be_cnt,4);
         m_prf->update(label, label_len);
         m_prf->update(delim);
         m_prf->update(salt, salt_len);
         m_prf->update(be_len,4);
         m_prf->final(ki);

         std::copy(ki.begin(), ki.begin() + to_copy, p);
         ++counter;

         if (counter == 0)
            throw Invalid_Argument("Can't process more than 4GB");

         p += to_copy;
         }

   return key_len;
   }
}
