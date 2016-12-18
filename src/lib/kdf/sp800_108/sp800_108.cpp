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

size_t SP800_108_Counter::kdf(uint8_t key[], size_t key_len,
                              const uint8_t secret[], size_t secret_len,
                              const uint8_t salt[], size_t salt_len,
                              const uint8_t label[], size_t label_len) const
   {
      const std::size_t prf_len =  m_prf->output_length();
      const uint8_t delim = 0;
      uint8_t *p = key;
      uint32_t counter = 1;
      uint32_t length = key_len * 8;
      uint8_t be_len[4] = { 0 };
      secure_vector<uint8_t> tmp;

      store_be(length, be_len);
      m_prf->set_key(secret, secret_len);

      while(p < key + key_len && counter != 0)
         {
         const std::size_t to_copy = std::min< std::size_t >(key + key_len - p, prf_len);
         uint8_t be_cnt[4] = { 0 };

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

size_t SP800_108_Feedback::kdf(uint8_t key[], size_t key_len,
                               const uint8_t secret[], size_t secret_len,
                               const uint8_t salt[], size_t salt_len,
                               const uint8_t label[], size_t label_len) const
   {
      const std::size_t prf_len =  m_prf->output_length();
      const std::size_t iv_len = (salt_len >= prf_len ? prf_len : 0);
      const uint8_t delim = 0;

      uint8_t *p = key;
      uint32_t counter = 1;
      uint32_t length = key_len * 8;
      uint8_t be_len[4] = { 0 };
      secure_vector< uint8_t > prev(salt, salt + iv_len);
      secure_vector< uint8_t > ctx(salt + iv_len, salt + salt_len);

      store_be(length, be_len);
      m_prf->set_key(secret, secret_len);

      while(p < key + key_len && counter != 0)
         {
         const std::size_t to_copy = std::min< std::size_t >(key + key_len - p, prf_len);
         uint8_t be_cnt[4] = { 0 };

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

size_t SP800_108_Pipeline::kdf(uint8_t key[], size_t key_len,
                    const uint8_t secret[], size_t secret_len,
                    const uint8_t salt[], size_t salt_len,
                    const uint8_t label[], size_t label_len) const
   {
      const std::size_t prf_len =  m_prf->output_length();
      const uint8_t delim = 0;

      uint8_t *p = key;
      uint32_t counter = 1;
      uint32_t length = key_len * 8;
      uint8_t be_len[4] = { 0 };
      secure_vector<uint8_t> ai, ki;

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
         uint8_t be_cnt[4] = { 0 };

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
