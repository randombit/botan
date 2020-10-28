/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_AEAD_OCB)
   #include <botan/ocb.h>
   #include <botan/block_cipher.h>
   #include <botan/loadstor.h>
   #include <botan/internal/poly_dbl.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_AEAD_OCB)

// Toy cipher used for wide block tests

class OCB_Wide_Test_Block_Cipher final : public Botan::BlockCipher
   {
   public:
      OCB_Wide_Test_Block_Cipher(size_t bs) : m_bs(bs) {}

      std::string name() const override { return "OCB_ToyCipher"; }
      size_t block_size() const override { return m_bs; }
      void clear() override { m_key.clear(); }

      Botan::BlockCipher* clone() const override
         {
         return new OCB_Wide_Test_Block_Cipher(m_bs);
         }

      void key_schedule(const uint8_t key[], size_t length) override
         {
         m_key.assign(key, key + length);
         }

      Botan::Key_Length_Specification key_spec() const override
         {
         return Botan::Key_Length_Specification(m_bs);
         }

      void encrypt_n(const uint8_t in[], uint8_t out[],
                     size_t blocks) const override
         {
         while(blocks)
            {
            Botan::copy_mem(out, in, m_bs);
            Botan::poly_double_n(out, m_bs);

            for(size_t i = 0; i != m_bs; ++i)
               out[i] ^= m_key[i];

            blocks--;
            in += block_size();
            out += block_size();
            }
         }

      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override
         {
         while(blocks)
            {
            for(size_t i = 0; i != m_bs; ++i)
               out[i] = in[i] ^ m_key[i];

            uint8_t carry = in[m_bs-1] & 0x01;

            if(carry)
               {
               if(m_bs == 16 || m_bs == 24)
                  {
                  out[m_bs-1] ^= 0x87;
                  }
               else if(m_bs == 32)
                  {
                  out[m_bs-2] ^= 0x4;
                  out[m_bs-1] ^= 0x25;
                  }
               else if(m_bs == 64)
                  {
                  out[m_bs-2] ^= 0x1;
                  out[m_bs-1] ^= 0x25;
                  }
               else
                  throw Test_Error("Bad OCB test block size");
               }

            carry <<= 7;

            for(size_t i = 0; i != m_bs; ++i)
               {
               const uint8_t temp = out[i];
               out[i] = (temp >> 1) | carry;
               carry = (temp & 0x1);
               carry <<= 7;
               }

            blocks--;
            in += block_size();
            out += block_size();
            }
         }
   private:
      size_t m_bs;
      std::vector<uint8_t> m_key;
   };

class OCB_Wide_KAT_Tests final : public Text_Based_Test
   {
   public:
      OCB_Wide_KAT_Tests()
         : Text_Based_Test("ocb/ocb_wide.vec", "Key,Nonce,AD,In,Out") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("OCB wide block KAT");

         const std::vector<uint8_t> key = vars.get_req_bin("Key");
         const std::vector<uint8_t> nonce = vars.get_req_bin("Nonce");
         const std::vector<uint8_t> ad = vars.get_req_bin("AD");
         const std::vector<uint8_t> input = vars.get_req_bin("In");
         const std::vector<uint8_t> expected = vars.get_req_bin("Out");

         const size_t bs = key.size();
         Botan::secure_vector<uint8_t> buf(input.begin(), input.end());

         Botan::OCB_Encryption enc(new OCB_Wide_Test_Block_Cipher(bs), std::min<size_t>(bs, 32));
         enc.set_key(key);
         enc.set_ad(ad);
         enc.start(nonce);
         enc.finish(buf);
         result.test_eq("Ciphertext matches", buf, expected);

         Botan::OCB_Decryption dec(new OCB_Wide_Test_Block_Cipher(bs), std::min<size_t>(bs, 32));
         dec.set_key(key);
         dec.set_ad(ad);
         dec.start(nonce);
         dec.finish(buf);
         result.test_eq("Decryption correct", buf, input);

         return result;
         }
   };

BOTAN_REGISTER_TEST("modes", "ocb_wide", OCB_Wide_KAT_Tests);

class OCB_Wide_Long_KAT_Tests final : public Text_Based_Test
   {
   public:
      OCB_Wide_Long_KAT_Tests()
         : Text_Based_Test("ocb/ocb_wide_long.vec", "Output") {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         Test::Result result("OCB wide block long test");

         const std::vector<uint8_t> expected = vars.get_req_bin("Output");

         std::unique_ptr<Botan::BlockCipher> cipher;
         size_t bs = 0;

         if(algo == "SHACAL2")
            {
#if defined(BOTAN_HAS_SHACAL2)
            cipher = Botan::BlockCipher::create_or_throw("SHACAL2");
            bs = 32;
#else
            return {result};
#endif
            }
         else
            {
            if(algo == "Toy128")
               bs = 16;
            else if(algo == "Toy192")
               bs = 24;
            else if(algo == "Toy256")
               bs = 32;
            else if(algo == "Toy512")
               bs = 64;
            else
               throw Test_Error("Unknown cipher for OCB wide block long test");
            cipher.reset(new OCB_Wide_Test_Block_Cipher(bs));
            }

         Botan::OCB_Encryption enc(cipher.release(), std::min<size_t>(bs, 32));

         /*
         Y, string of length min(B, 256) bits

         Y is defined as follows.

         K = (0xA0 || 0xA1 || 0xA2 || ...)[1..B]
         C = <empty string>
         for i = 0 to 127 do
           S = (0x50 || 0x51 || 0x52 || ...)[1..8i]
           N = num2str(3i+1,16)
           C = C || OCB-ENCRYPT(K,N,S,S)
           N = num2str(3i+2,16)
           C = C || OCB-ENCRYPT(K,N,<empty string>,S)
           N = num2str(3i+3,16)
           C = C || OCB-ENCRYPT(K,N,S,<empty string>)
         end for
         N = num2str(385,16)
         Y = OCB-ENCRYPT(K,N,C,<empty string>)
         */

         std::vector<uint8_t> key(bs);
         for(size_t i = 0; i != bs; ++i)
            key[i] = static_cast<uint8_t>(0xA0 + i);

         enc.set_key(key);

         const std::vector<uint8_t> empty;
         std::vector<uint8_t> N(2);
         std::vector<uint8_t> C;

         for(size_t i = 0; i != 128; ++i)
            {
            std::vector<uint8_t> S(i);
            for(size_t j = 0; j != S.size(); ++j)
               S[j] = static_cast<uint8_t>(0x50 + j);

            Botan::store_be(static_cast<uint16_t>(3 * i + 1), &N[0]);

            ocb_encrypt(result, C, enc, N, S, S);
            Botan::store_be(static_cast<uint16_t>(3 * i + 2), &N[0]);
            ocb_encrypt(result, C, enc, N, S, empty);
            Botan::store_be(static_cast<uint16_t>(3 * i + 3), &N[0]);
            ocb_encrypt(result, C, enc, N, empty, S);
            }

         Botan::store_be(static_cast<uint16_t>(385), &N[0]);
         std::vector<uint8_t> final_result;
         ocb_encrypt(result, final_result, enc, N, empty, C);

         result.test_eq("correct value", final_result, expected);

         return result;
         }

   private:
      void ocb_encrypt(Test::Result& /*result*/,
                       std::vector<uint8_t>& output_to,
                       Botan::OCB_Encryption& enc,
                       const std::vector<uint8_t>& nonce,
                       const std::vector<uint8_t>& pt,
                       const std::vector<uint8_t>& ad)
         {
         enc.set_associated_data(ad.data(), ad.size());
         enc.start(nonce.data(), nonce.size());
         Botan::secure_vector<uint8_t> buf(pt.begin(), pt.end());
         enc.finish(buf, 0);
         output_to.insert(output_to.end(), buf.begin(), buf.end());
         }
   };

BOTAN_REGISTER_TEST("modes", "ocb_long_wide", OCB_Wide_Long_KAT_Tests);

class OCB_Long_KAT_Tests final : public Text_Based_Test
   {
   public:
      OCB_Long_KAT_Tests()
         : Text_Based_Test("ocb/ocb_long.vec",
                           "Keylen,Taglen,Output") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         const size_t keylen = vars.get_req_sz("Keylen");
         const size_t taglen = vars.get_req_sz("Taglen");
         const std::vector<uint8_t> expected = vars.get_req_bin("Output");

         // Test from RFC 7253 Appendix A

         const std::string algo = "AES-" + std::to_string(keylen);

         Test::Result result("OCB long");

         std::unique_ptr<Botan::BlockCipher> aes(Botan::BlockCipher::create(algo));
         if(!aes)
            {
            result.note_missing(algo);
            return result;
            }

         Botan::OCB_Encryption enc(aes->clone(), taglen / 8);
         Botan::OCB_Decryption dec(aes->clone(), taglen / 8);

         std::vector<uint8_t> key(keylen / 8);
         key[keylen / 8 - 1] = static_cast<uint8_t>(taglen);

         enc.set_key(key);
         dec.set_key(key);

         const std::vector<uint8_t> empty;
         std::vector<uint8_t> N(12);
         std::vector<uint8_t> C;

         for(size_t i = 0; i != 128; ++i)
            {
            const std::vector<uint8_t> S(i);

            Botan::store_be(static_cast<uint32_t>(3 * i + 1), &N[8]);

            ocb_encrypt(result, C, enc, dec, N, S, S);
            Botan::store_be(static_cast<uint32_t>(3 * i + 2), &N[8]);
            ocb_encrypt(result, C, enc, dec, N, S, empty);
            Botan::store_be(static_cast<uint32_t>(3 * i + 3), &N[8]);
            ocb_encrypt(result, C, enc, dec, N, empty, S);
            }

         Botan::store_be(static_cast<uint32_t>(385), &N[8]);
         std::vector<uint8_t> final_result;
         ocb_encrypt(result, final_result, enc, dec, N, empty, C);

         result.test_eq("correct value", final_result, expected);

         return result;
         }
   private:
      void ocb_encrypt(Test::Result& result,
                       std::vector<uint8_t>& output_to,
                       Botan::OCB_Encryption& enc,
                       Botan::OCB_Decryption& dec,
                       const std::vector<uint8_t>& nonce,
                       const std::vector<uint8_t>& pt,
                       const std::vector<uint8_t>& ad)
         {
         enc.set_associated_data(ad.data(), ad.size());

         enc.start(nonce.data(), nonce.size());

         Botan::secure_vector<uint8_t> buf(pt.begin(), pt.end());
         enc.finish(buf, 0);
         output_to.insert(output_to.end(), buf.begin(), buf.end());

         try
            {
            dec.set_associated_data(ad.data(), ad.size());

            dec.start(nonce.data(), nonce.size());

            dec.finish(buf, 0);

            result.test_eq("OCB round tripped", buf, pt);
            }
         catch(std::exception& e)
            {
            result.test_failure("OCB round trip error", e.what());
            }

         }
   };

BOTAN_REGISTER_TEST("modes", "ocb_long", OCB_Long_KAT_Tests);

#endif

}

}
