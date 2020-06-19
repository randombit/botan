/*
* Block Ciphers via CommonCrypto
* (C) 2018 Jose Luis Pereira
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/commoncrypto.h>
#include <botan/internal/commoncrypto_utils.h>
#include <botan/hex.h>
#include <botan/block_cipher.h>

#include <CommonCrypto/CommonCrypto.h>

namespace Botan {

namespace {

class CommonCrypto_BlockCipher final : public BlockCipher
   {
   public:
      CommonCrypto_BlockCipher(const std::string& name, const CommonCryptor_Opts& opts);

      ~CommonCrypto_BlockCipher();

      void clear() override;
      std::string provider() const override { return "commoncrypto"; }
      std::string name() const override { return m_cipher_name; }
      BlockCipher* clone() const override;

      size_t block_size() const override { return m_opts.block_size; }

      Key_Length_Specification key_spec() const override { return m_opts.key_spec; }

      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override
         {
         verify_key_set(m_key_set);
         size_t total_len = blocks * m_opts.block_size;
         size_t out_len = 0;

         CCCryptorStatus status = CCCryptorUpdate(m_encrypt, in, total_len,
                                  out, total_len, &out_len);
         if(status != kCCSuccess)
            {
            throw CommonCrypto_Error("CCCryptorUpdate encrypt", status);
            }
         }

      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override
         {
         verify_key_set(m_key_set);
         size_t total_len = blocks * m_opts.block_size;
         size_t out_len = 0;

         CCCryptorStatus status = CCCryptorUpdate(m_decrypt, in, total_len,
                                  out, total_len, &out_len);
         if(status != kCCSuccess)
            {
            throw CommonCrypto_Error("CCCryptorUpdate decrypt", status);
            }
         }

      void key_schedule(const uint8_t key[], size_t key_len) override;

      std::string m_cipher_name;
      CommonCryptor_Opts m_opts;

      CCCryptorRef m_encrypt = nullptr;
      CCCryptorRef m_decrypt = nullptr;
      bool m_key_set;
   };

CommonCrypto_BlockCipher::CommonCrypto_BlockCipher(const std::string& algo_name,
      const CommonCryptor_Opts& opts) :
   m_cipher_name(algo_name),
   m_opts(opts),
   m_key_set(false)
   {
   }

CommonCrypto_BlockCipher::~CommonCrypto_BlockCipher()
   {
   if(m_encrypt)
      {
      CCCryptorRelease(m_encrypt);
      }
   if(m_decrypt)
      {
      CCCryptorRelease(m_decrypt);
      }
   }

/*
* Set the key
*/
void CommonCrypto_BlockCipher::key_schedule(const uint8_t key[], size_t length)
   {
   secure_vector<uint8_t> full_key(key, key + length);

   clear();
   commoncrypto_adjust_key_size(key, length, m_opts, full_key);

   CCCryptorStatus status;
   status = CCCryptorCreate(kCCEncrypt, m_opts.algo, kCCOptionECBMode,
                            full_key.data(), full_key.size(), nullptr, &m_encrypt);
   if(status != kCCSuccess)
      {
      throw CommonCrypto_Error("CCCryptorCreate encrypt", status);
      }
   status = CCCryptorCreate(kCCDecrypt, m_opts.algo, kCCOptionECBMode,
                            full_key.data(), full_key.size(), nullptr, &m_decrypt);
   if(status != kCCSuccess)
      {
      throw CommonCrypto_Error("CCCryptorCreate decrypt", status);
      }

   m_key_set = true;
   }

/*
* Return a clone of this object
*/
BlockCipher* CommonCrypto_BlockCipher::clone() const
   {
   return new CommonCrypto_BlockCipher(m_cipher_name, m_opts);
   }

/*
* Clear memory of sensitive data
*/
void CommonCrypto_BlockCipher::clear()
   {
   m_key_set = false;

   if(m_encrypt)
      {
      CCCryptorRelease(m_encrypt);
      m_encrypt = nullptr;
      }

   if(m_decrypt)
      {
      CCCryptorRelease(m_decrypt);
      m_decrypt = nullptr;
      }
   }
}

std::unique_ptr<BlockCipher>
make_commoncrypto_block_cipher(const std::string& name)
   {

   try
      {
      CommonCryptor_Opts opts = commoncrypto_opts_from_algo_name(name);
      return std::unique_ptr<BlockCipher>(new CommonCrypto_BlockCipher(name, opts));
      }
   catch(CommonCrypto_Error& e)
      {
      return nullptr;
      }
   }
}

