/*
* OpenSSL Block Cipher
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/openssl_engine.h>
#include <openssl/evp.h>

namespace Botan {

namespace {

/*
* EVP Block Cipher
*/
class EVP_BlockCipher : public BlockCipher
   {
   public:
      void clear();
      std::string name() const { return cipher_name; }
      BlockCipher* clone() const;

      size_t block_size() const { return block_sz; }

      EVP_BlockCipher(const EVP_CIPHER*, const std::string&);

      EVP_BlockCipher(const EVP_CIPHER*, const std::string&,
                      size_t, size_t, size_t);

      Key_Length_Specification key_spec() const { return cipher_key_spec; }

      ~EVP_BlockCipher();
   private:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;
      void key_schedule(const byte[], size_t);

      size_t block_sz;
      Key_Length_Specification cipher_key_spec;
      std::string cipher_name;
      mutable EVP_CIPHER_CTX encrypt, decrypt;
   };

/*
* EVP Block Cipher Constructor
*/
EVP_BlockCipher::EVP_BlockCipher(const EVP_CIPHER* algo,
                                 const std::string& algo_name) :
   block_sz(EVP_CIPHER_block_size(algo)),
   cipher_key_spec(EVP_CIPHER_key_length(algo)),
   cipher_name(algo_name)
   {
   if(EVP_CIPHER_mode(algo) != EVP_CIPH_ECB_MODE)
      throw Invalid_Argument("EVP_BlockCipher: Non-ECB EVP was passed in");

   EVP_CIPHER_CTX_init(&encrypt);
   EVP_CIPHER_CTX_init(&decrypt);

   EVP_EncryptInit_ex(&encrypt, algo, 0, 0, 0);
   EVP_DecryptInit_ex(&decrypt, algo, 0, 0, 0);

   EVP_CIPHER_CTX_set_padding(&encrypt, 0);
   EVP_CIPHER_CTX_set_padding(&decrypt, 0);
   }

/*
* EVP Block Cipher Constructor
*/
EVP_BlockCipher::EVP_BlockCipher(const EVP_CIPHER* algo,
                                 const std::string& algo_name,
                                 size_t key_min, size_t key_max,
                                 size_t key_mod) :
   block_sz(EVP_CIPHER_block_size(algo)),
   cipher_key_spec(key_min, key_max, key_mod),
   cipher_name(algo_name)
   {
   if(EVP_CIPHER_mode(algo) != EVP_CIPH_ECB_MODE)
      throw Invalid_Argument("EVP_BlockCipher: Non-ECB EVP was passed in");

   EVP_CIPHER_CTX_init(&encrypt);
   EVP_CIPHER_CTX_init(&decrypt);

   EVP_EncryptInit_ex(&encrypt, algo, 0, 0, 0);
   EVP_DecryptInit_ex(&decrypt, algo, 0, 0, 0);

   EVP_CIPHER_CTX_set_padding(&encrypt, 0);
   EVP_CIPHER_CTX_set_padding(&decrypt, 0);
   }

/*
* EVP Block Cipher Destructor
*/
EVP_BlockCipher::~EVP_BlockCipher()
   {
   EVP_CIPHER_CTX_cleanup(&encrypt);
   EVP_CIPHER_CTX_cleanup(&decrypt);
   }

/*
* Encrypt a block
*/
void EVP_BlockCipher::encrypt_n(const byte in[], byte out[],
                                size_t blocks) const
   {
   int out_len = 0;
   EVP_EncryptUpdate(&encrypt, out, &out_len, in, blocks * block_sz);
   }

/*
* Decrypt a block
*/
void EVP_BlockCipher::decrypt_n(const byte in[], byte out[],
                                size_t blocks) const
   {
   int out_len = 0;
   EVP_DecryptUpdate(&decrypt, out, &out_len, in, blocks * block_sz);
   }

/*
* Set the key
*/
void EVP_BlockCipher::key_schedule(const byte key[], size_t length)
   {
   secure_vector<byte> full_key(key, key + length);

   if(cipher_name == "TripleDES" && length == 16)
      {
      full_key += std::make_pair(key, 8);
      }
   else
      if(EVP_CIPHER_CTX_set_key_length(&encrypt, length) == 0 ||
         EVP_CIPHER_CTX_set_key_length(&decrypt, length) == 0)
         throw Invalid_Argument("EVP_BlockCipher: Bad key length for " +
                                cipher_name);

   if(cipher_name == "RC2")
      {
      EVP_CIPHER_CTX_ctrl(&encrypt, EVP_CTRL_SET_RC2_KEY_BITS, length*8, 0);
      EVP_CIPHER_CTX_ctrl(&decrypt, EVP_CTRL_SET_RC2_KEY_BITS, length*8, 0);
      }

   EVP_EncryptInit_ex(&encrypt, 0, 0, full_key.data(), 0);
   EVP_DecryptInit_ex(&decrypt, 0, 0, full_key.data(), 0);
   }

/*
* Return a clone of this object
*/
BlockCipher* EVP_BlockCipher::clone() const
   {
   return new EVP_BlockCipher(EVP_CIPHER_CTX_cipher(&encrypt),
                              cipher_name,
                              cipher_key_spec.minimum_keylength(),
                              cipher_key_spec.maximum_keylength(),
                              cipher_key_spec.keylength_multiple());
   }

/*
* Clear memory of sensitive data
*/
void EVP_BlockCipher::clear()
   {
   const EVP_CIPHER* algo = EVP_CIPHER_CTX_cipher(&encrypt);

   EVP_CIPHER_CTX_cleanup(&encrypt);
   EVP_CIPHER_CTX_cleanup(&decrypt);
   EVP_CIPHER_CTX_init(&encrypt);
   EVP_CIPHER_CTX_init(&decrypt);
   EVP_EncryptInit_ex(&encrypt, algo, 0, 0, 0);
   EVP_DecryptInit_ex(&decrypt, algo, 0, 0, 0);
   EVP_CIPHER_CTX_set_padding(&encrypt, 0);
   EVP_CIPHER_CTX_set_padding(&decrypt, 0);
   }

}

/*
* Look for an algorithm with this name
*/
BlockCipher*
OpenSSL_Engine::find_block_cipher(const SCAN_Name& request,
                                  Algorithm_Factory&) const
   {
#define HANDLE_EVP_CIPHER(NAME, EVP)                            \
   if(request.algo_name() == NAME && request.arg_count() == 0)  \
      return new EVP_BlockCipher(EVP, NAME);

#define HANDLE_EVP_CIPHER_KEYLEN(NAME, EVP, MIN, MAX, MOD)      \
   if(request.algo_name() == NAME && request.arg_count() == 0)  \
      return new EVP_BlockCipher(EVP, NAME, MIN, MAX, MOD);

#if !defined(OPENSSL_NO_AES)
   /*
   Using OpenSSL's AES causes crashes inside EVP on x86-64 with OpenSSL 0.9.8g
   cause is unknown
   */
   HANDLE_EVP_CIPHER("AES-128", EVP_aes_128_ecb());
   HANDLE_EVP_CIPHER("AES-192", EVP_aes_192_ecb());
   HANDLE_EVP_CIPHER("AES-256", EVP_aes_256_ecb());
#endif

#if !defined(OPENSSL_NO_DES)
   HANDLE_EVP_CIPHER("DES", EVP_des_ecb());
   HANDLE_EVP_CIPHER_KEYLEN("TripleDES", EVP_des_ede3_ecb(), 16, 24, 8);
#endif

#if !defined(OPENSSL_NO_BF)
   HANDLE_EVP_CIPHER_KEYLEN("Blowfish", EVP_bf_ecb(), 1, 56, 1);
#endif

#if !defined(OPENSSL_NO_CAST)
   HANDLE_EVP_CIPHER_KEYLEN("CAST-128", EVP_cast5_ecb(), 1, 16, 1);
#endif

#if !defined(OPENSSL_NO_CAMELLIA)
   HANDLE_EVP_CIPHER("Camellia-128", EVP_camellia_128_ecb());
   HANDLE_EVP_CIPHER("Camellia-192", EVP_camellia_192_ecb());
   HANDLE_EVP_CIPHER("Camellia-256", EVP_camellia_256_ecb());
#endif

#if !defined(OPENSSL_NO_RC2)
   HANDLE_EVP_CIPHER_KEYLEN("RC2", EVP_rc2_ecb(), 1, 32, 1);
#endif

#if !defined(OPENSSL_NO_RC5) && 0
   if(request.algo_name() == "RC5")
      if(request.arg_as_integer(0, 12) == 12)
         return new EVP_BlockCipher(EVP_rc5_32_12_16_ecb(),
                                    "RC5(12)", 1, 32, 1);
#endif

#if !defined(OPENSSL_NO_IDEA) && 0
   HANDLE_EVP_CIPHER("IDEA", EVP_idea_ecb());
#endif

#if !defined(OPENSSL_NO_SEED)
   HANDLE_EVP_CIPHER("SEED", EVP_seed_ecb());
#endif

#undef HANDLE_EVP_CIPHER
#undef HANDLE_EVP_CIPHER_KEYLEN

   return 0;
   }

}
