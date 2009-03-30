/*
* OpenSSL Block Cipher
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eng_ossl.h>
#include <openssl/evp.h>

namespace Botan {

namespace {

/*
* EVP Block Cipher
*/
class EVP_BlockCipher : public BlockCipher
   {
   public:
      void clear() throw();
      std::string name() const { return cipher_name; }
      BlockCipher* clone() const;
      EVP_BlockCipher(const EVP_CIPHER*, const std::string&);
      EVP_BlockCipher(const EVP_CIPHER*, const std::string&,
                      u32bit, u32bit, u32bit);

      ~EVP_BlockCipher();
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key_schedule(const byte[], u32bit);
      std::string cipher_name;
      mutable EVP_CIPHER_CTX encrypt, decrypt;
   };

/*
* EVP Block Cipher Constructor
*/
EVP_BlockCipher::EVP_BlockCipher(const EVP_CIPHER* algo,
                                 const std::string& algo_name) :
   BlockCipher(EVP_CIPHER_block_size(algo), EVP_CIPHER_key_length(algo)),
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
                                 u32bit key_min, u32bit key_max,
                                 u32bit key_mod) :
   BlockCipher(EVP_CIPHER_block_size(algo), key_min, key_max, key_mod),
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
void EVP_BlockCipher::enc(const byte in[], byte out[]) const
   {
   int out_len = 0;
   EVP_EncryptUpdate(&encrypt, out, &out_len, in, BLOCK_SIZE);
   }

/*
* Decrypt a block
*/
void EVP_BlockCipher::dec(const byte in[], byte out[]) const
   {
   int out_len = 0;
   EVP_DecryptUpdate(&decrypt, out, &out_len, in, BLOCK_SIZE);
   }

/*
* Set the key
*/
void EVP_BlockCipher::key_schedule(const byte key[], u32bit length)
   {
   SecureVector<byte> full_key(key, length);

   if(cipher_name == "TripleDES" && length == 16)
      full_key.append(key, 8);
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

   EVP_EncryptInit_ex(&encrypt, 0, 0, full_key.begin(), 0);
   EVP_DecryptInit_ex(&decrypt, 0, 0, full_key.begin(), 0);
   }

/*
* Return a clone of this object
*/
BlockCipher* EVP_BlockCipher::clone() const
   {
   return new EVP_BlockCipher(EVP_CIPHER_CTX_cipher(&encrypt),
                              cipher_name, MINIMUM_KEYLENGTH,
                              MAXIMUM_KEYLENGTH, KEYLENGTH_MULTIPLE);
   }

/*
* Clear memory of sensitive data
*/
void EVP_BlockCipher::clear() throw()
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

#if 0
   /*
   Using OpenSSL's AES causes crashes inside EVP on x86-64 with OpenSSL 0.9.8g
   cause is unknown
   */
   HANDLE_EVP_CIPHER("AES-128", EVP_aes_128_ecb());
   HANDLE_EVP_CIPHER("AES-192", EVP_aes_192_ecb());
   HANDLE_EVP_CIPHER("AES-256", EVP_aes_256_ecb());
#endif

   HANDLE_EVP_CIPHER("DES", EVP_des_ecb());
   HANDLE_EVP_CIPHER_KEYLEN("TripleDES", EVP_des_ede3_ecb(), 16, 24, 8);

   HANDLE_EVP_CIPHER_KEYLEN("Blowfish", EVP_bf_ecb(), 1, 56, 1);
   HANDLE_EVP_CIPHER_KEYLEN("CAST-128", EVP_cast5_ecb(), 1, 16, 1);
   HANDLE_EVP_CIPHER_KEYLEN("RC2", EVP_rc2_ecb(), 1, 32, 1);

#undef HANDLE_EVP_CIPHER
#undef HANDLE_EVP_CIPHER_KEYLEN

   return 0;
   }

}
