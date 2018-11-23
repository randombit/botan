/*
* Cipher Modes via OpenSSL
* (C) 1999-2010,2015 Jack Lloyd
* (C) 2017 Alexander Bluhm (genua GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/cipher_mode.h>
#include <botan/internal/rounding.h>
#include <botan/internal/openssl.h>
#include <openssl/evp.h>
#include <limits.h>

namespace Botan {

namespace {

class OpenSSL_Cipher_Mode final : public Cipher_Mode
   {
   public:
      OpenSSL_Cipher_Mode(const std::string& name,
                          const EVP_CIPHER* cipher,
                          Cipher_Dir direction);
      ~OpenSSL_Cipher_Mode();

      std::string provider() const override { return "openssl"; }
      std::string name() const override { return m_mode_name; }

      void start_msg(const uint8_t nonce[], size_t nonce_len) override;
      size_t process(uint8_t msg[], size_t msg_len) override;
      void finish(secure_vector<uint8_t>& final_block, size_t offset0) override;
      size_t output_length(size_t input_length) const override;
      size_t update_granularity() const override;
      size_t minimum_final_size() const override;
      size_t default_nonce_length() const override;
      bool valid_nonce_length(size_t nonce_len) const override;
      void clear() override;
      void reset() override;
      Key_Length_Specification key_spec() const override;

   private:
      void key_schedule(const uint8_t key[], size_t length) override;

      const std::string m_mode_name;
      const Cipher_Dir m_direction;
      size_t m_block_size;
      EVP_CIPHER_CTX* m_cipher;
      bool m_key_set;
      bool m_nonce_set;
   };

OpenSSL_Cipher_Mode::OpenSSL_Cipher_Mode(const std::string& name,
                                         const EVP_CIPHER* algo,
                                         Cipher_Dir direction) :
   m_mode_name(name),
   m_direction(direction),
   m_key_set(false),
   m_nonce_set(false)
   {
   m_block_size = EVP_CIPHER_block_size(algo);

   if(EVP_CIPHER_mode(algo) != EVP_CIPH_CBC_MODE)
      throw Invalid_Argument("OpenSSL_BlockCipher: Non-CBC EVP was passed in");

   m_cipher = EVP_CIPHER_CTX_new();
   if (m_cipher == nullptr)
      throw OpenSSL_Error("Can't allocate new context", ERR_get_error());

   EVP_CIPHER_CTX_init(m_cipher);
   if(!EVP_CipherInit_ex(m_cipher, algo, nullptr, nullptr, nullptr,
                         m_direction == ENCRYPTION ? 1 : 0))
      throw OpenSSL_Error("EVP_CipherInit_ex", ERR_get_error());
   if(!EVP_CIPHER_CTX_set_padding(m_cipher, 0))
      throw OpenSSL_Error("EVP_CIPHER_CTX_set_padding", ERR_get_error());
   }

OpenSSL_Cipher_Mode::~OpenSSL_Cipher_Mode()
   {
   EVP_CIPHER_CTX_free(m_cipher);
   }

void OpenSSL_Cipher_Mode::start_msg(const uint8_t nonce[], size_t nonce_len)
   {
   verify_key_set(m_key_set);

   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   if(nonce_len)
      {
      if(!EVP_CipherInit_ex(m_cipher, nullptr, nullptr, nullptr, nonce, -1))
         throw OpenSSL_Error("EVP_CipherInit_ex nonce", ERR_get_error());
      }
   else if(m_nonce_set == false)
      {
      const std::vector<uint8_t> zeros(m_block_size);
      if(!EVP_CipherInit_ex(m_cipher, nullptr, nullptr, nullptr, zeros.data(), -1))
         throw OpenSSL_Error("EVP_CipherInit_ex nonce", ERR_get_error());
      }
   // otherwise existing CBC state left unchanged

   m_nonce_set = true;
   }

size_t OpenSSL_Cipher_Mode::process(uint8_t msg[], size_t msg_len)
   {
   verify_key_set(m_key_set);
   BOTAN_STATE_CHECK(m_nonce_set);

   if(msg_len == 0)
      return 0;
   if(msg_len > INT_MAX)
      throw Internal_Error("msg_len overflow");
   int outl = msg_len;
   secure_vector<uint8_t> out(outl);

   if(!EVP_CipherUpdate(m_cipher, out.data(), &outl, msg, msg_len))
      throw OpenSSL_Error("EVP_CipherUpdate", ERR_get_error());
   copy_mem(msg, out.data(), outl);
   return outl;
   }

void OpenSSL_Cipher_Mode::finish(secure_vector<uint8_t>& buffer,
                                 size_t offset)
   {
   verify_key_set(m_key_set);
   BOTAN_STATE_CHECK(m_nonce_set);

   BOTAN_ASSERT(buffer.size() >= offset, "Offset ok");
   uint8_t* buf = buffer.data() + offset;
   const size_t buf_size = buffer.size() - offset;

   size_t written = process(buf, buf_size);
   int outl = buf_size - written;
   secure_vector<uint8_t> out(outl);

   if(!EVP_CipherFinal_ex(m_cipher, out.data(), &outl))
      throw OpenSSL_Error("EVP_CipherFinal_ex", ERR_get_error());
   copy_mem(buf + written, out.data(), outl);
   written += outl;
   buffer.resize(offset + written);
   }

size_t OpenSSL_Cipher_Mode::update_granularity() const
   {
   return m_block_size * BOTAN_BLOCK_CIPHER_PAR_MULT;
   }

size_t OpenSSL_Cipher_Mode::minimum_final_size() const
   {
   return 0; // no padding
   }

size_t OpenSSL_Cipher_Mode::default_nonce_length() const
   {
   return m_block_size;
   }

bool OpenSSL_Cipher_Mode::valid_nonce_length(size_t nonce_len) const
   {
   return (nonce_len == 0 || nonce_len == m_block_size);
   }

size_t OpenSSL_Cipher_Mode::output_length(size_t input_length) const
   {
   if(input_length == 0)
      return m_block_size;
   else
      return round_up(input_length, m_block_size);
   }

void OpenSSL_Cipher_Mode::clear()
   {
   m_key_set = false;
   m_nonce_set = false;

   const EVP_CIPHER* algo = EVP_CIPHER_CTX_cipher(m_cipher);

   if(!EVP_CIPHER_CTX_cleanup(m_cipher))
      throw OpenSSL_Error("EVP_CIPHER_CTX_cleanup", ERR_get_error());
   EVP_CIPHER_CTX_init(m_cipher);
   if(!EVP_CipherInit_ex(m_cipher, algo, nullptr, nullptr, nullptr,
                         m_direction == ENCRYPTION ? 1 : 0))
      throw OpenSSL_Error("EVP_CipherInit_ex clear", ERR_get_error());
   if(!EVP_CIPHER_CTX_set_padding(m_cipher, 0))
      throw OpenSSL_Error("EVP_CIPHER_CTX_set_padding clear", ERR_get_error());
   }

void OpenSSL_Cipher_Mode::reset()
   {
   if(!EVP_CipherInit_ex(m_cipher, nullptr, nullptr, nullptr, nullptr, -1))
      throw OpenSSL_Error("EVP_CipherInit_ex clear", ERR_get_error());
   m_nonce_set = false;
   }

Key_Length_Specification OpenSSL_Cipher_Mode::key_spec() const
   {
   return Key_Length_Specification(EVP_CIPHER_CTX_key_length(m_cipher));
   }

void OpenSSL_Cipher_Mode::key_schedule(const uint8_t key[], size_t length)
   {
   if(!EVP_CIPHER_CTX_set_key_length(m_cipher, length))
      throw OpenSSL_Error("EVP_CIPHER_CTX_set_key_length", ERR_get_error());
   if(!EVP_CipherInit_ex(m_cipher, nullptr, nullptr, key, nullptr, -1))
      throw OpenSSL_Error("EVP_CipherInit_ex key", ERR_get_error());
   m_key_set = true;
   m_nonce_set = false;
   }

}

Cipher_Mode*
make_openssl_cipher_mode(const std::string& name, Cipher_Dir direction)
   {
#define MAKE_OPENSSL_MODE(evp_fn) \
   new OpenSSL_Cipher_Mode(name, (evp_fn)(), direction)

#if defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_MODE_CBC) && !defined(OPENSSL_NO_AES)
   if(name == "AES-128/CBC/NoPadding")
      return MAKE_OPENSSL_MODE(EVP_aes_128_cbc);
   if(name == "AES-192/CBC/NoPadding")
      return MAKE_OPENSSL_MODE(EVP_aes_192_cbc);
   if(name == "AES-256/CBC/NoPadding")
      return MAKE_OPENSSL_MODE(EVP_aes_256_cbc);
#endif

#undef MAKE_OPENSSL_MODE
   return nullptr;
   }

}
