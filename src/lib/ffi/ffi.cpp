/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/system_rng.h>
#include <botan/auto_rng.h>
#include <botan/lookup.h>
#include <botan/aead.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/pbkdf.h>
#include <botan/version.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/data_src.h>
#include <botan/hex.h>
#include <botan/mem_ops.h>
#include <botan/x509_key.h>
#include <cstring>
#include <memory>

#if defined(BOTAN_HAS_RSA)
  #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_ECDH)
  #include <botan/ecdh.h>
#endif

#if defined(BOTAN_HAS_CURVE_25519)
  #include <botan/curve25519.h>
#endif

#if defined(BOTAN_HAS_BCRYPT)
  #include <botan/bcrypt.h>
#endif

namespace {

#define BOTAN_ASSERT_ARG_NON_NULL(p) \
   do { if(!p) throw std::invalid_argument("Argument " #p " is null"); } while(0)

template<typename T, uint32_t MAGIC>
struct botan_struct
   {
   public:
      botan_struct(T* obj) : m_magic(MAGIC), m_obj(obj) {}
      ~botan_struct() { m_magic = 0; m_obj.reset(); }

      T* get() const
         {
         if(m_magic != MAGIC)
            throw std::runtime_error("Bad magic " + std::to_string(m_magic) +
                                     " in ffi object expected " + std::to_string(MAGIC));
         return m_obj.get();
         }
   private:
      uint32_t m_magic = 0;
      std::unique_ptr<T> m_obj;
   };

void log_exception(const char* func_name, const char* what)
   {
   fprintf(stderr, "%s: %s\n", func_name, what);
   }

template<typename T, uint32_t M>
T& safe_get(botan_struct<T,M>* p)
   {
   if(!p)
      throw std::runtime_error("Null pointer argument");
   if(T* t = p->get())
      return *t;
   throw std::runtime_error("Invalid object pointer");
   }

template<typename T, uint32_t M, typename F>
int apply_fn(botan_struct<T, M>* o, const char* func_name, F func)
   {
   try
      {
      if(!o)
         throw std::runtime_error("Null object to " + std::string(func_name));
      if(T* t = o->get())
         return func(*t);
      }
   catch(std::exception& e)
      {
      log_exception(func_name, e.what());
      return -1;
      }
   catch(...)
      {
      log_exception(func_name, "unknown exception type");
      return -2;
      }

   return -1;
   }

inline int write_output(uint8_t out[], size_t* out_len, const uint8_t buf[], size_t buf_len)
   {
   Botan::clear_mem(out, *out_len);
   const size_t avail = *out_len;
   *out_len = buf_len;
   if(avail >= buf_len)
      {
      Botan::copy_mem(out, buf, buf_len);
      return 0;
      }
   return -1;
   }

template<typename Alloc>
int write_vec_output(uint8_t out[], size_t* out_len, const std::vector<uint8_t, Alloc>& buf)
   {
   return write_output(out, out_len, buf.data(), buf.size());
   }

inline int write_str_output(uint8_t out[], size_t* out_len, const std::string& str)
   {
   return write_output(out, out_len,
                       reinterpret_cast<const uint8_t*>(str.c_str()),
                       str.size() + 1);
   }

inline int write_str_output(char out[], size_t* out_len, const std::string& str)
   {
   return write_str_output(reinterpret_cast<uint8_t*>(out), out_len, str);
   }

#define BOTAN_FFI_DO(T, obj, block) apply_fn(obj, BOTAN_CURRENT_FUNCTION, [=](T& obj) { do { block } while(0); return 0; })

}

extern "C" {

#define BOTAN_FFI_DECLARE_STRUCT(NAME, TYPE, MAGIC) \
   struct NAME : public botan_struct<TYPE, MAGIC> { explicit NAME(TYPE* x) : botan_struct(x) {} }

struct botan_cipher_struct : public botan_struct<Botan::Cipher_Mode, 0xB4A2BF9C>
   {
   explicit botan_cipher_struct(Botan::Cipher_Mode* x) : botan_struct(x) {}
   Botan::secure_vector<uint8_t> m_buf;
   };

BOTAN_FFI_DECLARE_STRUCT(botan_rng_struct, Botan::RandomNumberGenerator, 0x4901F9C1);
BOTAN_FFI_DECLARE_STRUCT(botan_hash_struct, Botan::HashFunction, 0x1F0A4F84);
BOTAN_FFI_DECLARE_STRUCT(botan_mac_struct, Botan::MessageAuthenticationCode, 0xA06E8FC1);
BOTAN_FFI_DECLARE_STRUCT(botan_pubkey_struct, Botan::Public_Key, 0x2C286519);
BOTAN_FFI_DECLARE_STRUCT(botan_privkey_struct, Botan::Private_Key, 0x7F96385E);
BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_encrypt_struct, Botan::PK_Encryptor, 0x891F3FC3);
BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_decrypt_struct, Botan::PK_Decryptor, 0x912F3C37);
BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_sign_struct, Botan::PK_Signer, 0x1AF0C39F);
BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_verify_struct, Botan::PK_Verifier, 0x2B91F936);
BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_ka_struct, Botan::PK_Key_Agreement, 0x2939CAB1);

/*
* Versioning
*/
uint32_t botan_ffi_api_version()
   {
   return 20150210; // should match value in info.txt
   }

const char* botan_version_string()
   {
   return Botan::version_cstr();
   }

uint32_t botan_version_major() { return Botan::version_major(); }
uint32_t botan_version_minor() { return Botan::version_minor(); }
uint32_t botan_version_patch() { return Botan::version_patch(); }
uint32_t botan_version_datestamp()  { return Botan::version_datestamp(); }

int botan_same_mem(const uint8_t* x, const uint8_t* y, size_t len)
   {
   return Botan::same_mem(x, y, len) ? 0 : 1;
   }

int botan_hex_encode(const uint8_t* in, size_t len, char* out, uint32_t flags)
   {
   try
      {
      const bool uppercase = (flags & BOTAN_FFI_HEX_LOWER_CASE) == 0;
      Botan::hex_encode(out, in, len, uppercase);
      return 0;
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }

   return 1;
   }

int botan_rng_init(botan_rng_t* rng_out, const char* rng_type)
   {
   // Just gives unique_ptr something to delete, really
   class RNG_Wrapper : public Botan::RandomNumberGenerator
      {
      public:
         RNG_Wrapper(Botan::RandomNumberGenerator& rng) : m_rng(rng) {}
         void randomize(Botan::byte out[], size_t len) override { m_rng.randomize(out, len); }
         bool is_seeded() const override { return m_rng.is_seeded(); }
         void clear() override { m_rng.clear(); }
         std::string name() const { return m_rng.name(); }
         void reseed(size_t poll_bits = 256) { m_rng.reseed(poll_bits); }
         void add_entropy(const Botan::byte in[], size_t len) { m_rng.add_entropy(in, len); }
      private:
         Botan::RandomNumberGenerator& m_rng;
      };

   try
      {
      BOTAN_ASSERT_ARG_NON_NULL(rng_out);

      if(rng_type == nullptr || *rng_type == 0)
         rng_type = "system";

      const std::string rng_type_s(rng_type);

      std::unique_ptr<Botan::RandomNumberGenerator> rng;

      if(rng_type_s == "system")
         rng.reset(new RNG_Wrapper(Botan::system_rng()));
      else if(rng_type_s == "user")
         rng.reset(new Botan::AutoSeeded_RNG);

      if(rng)
         {
         *rng_out = new botan_rng_struct(rng.release());
         return 0;
         }
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }
   catch(...)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, "unknown");
      }

   return -1;
   }

int botan_rng_destroy(botan_rng_t rng)
   {
   delete rng;
   return 0;
   }

int botan_rng_get(botan_rng_t rng, uint8_t* out, size_t out_len)
   {
   return BOTAN_FFI_DO(Botan::RandomNumberGenerator, rng, { rng.randomize(out, out_len); });
   }

int botan_rng_reseed(botan_rng_t rng, size_t bits)
   {
   return BOTAN_FFI_DO(Botan::RandomNumberGenerator, rng, { rng.reseed(bits); });
   }

int botan_hash_init(botan_hash_t* hash, const char* hash_name, uint32_t flags)
   {
   try
      {
      if(hash == nullptr || hash_name == nullptr || *hash_name == 0)
         return BOTAN_FFI_ERROR_NULL_POINTER;
      if(flags != 0)
         return BOTAN_FFI_ERROR_BAD_FLAG;

      if(auto h = Botan::get_hash_function(hash_name))
         {
         *hash = new botan_hash_struct(h);
         return 0;
         }
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }
   catch(...)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, "unknown");
      }

   return BOTAN_FFI_ERROR_EXCEPTION_THROWN;
   }

int botan_hash_destroy(botan_hash_t hash)
   {
   delete hash;
   return 0;
   }

int botan_hash_output_length(botan_hash_t hash, size_t* out)
   {
   return BOTAN_FFI_DO(Botan::HashFunction, hash, { *out = hash.output_length(); });
   }

int botan_hash_clear(botan_hash_t hash)
   {
   return BOTAN_FFI_DO(Botan::HashFunction, hash, { hash.clear(); });
   }

int botan_hash_update(botan_hash_t hash, const uint8_t* buf, size_t len)
   {
   return BOTAN_FFI_DO(Botan::HashFunction, hash, { hash.update(buf, len); });
   }

int botan_hash_final(botan_hash_t hash, uint8_t out[])
   {
   return BOTAN_FFI_DO(Botan::HashFunction, hash, { hash.final(out); });
   }

int botan_mac_init(botan_mac_t* mac, const char* mac_name, uint32_t flags)
   {
   try
      {
      if(!mac || !mac_name || flags != 0)
         return -1;

      if(auto m = Botan::get_mac(mac_name))
         {
         *mac = new botan_mac_struct(m);
         return 0;
         }
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }
   catch(...)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, "unknown");
      }

   return -2;
   }

int botan_mac_destroy(botan_mac_t mac)
   {
   delete mac;
   return 0;
   }

int botan_mac_set_key(botan_mac_t mac, const uint8_t* key, size_t key_len)
   {
   return BOTAN_FFI_DO(Botan::MessageAuthenticationCode, mac, { mac.set_key(key, key_len); });
   }

int botan_mac_output_length(botan_mac_t mac, size_t* out)
   {
   return BOTAN_FFI_DO(Botan::MessageAuthenticationCode, mac, { *out = mac.output_length(); });
   }

int botan_mac_clear(botan_mac_t mac)
   {
   return BOTAN_FFI_DO(Botan::MessageAuthenticationCode, mac, { mac.clear(); });
   }

int botan_mac_update(botan_mac_t mac, const uint8_t* buf, size_t len)
   {
   return BOTAN_FFI_DO(Botan::MessageAuthenticationCode, mac, { mac.update(buf, len); });
   }

int botan_mac_final(botan_mac_t mac, uint8_t out[])
   {
   return BOTAN_FFI_DO(Botan::MessageAuthenticationCode, mac, { mac.final(out); });
   }

int botan_cipher_init(botan_cipher_t* cipher, const char* cipher_name, uint32_t flags)
   {
   try
      {
      const bool encrypt_p = ((flags & BOTAN_CIPHER_INIT_FLAG_MASK_DIRECTION) == BOTAN_CIPHER_INIT_FLAG_ENCRYPT);
      const Botan::Cipher_Dir dir = encrypt_p ? Botan::ENCRYPTION : Botan::DECRYPTION;
      std::unique_ptr<Botan::Cipher_Mode> mode(Botan::get_cipher_mode(cipher_name, dir));
      if(!mode)
         return -1;
      *cipher = new botan_cipher_struct(mode.release());
      return 0;
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }
   catch(...)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, "unknown");
      }

   return -1;
   }

int botan_cipher_destroy(botan_cipher_t cipher)
   {
   delete cipher;
   return 0;
   }

int botan_cipher_clear(botan_cipher_t cipher)
   {
   return BOTAN_FFI_DO(Botan::Cipher_Mode, cipher, { cipher.clear(); });
   }

int botan_cipher_set_key(botan_cipher_t cipher,
                         const uint8_t* key, size_t key_len)
   {
   return BOTAN_FFI_DO(Botan::Cipher_Mode, cipher, { cipher.set_key(key, key_len); });
   }

int botan_cipher_start(botan_cipher_t cipher_obj,
                       const uint8_t* nonce, size_t nonce_len)
   {
   try
      {
      Botan::Cipher_Mode& cipher = safe_get(cipher_obj);
      BOTAN_ASSERT(cipher.start(nonce, nonce_len).empty(), "Ciphers have no prefix");
      cipher_obj->m_buf.reserve(cipher.update_granularity());
      return 0;
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }

   return -1;
   }

int botan_cipher_update(botan_cipher_t cipher_obj,
                        uint32_t flags,
                        uint8_t output[],
                        size_t output_size,
                        size_t* output_written,
                        const uint8_t input[],
                        size_t input_size,
                        size_t* input_consumed)
   {
   using namespace Botan;

   try
      {
      Cipher_Mode& cipher = safe_get(cipher_obj);
      secure_vector<uint8_t>& mbuf = cipher_obj->m_buf;

      const bool final_input = (flags & BOTAN_CIPHER_UPDATE_FLAG_FINAL);

      if(final_input)
         {
         mbuf.assign(input, input + input_size);
         *input_consumed = input_size;
         *output_written = 0;

         try
            {
            cipher.finish(mbuf);
            }
         catch(Integrity_Failure& e)
            {
            log_exception(BOTAN_CURRENT_FUNCTION, e.what());
            return -2;
            }

         *output_written = mbuf.size();

         if(mbuf.size() <= output_size)
            {
            copy_mem(output, mbuf.data(), mbuf.size());
            mbuf.clear();
            return 0;
            }

         return -1;
         }

      if(input_size == 0)
         {
         // Currently must take entire buffer in this case
         *output_written = mbuf.size();
         if(output_size >= mbuf.size())
            {
            copy_mem(output, mbuf.data(), mbuf.size());
            mbuf.clear();
            return 0;
            }

         return -1;
         }

      const size_t ud = cipher.update_granularity();
      BOTAN_ASSERT(cipher.update_granularity() > cipher.minimum_final_size(), "logic error");

#if 0
      // Avoiding double copy:
      if(Online_Cipher_Mode* ocm = dynamic_cast<Online_Cipher_Mode*>(&cipher))
         {
         const size_t taken = round_down(input_size, ud);
         *input_consumed = taken;
         *output_size = taken;
         copy_mem(output, input, taken);
         ocm->update_in_place(output, taken);
         return 0;
         }
#endif

      mbuf.resize(ud);
      size_t taken = 0, written = 0;

      while(input_size >= ud && output_size >= ud)
         {
         copy_mem(mbuf.data(), input, ud);
         cipher.update(mbuf);

         input_size -= ud;
         input += ud;
         taken += ud;

         output_size -= ud;
         output += ud;
         written += ud;
         }

      *output_written = written;
      *input_consumed = taken;

      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }

   return -1;
   }

int botan_cipher_set_associated_data(botan_cipher_t cipher,
                                     const uint8_t* ad,
                                     size_t ad_len)
   {
   return BOTAN_FFI_DO(Botan::Cipher_Mode, cipher, {
      if(Botan::AEAD_Mode* aead = dynamic_cast<Botan::AEAD_Mode*>(&cipher))
         {
         aead->set_associated_data(ad, ad_len);
         return 0;
         }
      return -1;
      });
   }

int botan_cipher_valid_nonce_length(botan_cipher_t cipher, size_t nl)
   {
   return BOTAN_FFI_DO(Botan::Cipher_Mode, cipher, { return cipher.valid_nonce_length(nl) ? 1 : 0; });
   }

int botan_cipher_get_default_nonce_length(botan_cipher_t cipher, size_t* nl)
   {
   return BOTAN_FFI_DO(Botan::Cipher_Mode, cipher, { *nl = cipher.default_nonce_length(); });
   }

int botan_cipher_get_update_granularity(botan_cipher_t cipher, size_t* ug)
   {
   return BOTAN_FFI_DO(Botan::Cipher_Mode, cipher, { *ug = cipher.update_granularity(); });
   }

int botan_cipher_get_tag_length(botan_cipher_t cipher, size_t* tl)
   {
   return BOTAN_FFI_DO(Botan::Cipher_Mode, cipher, { *tl = cipher.tag_size(); });
   }

int botan_pbkdf(const char* pbkdf_algo, uint8_t out[], size_t out_len,
                const char* pass, const uint8_t salt[], size_t salt_len,
                size_t iterations)
   {
   try
      {
      std::unique_ptr<Botan::PBKDF> pbkdf(Botan::get_pbkdf(pbkdf_algo));
      pbkdf->pbkdf_iterations(out, out_len, pass, salt, salt_len, iterations);
      return 0;
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }

   return -1;
   }

int botan_pbkdf_timed(const char* pbkdf_algo,
                      uint8_t out[], size_t out_len,
                      const char* password,
                      const uint8_t salt[], size_t salt_len,
                      size_t ms_to_run,
                      size_t* iterations_used)
   {
   try
      {
      std::unique_ptr<Botan::PBKDF> pbkdf(Botan::get_pbkdf(pbkdf_algo));
      pbkdf->pbkdf_timed(out, out_len, password, salt, salt_len,
                         std::chrono::milliseconds(ms_to_run),
                         *iterations_used);
      return 0;
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }

   return -1;
   }

int botan_kdf(const char* kdf_algo,
              uint8_t out[], size_t out_len,
              const uint8_t secret[], size_t secret_len,
              const uint8_t salt[], size_t salt_len)
   {
   try
      {
      std::unique_ptr<Botan::KDF> kdf(Botan::get_kdf(kdf_algo));
      kdf->kdf(out, out_len, secret, secret_len, salt, salt_len);
      return 0;
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }

   return -1;
   }

#if defined(BOTAN_HAS_BCRYPT)
int botan_bcrypt_generate(uint8_t* out, size_t* out_len,
                          const char* pass,
                          botan_rng_t rng_obj, size_t wf,
                          uint32_t flags)
   {
   try
      {
      BOTAN_ASSERT_ARG_NON_NULL(out);
      BOTAN_ASSERT_ARG_NON_NULL(out_len);
      BOTAN_ASSERT_ARG_NON_NULL(pass);

      if(flags != 0)
         return BOTAN_FFI_ERROR_BAD_FLAG;

      if(wf < 2 || wf > 30)
         throw std::runtime_error("Bad bcrypt work factor " + std::to_string(wf));

      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);
      const std::string bcrypt = Botan::generate_bcrypt(pass, rng, wf);
      return write_str_output(out, out_len, bcrypt);
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }
   catch(...)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, "unknown");
      }

   return BOTAN_FFI_ERROR_EXCEPTION_THROWN;
   }

int botan_bcrypt_is_valid(const char* pass, const char* hash)
   {
   try
      {
      if(Botan::check_bcrypt(pass, hash))
         return 0; // success
      return 1;
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }
   catch(...)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, "unknown");
      }

   return BOTAN_FFI_ERROR_EXCEPTION_THROWN;
   }

#endif

int botan_privkey_create_rsa(botan_privkey_t* key_obj, botan_rng_t rng_obj, size_t n_bits)
   {
   try
      {
      if(key_obj == nullptr || rng_obj == nullptr)
         return -1;
      if(n_bits < 1024 || n_bits > 16*1024)
         return -2;

      *key_obj = nullptr;

#if defined(BOTAN_HAS_RSA)
      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);
      std::unique_ptr<Botan::Private_Key> key(new Botan::RSA_PrivateKey(rng, n_bits));
      *key_obj = new botan_privkey_struct(key.release());
      return 0;
#endif
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }

   return BOTAN_FFI_ERROR_EXCEPTION_THROWN;
   }


int botan_privkey_create_ecdsa(botan_privkey_t* key_obj, botan_rng_t rng_obj, const char* param_str)
   {
   try
      {
      if(key_obj == nullptr || rng_obj == nullptr || param_str == nullptr || *param_str == 0)
         return -1;

      *key_obj = nullptr;

#if defined(BOTAN_HAS_ECDSA)
      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);
      Botan::EC_Group grp(param_str);
      std::unique_ptr<Botan::Private_Key> key(new Botan::ECDSA_PrivateKey(rng, grp));
      *key_obj = new botan_privkey_struct(key.release());
      return 0;
#endif
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }

   return BOTAN_FFI_ERROR_EXCEPTION_THROWN;
   }

int botan_privkey_create_ecdh(botan_privkey_t* key_obj, botan_rng_t rng_obj, const char* param_str)
   {
   try
      {
      if(key_obj == nullptr || rng_obj == nullptr || param_str == nullptr || *param_str == 0)
         return -1;

      *key_obj = nullptr;

      const std::string params(param_str);

#if defined(BOTAN_HAS_CURVE_25519)
      if(params == "curve25519")
         {
         std::unique_ptr<Botan::Private_Key> key(new Botan::Curve25519_PrivateKey(safe_get(rng_obj)));
         *key_obj = new botan_privkey_struct(key.release());
         return 0;
         }
#endif

#if defined(BOTAN_HAS_ECDH)
      Botan::EC_Group grp(params);
      std::unique_ptr<Botan::Private_Key> key(new Botan::ECDH_PrivateKey(safe_get(rng_obj), grp));
      *key_obj = new botan_privkey_struct(key.release());
      return 0;
#endif
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }

   return BOTAN_FFI_ERROR_EXCEPTION_THROWN;
   }

int botan_privkey_load(botan_privkey_t* key, botan_rng_t rng_obj,
                       const uint8_t bits[], size_t len,
                       const char* password)
   {
   *key = nullptr;

   try
      {
      Botan::DataSource_Memory src(bits, len);

      if(password == nullptr)
         password = "";

      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);

      std::unique_ptr<Botan::PKCS8_PrivateKey> pkcs8;
      pkcs8.reset(Botan::PKCS8::load_key(src, rng, static_cast<std::string>(password)));

      if(pkcs8)
         {
         *key = new botan_privkey_struct(pkcs8.release());
         return 0;
         }
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }

   return -1;
   }

int botan_privkey_destroy(botan_privkey_t key)
   {
   delete key;
   return 0;
   }

int botan_pubkey_destroy(botan_privkey_t key)
   {
   delete key;
   return 0;
   }

int botan_privkey_export_pubkey(botan_pubkey_t* pubout, botan_privkey_t key_obj)
   {
   try
      {
      std::unique_ptr<Botan::Public_Key> pubkey(
         Botan::X509::load_key(
            Botan::X509::BER_encode(safe_get(key_obj))));
      *pubout = new botan_pubkey_struct(pubkey.release());
      return 0;
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }

   return BOTAN_FFI_ERROR_EXCEPTION_THROWN;
   }

int botan_pubkey_algo_name(botan_pubkey_t key, char out[], size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::Public_Key, key, { return write_str_output(out, out_len, key.algo_name()); });
   }

int botan_pubkey_export(botan_pubkey_t key, uint8_t out[], size_t* out_len, uint32_t flags)
   {
   return BOTAN_FFI_DO(Botan::Public_Key, key, {
      if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_DER)
         return write_vec_output(out, out_len, Botan::X509::BER_encode(key));
      else if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_PEM)
         return write_str_output(out, out_len, Botan::X509::PEM_encode(key));
      else
         return -2;
      });
   }

int botan_privkey_export(botan_privkey_t key, uint8_t out[], size_t* out_len, uint32_t flags)
   {
   return BOTAN_FFI_DO(Botan::Private_Key, key, {
      if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_DER)
         return write_vec_output(out, out_len, Botan::PKCS8::BER_encode(key));
      else if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_PEM)
         return write_str_output(out, out_len, Botan::PKCS8::PEM_encode(key));
      else
         return -2;
      });
   }

int botan_privkey_export_encrypted(botan_privkey_t key,
                                   uint8_t out[], size_t* out_len,
                                   botan_rng_t rng_obj,
                                   const char* pass,
                                   const char* pbe,
                                   uint32_t flags)
   {
   return BOTAN_FFI_DO(Botan::Private_Key, key, {
      auto pbkdf_time = std::chrono::milliseconds(300);
      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);

      if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_DER)
         return write_vec_output(out, out_len, Botan::PKCS8::BER_encode(key, rng, pass, pbkdf_time, pbe));
      else if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_PEM)
         return write_str_output(out, out_len, Botan::PKCS8::PEM_encode(key, rng, pass, pbkdf_time, pbe));
      else
         return -2;
      });
   }

int botan_pubkey_estimated_strength(botan_pubkey_t key, size_t* estimate)
   {
   return BOTAN_FFI_DO(Botan::Public_Key, key, { *estimate = key.estimated_strength(); });
   }

int botan_pubkey_fingerprint(botan_pubkey_t key, const char* hash_fn,
                             uint8_t out[], size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::Public_Key, key, {
      std::unique_ptr<Botan::HashFunction> h(Botan::get_hash(hash_fn));
      return write_vec_output(out, out_len, h->process(key.x509_subject_public_key()));
      });
   }

int botan_pk_op_encrypt_create(botan_pk_op_encrypt_t* op,
                               botan_pubkey_t key_obj,
                               const char* padding,
                               uint32_t flags)
   {
   try
      {
      BOTAN_ASSERT_NONNULL(op);

      if(flags != 0)
         return BOTAN_FFI_ERROR_BAD_FLAG;

      std::unique_ptr<Botan::PK_Encryptor> pk(new Botan::PK_Encryptor_EME(safe_get(key_obj), padding));
      *op = new botan_pk_op_encrypt_struct(pk.release());
      return 0;
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }

   return -1;
   }

int botan_pk_op_encrypt_destroy(botan_pk_op_encrypt_t op)
   {
   delete op;
   return 0;
   }

int botan_pk_op_encrypt(botan_pk_op_encrypt_t op,
                        botan_rng_t rng_obj,
                        uint8_t out[], size_t* out_len,
                        const uint8_t plaintext[], size_t plaintext_len)
   {
   return BOTAN_FFI_DO(Botan::PK_Encryptor, op, {
      return write_vec_output(out, out_len, op.encrypt(plaintext, plaintext_len, safe_get(rng_obj)));
      });
   }

/*
* Public Key Decryption
*/
int botan_pk_op_decrypt_create(botan_pk_op_decrypt_t* op,
                               botan_privkey_t key_obj,
                               const char* padding,
                               uint32_t flags)
   {
   try
      {
      BOTAN_ASSERT_NONNULL(op);

      if(flags != 0)
         return BOTAN_FFI_ERROR_BAD_FLAG;

      std::unique_ptr<Botan::PK_Decryptor> pk(new Botan::PK_Decryptor_EME(safe_get(key_obj), padding));
      *op = new botan_pk_op_decrypt_struct(pk.release());
      return 0;
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }

   return -1;
   }

int botan_pk_op_decrypt_destroy(botan_pk_op_decrypt_t op)
   {
   delete op;
   return 0;
   }

int botan_pk_op_decrypt(botan_pk_op_decrypt_t op,
                        uint8_t out[], size_t* out_len,
                        uint8_t ciphertext[], size_t ciphertext_len)
   {
   return BOTAN_FFI_DO(Botan::PK_Decryptor, op, {
      return write_vec_output(out, out_len, op.decrypt(ciphertext, ciphertext_len));
      });
   }

/*
* Signature Generation
*/
int botan_pk_op_sign_create(botan_pk_op_sign_t* op,
                            botan_privkey_t key_obj,
                            const char* hash,
                            uint32_t flags)
   {
   try
      {
      BOTAN_ASSERT_NONNULL(op);

      if(flags != 0)
         return BOTAN_FFI_ERROR_BAD_FLAG;

      std::unique_ptr<Botan::PK_Signer> pk(new Botan::PK_Signer(safe_get(key_obj), hash));
      *op = new botan_pk_op_sign_struct(pk.release());
      return 0;
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }

   return BOTAN_FFI_ERROR_EXCEPTION_THROWN;
   }

int botan_pk_op_sign_destroy(botan_pk_op_sign_t op)
   {
   delete op;
   return 0;
   }

int botan_pk_op_sign_update(botan_pk_op_sign_t op, const uint8_t in[], size_t in_len)
   {
   return BOTAN_FFI_DO(Botan::PK_Signer, op, { op.update(in, in_len); });
   }

int botan_pk_op_sign_finish(botan_pk_op_sign_t op, botan_rng_t rng_obj, uint8_t out[], size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::PK_Signer, op, {
      return write_vec_output(out, out_len, op.signature(safe_get(rng_obj)));
      });
   }

int botan_pk_op_verify_create(botan_pk_op_verify_t* op,
                              botan_pubkey_t key_obj,
                              const char* hash,
                              uint32_t flags)
   {
   try
      {
      BOTAN_ASSERT_NONNULL(op);

      if(flags != 0)
         return BOTAN_FFI_ERROR_BAD_FLAG;

      std::unique_ptr<Botan::PK_Verifier> pk(new Botan::PK_Verifier(safe_get(key_obj), hash));
      *op = new botan_pk_op_verify_struct(pk.release());
      return 0;
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }

   return -1;
   }

int botan_pk_op_verify_destroy(botan_pk_op_verify_t op)
   {
   delete op;
   return 0;
   }

int botan_pk_op_verify_update(botan_pk_op_verify_t op, const uint8_t in[], size_t in_len)
   {
   return BOTAN_FFI_DO(Botan::PK_Verifier, op, { op.update(in, in_len); });
   }

int botan_pk_op_verify_finish(botan_pk_op_verify_t op, const uint8_t sig[], size_t sig_len)
   {
   return BOTAN_FFI_DO(Botan::PK_Verifier, op, {
      const bool legit = op.check_signature(sig, sig_len);

      if(legit)
         return 0;
      else
         return 1;
      });
   }

int botan_pk_op_key_agreement_create(botan_pk_op_ka_t* op,
                                     botan_privkey_t key_obj,
                                     const char* kdf,
                                     uint32_t flags)
   {
   try
      {
      BOTAN_ASSERT_NONNULL(op);

      if(flags != 0)
         return BOTAN_FFI_ERROR_BAD_FLAG;

      std::unique_ptr<Botan::PK_Key_Agreement> pk(new Botan::PK_Key_Agreement(safe_get(key_obj), kdf));
      *op = new botan_pk_op_ka_struct(pk.release());
      return 0;
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }

   return -1;
   }

int botan_pk_op_key_agreement_destroy(botan_pk_op_ka_t op)
   {
   delete op;
   return 0;
   }

int botan_pk_op_key_agreement_export_public(botan_privkey_t key,
                                            uint8_t out[], size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::Private_Key, key, {
      if(auto kak = dynamic_cast<const Botan::PK_Key_Agreement_Key*>(&key))
         return write_vec_output(out, out_len, kak->public_value());
      return -2;
      });
   }

int botan_pk_op_key_agreement(botan_pk_op_ka_t op,
                              uint8_t out[], size_t* out_len,
                              const uint8_t other_key[], size_t other_key_len,
                              const uint8_t salt[], size_t salt_len)
   {
   return BOTAN_FFI_DO(Botan::PK_Key_Agreement, op, {
      auto k = op.derive_key(*out_len, other_key, other_key_len, salt, salt_len).bits_of();
      return write_vec_output(out, out_len, k);
      });
   }

}

