/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/system_rng.h>
#include <botan/exceptn.h>
#include <botan/auto_rng.h>
#include <botan/aead.h>
#include <botan/block_cipher.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/pbkdf.h>
#include <botan/version.h>
#include <botan/pkcs8.h>
#include <botan/x509cert.h>
#include <botan/data_src.h>
#include <botan/pubkey.h>
#include <botan/hex.h>
#include <botan/mem_ops.h>
#include <botan/x509_key.h>
#include <botan/pk_algs.h>
#include <botan/bigint.h>
#include <botan/reducer.h>
#include <botan/numthry.h>
#include <botan/divide.h>
#include <cstring>
#include <memory>

#if defined(BOTAN_HAS_RSA)
  #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_ELGAMAL)
  #include <botan/elgamal.h>
#endif

#if defined(BOTAN_HAS_DSA)
  #include <botan/dsa.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)
  #include <botan/ecc_key.h>
#endif

#if defined(BOTAN_HAS_DL_PUBLIC_KEY_FAMILY)
  #include <botan/dl_algo.h>
#endif

#if defined(BOTAN_HAS_ECDH)
  #include <botan/ecdh.h>
#endif

#if defined(BOTAN_HAS_CURVE_25519)
  #include <botan/curve25519.h>
#endif

#if defined(BOTAN_HAS_MCELIECE)
  #include <botan/mceliece.h>
#endif

#if defined(BOTAN_HAS_MCEIES)
  #include <botan/mceies.h>
#endif

#if defined(BOTAN_HAS_BCRYPT)
  #include <botan/bcrypt.h>
#endif

#if defined(BOTAN_HAS_HASH_ID)
  #include <botan/hash_id.h>
#endif

#if defined(BOTAN_HAS_TLS)
  #include <botan/tls_client.h>
  #include <botan/tls_server.h>
#endif

namespace {

#define BOTAN_ASSERT_ARG_NON_NULL(p) \
   do { if(!p) throw Botan::Invalid_Argument("Argument " #p " is null"); } while(0)

class FFI_Error : public Botan::Exception
   {
   public:
      explicit FFI_Error(const std::string& what) : Exception("FFI error", what) {}
   };

template<typename T, uint32_t MAGIC>
struct botan_struct
   {
   public:
      botan_struct(T* obj) : m_magic(MAGIC), m_obj(obj) {}
      ~botan_struct() { m_magic = 0; m_obj.reset(); }

      T* get() const
         {
         if(m_magic != MAGIC)
            throw FFI_Error("Bad magic " + std::to_string(m_magic) +
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

int ffi_error_exception_thrown(const char* exn)
   {
   fprintf(stderr, "exception %s\n", exn);
   return BOTAN_FFI_ERROR_EXCEPTION_THROWN;
   }

template<typename T, uint32_t M>
T& safe_get(botan_struct<T,M>* p)
   {
   if(!p)
      throw FFI_Error("Null pointer argument");
   if(T* t = p->get())
      return *t;
   throw FFI_Error("Invalid object pointer");
   }

template<typename T, uint32_t M>
const T& safe_get(const botan_struct<T,M>* p)
   {
   if(!p)
      throw FFI_Error("Null pointer argument");
   if(const T* t = p->get())
      return *t;
   throw FFI_Error("Invalid object pointer");
   }

template<typename T, uint32_t M, typename F>
int apply_fn(botan_struct<T, M>* o, const char* func_name, F func)
   {
   try
      {
      if(!o)
         throw FFI_Error("Null object to " + std::string(func_name));
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
   const size_t avail = *out_len;
   *out_len = buf_len;

   if(avail >= buf_len)
      {
      Botan::copy_mem(out, buf, buf_len);
      return 0;
      }
   else
      {
      Botan::clear_mem(out, avail);
      return BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE;
      }
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

inline int write_str_output(char out[], size_t* out_len, const std::vector<uint8_t>& str_vec)
   {
   return write_output(reinterpret_cast<uint8_t*>(out), out_len,
                       reinterpret_cast<const uint8_t*>(str_vec.data()),
                       str_vec.size());
   }

#define BOTAN_FFI_DO(T, obj, param, block) apply_fn(obj, BOTAN_CURRENT_FUNCTION, [=](T& param) -> int { do { block } while(0); return 0; })

Botan::BigInt pubkey_get_field(const Botan::Public_Key& key,
                               const std::string& field)
   {
   // Maybe this should be `return key.get_integer_field(field_name)`?

#if defined(BOTAN_HAS_RSA)
   if(const Botan::RSA_PublicKey* rsa = dynamic_cast<const Botan::RSA_PublicKey*>(&key))
      {
      if(field == "n")
         return rsa->get_n();
      else if(field == "e")
         return rsa->get_e();
      else
         throw Botan::Exception("Field not supported");
      }
#endif

#if defined(BOTAN_HAS_DL_PUBLIC_KEY_FAMILY)
   // Handles DSA, ElGamal, etc
   if(const Botan::DL_Scheme_PublicKey* dl = dynamic_cast<const Botan::DL_Scheme_PublicKey*>(&key))
      {
      if(field == "p")
         return dl->group_p();
      else if(field == "q")
         return dl->group_q();
      else if(field == "g")
         return dl->group_g();
      else if(field == "y")
         return dl->get_y();
      else
         throw Botan::Exception("Field not supported");
      }
#endif

#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)
   if(const Botan::EC_PublicKey* ecc = dynamic_cast<const Botan::EC_PublicKey*>(&key))
      {
      if(field == "public_x")
         return ecc->public_point().get_affine_x();
      else if(field == "public_y")
         return ecc->public_point().get_affine_y();
      else if(field == "base_x")
         return ecc->domain().get_base_point().get_affine_x();
      else if(field == "base_y")
         return ecc->domain().get_base_point().get_affine_y();
      else if(field == "p")
         return ecc->domain().get_curve().get_p();
      else if(field == "a")
         return ecc->domain().get_curve().get_a();
      else if(field == "b")
         return ecc->domain().get_curve().get_b();
      else if(field == "cofactor")
         return ecc->domain().get_cofactor();
      else if(field == "order")
         return ecc->domain().get_order();
      else
         throw Botan::Exception("Field not supported");
      }
#endif

   // Some other algorithm type not supported by this function
   throw Botan::Exception("Unsupported algorithm type for botan_pubkey_get_field");
   }

Botan::BigInt privkey_get_field(const Botan::Private_Key& key,
                                const std::string& field)
   {
   //return key.get_integer_field(field);

#if defined(BOTAN_HAS_RSA)

   if(const Botan::RSA_PrivateKey* rsa = dynamic_cast<const Botan::RSA_PrivateKey*>(&key))
      {
      if(field == "p")
         return rsa->get_p();
      else if(field == "q")
         return rsa->get_q();
      else if(field == "d")
         return rsa->get_d();
      else if(field == "c")
         return rsa->get_c();
      else if(field == "d1")
         return rsa->get_d1();
      else if(field == "d2")
         return rsa->get_d2();
      else
         return pubkey_get_field(key, field);
      }
#endif

#if defined(BOTAN_HAS_DL_PUBLIC_KEY_FAMILY)
   // Handles DSA, ElGamal, etc
   if(const Botan::DL_Scheme_PrivateKey* dl = dynamic_cast<const Botan::DL_Scheme_PrivateKey*>(&key))
      {
      if(field == "x")
         return dl->get_x();
      else
         return pubkey_get_field(key, field);
      }
#endif

#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)
   if(const Botan::EC_PrivateKey* ecc = dynamic_cast<const Botan::EC_PrivateKey*>(&key))
      {
      if(field == "x")
         return ecc->private_value();
      else
         return pubkey_get_field(key, field);
      }
#endif

   // Some other algorithm type not supported by this function
   throw Botan::Exception("Unsupported algorithm type for botan_privkey_get_field");
   }

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
BOTAN_FFI_DECLARE_STRUCT(botan_mp_struct, Botan::BigInt, 0xC828B9D2);
BOTAN_FFI_DECLARE_STRUCT(botan_block_cipher_struct, Botan::BlockCipher, 0x64C29716);
BOTAN_FFI_DECLARE_STRUCT(botan_hash_struct, Botan::HashFunction, 0x1F0A4F84);
BOTAN_FFI_DECLARE_STRUCT(botan_mac_struct, Botan::MessageAuthenticationCode, 0xA06E8FC1);
BOTAN_FFI_DECLARE_STRUCT(botan_pubkey_struct, Botan::Public_Key, 0x2C286519);
BOTAN_FFI_DECLARE_STRUCT(botan_privkey_struct, Botan::Private_Key, 0x7F96385E);
BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_encrypt_struct, Botan::PK_Encryptor, 0x891F3FC3);
BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_decrypt_struct, Botan::PK_Decryptor, 0x912F3C37);
BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_sign_struct, Botan::PK_Signer, 0x1AF0C39F);
BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_verify_struct, Botan::PK_Verifier, 0x2B91F936);
BOTAN_FFI_DECLARE_STRUCT(botan_pk_op_ka_struct, Botan::PK_Key_Agreement, 0x2939CAB1);

BOTAN_FFI_DECLARE_STRUCT(botan_x509_cert_struct, Botan::X509_Certificate, 0x8F628937);


#if defined(BOTAN_HAS_TLS)
BOTAN_FFI_DECLARE_STRUCT(botan_tls_channel_struct, Botan::TLS::Channel, 0x0212FE99);
#endif

/*
* Versioning
*/
uint32_t botan_ffi_api_version()
   {
   return BOTAN_HAS_FFI;
   }

int botan_ffi_supports_api(uint32_t api_version)
   {
   /*
   * In the future if multiple versions are supported, this
   * function would accept any of them.
   */
   if(api_version == BOTAN_HAS_FFI)
      return 0;
   return -1;
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
   return Botan::same_mem(x, y, len) ? 0 : -1;
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
   try
      {
      BOTAN_ASSERT_ARG_NON_NULL(rng_out);

      if(rng_type == nullptr || *rng_type == 0)
         rng_type = "system";

      const std::string rng_type_s(rng_type);

      std::unique_ptr<Botan::RandomNumberGenerator> rng;

      if(rng_type_s == "system")
         rng.reset(new Botan::System_RNG);
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
   return BOTAN_FFI_DO(Botan::RandomNumberGenerator, rng, r, { r.randomize(out, out_len); });
   }

int botan_rng_reseed(botan_rng_t rng, size_t bits)
   {
   return BOTAN_FFI_DO(Botan::RandomNumberGenerator, rng, r, { r.reseed_from_rng(Botan::system_rng(), bits); });
   }

int botan_mp_init(botan_mp_t* mp)
   {
   *mp = new botan_mp_struct(new Botan::BigInt);
   return 0;
   }

int botan_mp_clear(botan_mp_t mp)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, { bn.clear(); });
   }

int botan_mp_set_from_int(botan_mp_t mp, int initial_value)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, {
      if(initial_value >= 0)
         {
         bn = Botan::BigInt(static_cast<uint64_t>(initial_value));
         }
      else
         {
         bn = Botan::BigInt(static_cast<uint64_t>(-initial_value));
         bn.flip_sign();
         }
      });
   }

int botan_mp_set_from_str(botan_mp_t mp, const char* str)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, { bn = Botan::BigInt(str); });
   }

int botan_mp_set_from_radix_str(botan_mp_t mp, const char* str, size_t radix)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, {
      Botan::BigInt::Base base;
      if(radix == 10)
         base = Botan::BigInt::Decimal;
      else if(radix == 16)
         base = Botan::BigInt::Hexadecimal;
      else
         return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;

      const uint8_t* bytes = reinterpret_cast<const uint8_t*>(str);
      const size_t len = strlen(str);

      bn = Botan::BigInt::decode(bytes, len, base);
      });
   }

int botan_mp_set_from_mp(botan_mp_t dest, const botan_mp_t source)
   {
   return BOTAN_FFI_DO(Botan::BigInt, dest, bn, { bn = safe_get(source); });
   }

int botan_mp_is_negative(const botan_mp_t mp)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, { return bn.is_negative() ? 1 : 0; });
   }

int botan_mp_is_positive(const botan_mp_t mp)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, { return bn.is_positive() ? 1 : 0; });
   }

int botan_mp_flip_sign(botan_mp_t mp)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, { bn.flip_sign(); });
   }

int botan_mp_from_bin(botan_mp_t mp, const uint8_t bin[], size_t bin_len)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, { bn.binary_decode(bin, bin_len); });
   }

int botan_mp_to_hex(const botan_mp_t mp, char* out)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, {
      std::vector<uint8_t> hex = Botan::BigInt::encode(bn, Botan::BigInt::Hexadecimal);
      std::memcpy(out, hex.data(), hex.size());
      out[hex.size()] = 0; // null terminate
      });
   }

int botan_mp_to_str(const botan_mp_t mp, uint8_t digit_base, char* out, size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, {
      Botan::BigInt::Base base;
      if(digit_base == 0 || digit_base == 10)
         base = Botan::BigInt::Decimal;
      else if(digit_base == 16)
         base = Botan::BigInt::Hexadecimal;
      else
         throw FFI_Error("botan_mp_to_str invalid digit base");

      std::vector<uint8_t> hex = Botan::BigInt::encode(bn, base);
      hex.push_back(0); // null terminator
      return write_str_output(out, out_len, hex);
      });
   }

int botan_mp_to_bin(const botan_mp_t mp, uint8_t vec[])
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, { bn.binary_encode(vec); });
   }

int botan_mp_to_uint32(const botan_mp_t mp, uint32_t* val)
   {
   if(val == nullptr) {
   return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, { *val = bn.to_u32bit(); });
   }

int botan_mp_destroy(botan_mp_t mp)
   {
   delete mp;
   return 0;
   }

int botan_mp_add(botan_mp_t result, const botan_mp_t x, const botan_mp_t y)
   {
   return BOTAN_FFI_DO(Botan::BigInt, result, res, { res = safe_get(x) + safe_get(y); });
   }

int botan_mp_sub(botan_mp_t result, const botan_mp_t x, const botan_mp_t y)
   {
   return BOTAN_FFI_DO(Botan::BigInt, result, res, { res = safe_get(x) - safe_get(y); });
   }

int botan_mp_mul(botan_mp_t result, const botan_mp_t x, const botan_mp_t y)
   {
   return BOTAN_FFI_DO(Botan::BigInt, result, res, { res = safe_get(x) * safe_get(y); });
   }

int botan_mp_div(botan_mp_t quotient,
                 botan_mp_t remainder,
                 const botan_mp_t x, const botan_mp_t y)
   {
   return BOTAN_FFI_DO(Botan::BigInt, quotient, q, {
      Botan::BigInt r;
      Botan::divide(safe_get(x), safe_get(y), q, r);
      safe_get(remainder) = r;
      });
   }

int botan_mp_equal(const botan_mp_t x_w, const botan_mp_t y_w)
   {
   return BOTAN_FFI_DO(Botan::BigInt, x_w, x, { return x == safe_get(y_w); });
   }

int botan_mp_is_zero(const botan_mp_t mp)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, { return bn.is_zero(); });
   }

int botan_mp_is_odd(const botan_mp_t mp)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, { return bn.is_odd(); });
   }

int botan_mp_is_even(const botan_mp_t mp)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, { return bn.is_even(); });
   }

int botan_mp_cmp(int* result, const botan_mp_t x_w, const botan_mp_t y_w)
   {
   return BOTAN_FFI_DO(Botan::BigInt, x_w, x, { *result = x.cmp(safe_get(y_w)); });
   }

int botan_mp_swap(botan_mp_t x_w, botan_mp_t y_w)
   {
   return BOTAN_FFI_DO(Botan::BigInt, x_w, x, { x.swap(safe_get(y_w)); });
   }

// Return (base^exponent) % modulus
int botan_mp_powmod(botan_mp_t out, const botan_mp_t base, const botan_mp_t exponent, const botan_mp_t modulus)
   {
   return BOTAN_FFI_DO(Botan::BigInt, out, o,
                       { o = Botan::power_mod(safe_get(base), safe_get(exponent), safe_get(modulus)); });
   }

int botan_mp_lshift(botan_mp_t out, const botan_mp_t in, size_t shift)
   {
   return BOTAN_FFI_DO(Botan::BigInt, out, o, { o = safe_get(in) << shift; });
   }

int botan_mp_rshift(botan_mp_t out, const botan_mp_t in, size_t shift)
   {
   return BOTAN_FFI_DO(Botan::BigInt, out, o, { o = safe_get(in) >> shift; });
   }

int botan_mp_mod_inverse(botan_mp_t out, const botan_mp_t in, const botan_mp_t modulus)
   {
   return BOTAN_FFI_DO(Botan::BigInt, out, o, { o = Botan::inverse_mod(safe_get(in), safe_get(modulus)); });
   }

int botan_mp_mod_mul(botan_mp_t out, const botan_mp_t x, const botan_mp_t y, const botan_mp_t modulus)
   {
   return BOTAN_FFI_DO(Botan::BigInt, out, o, {
      Botan::Modular_Reducer reducer(safe_get(modulus));
      o = reducer.multiply(safe_get(x), safe_get(y));
      });
   }

int botan_mp_rand_bits(botan_mp_t rand_out, botan_rng_t rng, size_t bits)
   {
   return BOTAN_FFI_DO(Botan::RandomNumberGenerator, rng, r, {
      safe_get(rand_out).randomize(r, bits); });
   }

int botan_mp_rand_range(botan_mp_t rand_out,
                        botan_rng_t rng,
                        const botan_mp_t lower,
                        const botan_mp_t upper)
   {
   return BOTAN_FFI_DO(Botan::RandomNumberGenerator, rng, r, {
      safe_get(rand_out) = Botan::BigInt::random_integer(r, safe_get(lower), safe_get(upper)); });
   }

int botan_mp_gcd(botan_mp_t out, const botan_mp_t x, const botan_mp_t y)
   {
   return BOTAN_FFI_DO(Botan::BigInt, out, o, {
      o = Botan::gcd(safe_get(x), safe_get(y)); });
   }

int botan_mp_is_prime(const botan_mp_t mp, botan_rng_t rng, size_t test_prob)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, n,
                       { return (Botan::is_prime(n, safe_get(rng), test_prob)) ? 1 : 0; });
   }

int botan_mp_get_bit(const botan_mp_t mp, size_t bit)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, n, { return (n.get_bit(bit)); });
   }

int botan_mp_set_bit(botan_mp_t mp, size_t bit)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, n, { n.set_bit(bit); });
   }

int botan_mp_clear_bit(botan_mp_t mp, size_t bit)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, n, { n.clear_bit(bit); });
   }

int botan_mp_num_bits(const botan_mp_t mp, size_t* bits)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, n, { *bits = n.bits(); });
   }

int botan_mp_num_bytes(const botan_mp_t mp, size_t* bytes)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, n, { *bytes = n.bytes(); });
   }

int botan_block_cipher_init(botan_block_cipher_t* bc, const char* bc_name)
   {
   try
      {
      if(bc == nullptr || bc_name == nullptr || *bc_name == 0)
         return BOTAN_FFI_ERROR_NULL_POINTER;

      std::unique_ptr<Botan::BlockCipher> cipher(Botan::BlockCipher::create(bc_name));
      if(cipher)
         {
         *bc = new botan_block_cipher_struct(cipher.release());
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

/**
* Destroy a block cipher object
*/
int botan_block_cipher_destroy(botan_block_cipher_t bc)
   {
   delete bc;
   return 0;
   }

int botan_block_cipher_clear(botan_block_cipher_t bc)
   {
   return BOTAN_FFI_DO(Botan::BlockCipher, bc, b, { b.clear(); });
   }

/**
* Set the key for a block cipher instance
*/
int botan_block_cipher_set_key(botan_block_cipher_t bc,
                               const uint8_t key[], size_t len)
   {
   return BOTAN_FFI_DO(Botan::BlockCipher, bc, b, { b.set_key(key, len); });
   }

/**
* Return the positive block size of this block cipher, or negative to
* indicate an error
*/
int botan_block_cipher_block_size(botan_block_cipher_t bc)
   {
   return BOTAN_FFI_DO(Botan::BlockCipher, bc, b, { return b.block_size(); });
   }

int botan_block_cipher_encrypt_blocks(botan_block_cipher_t bc,
                                      const uint8_t in[],
                                      uint8_t out[],
                                      size_t blocks)
   {
   return BOTAN_FFI_DO(Botan::BlockCipher, bc, b, { b.encrypt_n(in, out, blocks); });
   }

int botan_block_cipher_decrypt_blocks(botan_block_cipher_t bc,
                                      const uint8_t in[],
                                      uint8_t out[],
                                      size_t blocks)
   {
   return BOTAN_FFI_DO(Botan::BlockCipher, bc, b, { b.decrypt_n(in, out, blocks); });
   }

int botan_hash_init(botan_hash_t* hash, const char* hash_name, uint32_t flags)
   {
   try
      {
      if(hash == nullptr || hash_name == nullptr || *hash_name == 0)
         return BOTAN_FFI_ERROR_NULL_POINTER;
      if(flags != 0)
         return BOTAN_FFI_ERROR_BAD_FLAG;

      auto h = Botan::HashFunction::create(hash_name);
      if(h)
         {
         *hash = new botan_hash_struct(h.release());
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
   return BOTAN_FFI_DO(Botan::HashFunction, hash, h, { *out = h.output_length(); });
   }

int botan_hash_block_size(botan_hash_t hash, size_t* out)
   {
   return BOTAN_FFI_DO(Botan::HashFunction, hash, h, { *out = h.hash_block_size(); });
   }

int botan_hash_clear(botan_hash_t hash)
   {
   return BOTAN_FFI_DO(Botan::HashFunction, hash, h, { h.clear(); });
   }

int botan_hash_update(botan_hash_t hash, const uint8_t* buf, size_t len)
   {
   return BOTAN_FFI_DO(Botan::HashFunction, hash, h, { h.update(buf, len); });
   }

int botan_hash_final(botan_hash_t hash, uint8_t out[])
   {
   return BOTAN_FFI_DO(Botan::HashFunction, hash, h, { h.final(out); });
   }

int botan_mac_init(botan_mac_t* mac, const char* mac_name, uint32_t flags)
   {
   try
      {
      if(!mac || !mac_name || flags != 0)
         return -1;

      auto m = Botan::MessageAuthenticationCode::create(mac_name);
      if(m)
         {
         *mac = new botan_mac_struct(m.release());
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
   return BOTAN_FFI_DO(Botan::MessageAuthenticationCode, mac, m, { m.set_key(key, key_len); });
   }

int botan_mac_output_length(botan_mac_t mac, size_t* out)
   {
   return BOTAN_FFI_DO(Botan::MessageAuthenticationCode, mac, m, { *out = m.output_length(); });
   }

int botan_mac_clear(botan_mac_t mac)
   {
   return BOTAN_FFI_DO(Botan::MessageAuthenticationCode, mac, m, { m.clear(); });
   }

int botan_mac_update(botan_mac_t mac, const uint8_t* buf, size_t len)
   {
   return BOTAN_FFI_DO(Botan::MessageAuthenticationCode, mac, m, { m.update(buf, len); });
   }

int botan_mac_final(botan_mac_t mac, uint8_t out[])
   {
   return BOTAN_FFI_DO(Botan::MessageAuthenticationCode, mac, m, { m.final(out); });
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
   return BOTAN_FFI_DO(Botan::Cipher_Mode, cipher, c, { c.clear(); });
   }

int botan_cipher_query_keylen(botan_cipher_t cipher,
                              size_t* out_minimum_keylength,
                              size_t* out_maximum_keylength)
   {
   return BOTAN_FFI_DO(Botan::Cipher_Mode, cipher, c, {
      *out_minimum_keylength = c.key_spec().minimum_keylength();
      *out_maximum_keylength = c.key_spec().maximum_keylength();
      });
   }

int botan_cipher_set_key(botan_cipher_t cipher,
                         const uint8_t* key, size_t key_len)
   {
   return BOTAN_FFI_DO(Botan::Cipher_Mode, cipher, c, { c.set_key(key, key_len); });
   }

int botan_cipher_start(botan_cipher_t cipher_obj,
                       const uint8_t* nonce, size_t nonce_len)
   {
   try
      {
      Botan::Cipher_Mode& cipher = safe_get(cipher_obj);
      cipher.start(nonce, nonce_len);
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
         copy_mem(output, mbuf.data(), ud);
         input += ud;
         taken += ud;

         output_size -= ud;
         output += ud;
         written += ud;
         }

      *output_written = written;
      *input_consumed = taken;

      return 0;
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
   return BOTAN_FFI_DO(Botan::Cipher_Mode, cipher, c, {
      if(Botan::AEAD_Mode* aead = dynamic_cast<Botan::AEAD_Mode*>(&c))
         {
         aead->set_associated_data(ad, ad_len);
         return 0;
         }
      return -1;
      });
   }

int botan_cipher_valid_nonce_length(botan_cipher_t cipher, size_t nl)
   {
   return BOTAN_FFI_DO(Botan::Cipher_Mode, cipher, c, { return c.valid_nonce_length(nl) ? 1 : 0; });
   }

int botan_cipher_get_default_nonce_length(botan_cipher_t cipher, size_t* nl)
   {
   return BOTAN_FFI_DO(Botan::Cipher_Mode, cipher, c, { *nl = c.default_nonce_length(); });
   }

int botan_cipher_get_update_granularity(botan_cipher_t cipher, size_t* ug)
   {
   return BOTAN_FFI_DO(Botan::Cipher_Mode, cipher, c, { *ug = c.update_granularity(); });
   }

int botan_cipher_get_tag_length(botan_cipher_t cipher, size_t* tl)
   {
   return BOTAN_FFI_DO(Botan::Cipher_Mode, cipher, c, { *tl = c.tag_size(); });
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
              const uint8_t salt[], size_t salt_len,
              const uint8_t label[], size_t label_len)
   {
   try
      {
      std::unique_ptr<Botan::KDF> kdf(Botan::get_kdf(kdf_algo));
      kdf->kdf(out, out_len, secret, secret_len, salt, salt_len, label, label_len);
      return 0;
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }

   return -1;
   }

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
         throw FFI_Error("Bad bcrypt work factor " + std::to_string(wf));

#if defined(BOTAN_HAS_BCRYPT)
      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);
      const std::string bcrypt = Botan::generate_bcrypt(pass, rng, wf);
      return write_str_output(out, out_len, bcrypt);
#else
      return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
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
#if defined(BOTAN_HAS_BCRYPT)
      return Botan::check_bcrypt(pass, hash) ? 0 : 1;
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
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

int botan_privkey_create(botan_privkey_t* key_obj,
                         const char* algo_name,
                         const char* algo_params,
                         botan_rng_t rng_obj)
   {
   try
      {
      if(key_obj == nullptr)
         return BOTAN_FFI_ERROR_NULL_POINTER;

      *key_obj = nullptr;
      if(rng_obj == nullptr)
         return BOTAN_FFI_ERROR_NULL_POINTER;

      if(algo_name == nullptr)
         algo_name = "RSA";
      if(algo_params == nullptr)
         algo_params = "";

      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);
      std::unique_ptr<Botan::Private_Key> key(
         Botan::create_private_key(algo_name, rng, algo_params));

      if(key)
         {
         *key_obj = new botan_privkey_struct(key.release());
         return 0;
         }
      else
         {
         return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
         }
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }

   return BOTAN_FFI_ERROR_EXCEPTION_THROWN;
   }

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
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
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
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }

   return BOTAN_FFI_ERROR_EXCEPTION_THROWN;
   }

int botan_privkey_create_mceliece(botan_privkey_t* key_obj, botan_rng_t rng_obj, size_t n, size_t t)
   {
   try
      {
      if(key_obj == nullptr || rng_obj == nullptr || n == 0 || t == 0)
         return -1;

      *key_obj = nullptr;

#if defined(BOTAN_HAS_MCELIECE)
      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);
      std::unique_ptr<Botan::Private_Key> key(new Botan::McEliece_PrivateKey(rng, n, t));
      *key_obj = new botan_privkey_struct(key.release());
      return 0;
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      return BOTAN_FFI_ERROR_EXCEPTION_THROWN;
      }
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

int botan_pubkey_load(botan_pubkey_t* key,
                      const uint8_t bits[], size_t bits_len)
   {
   *key = nullptr;

   try
      {
      Botan::DataSource_Memory src(bits, bits_len);
      std::unique_ptr<Botan::Public_Key> pubkey(Botan::X509::load_key(src));

      if(pubkey)
         {
         *key = new botan_pubkey_struct(pubkey.release());
         return 0;
         }
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }

   return -1;
   }

int botan_privkey_load_rsa(botan_privkey_t* key,
                           botan_mp_t rsa_p, botan_mp_t rsa_q, botan_mp_t rsa_e)
   {
#if defined(BOTAN_HAS_RSA)
   *key = nullptr;
   try
      {
      *key = new botan_privkey_struct(new Botan::RSA_PrivateKey(safe_get(rsa_p),
                                                                safe_get(rsa_q),
                                                                safe_get(rsa_e)));
      return 0;
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }
   return -1;
#else
   BOTAN_UNUSED(key, p, q, e);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_pubkey_load_rsa(botan_pubkey_t* key,
                          botan_mp_t n, botan_mp_t e)
   {
#if defined(BOTAN_HAS_RSA)
   *key = nullptr;
   try
      {
      *key = new botan_pubkey_struct(new Botan::RSA_PublicKey(safe_get(n), safe_get(e)));
      return 0;
      }
   catch(std::exception& exn)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, exn.what());
      }

   return -1;
#else
   BOTAN_UNUSED(key, n, e);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_privkey_load_dsa(botan_privkey_t* key,
                           botan_mp_t p, botan_mp_t q, botan_mp_t g, botan_mp_t x)
   {
#if defined(BOTAN_HAS_DSA)
   *key = nullptr;
   try
      {
      Botan::Null_RNG null_rng;
      Botan::DL_Group group(safe_get(p), safe_get(q), safe_get(g));
      *key = new botan_privkey_struct(new Botan::DSA_PrivateKey(null_rng, group, safe_get(x)));
      return 0;
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }
   return -1;
#else
   BOTAN_UNUSED(key, p, q, g, x);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_pubkey_load_dsa(botan_pubkey_t* key,
                          botan_mp_t p, botan_mp_t q, botan_mp_t g, botan_mp_t y)
   {
#if defined(BOTAN_HAS_DSA)
   *key = nullptr;
   try
      {
      Botan::DL_Group group(safe_get(p), safe_get(q), safe_get(g));
      *key = new botan_pubkey_struct(new Botan::DSA_PublicKey(group, safe_get(y)));
      return 0;
      }
   catch(std::exception& exn)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, exn.what());
      }

   return -1;
#else
   BOTAN_UNUSED(key, p, q, g, y);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_pubkey_load_elgamal(botan_pubkey_t* key,
                              botan_mp_t p, botan_mp_t g, botan_mp_t y)
   {
#if defined(BOTAN_HAS_ELGAMAL)
   *key = nullptr;
   try
      {
      Botan::DL_Group group(safe_get(p), safe_get(g));
      *key = new botan_pubkey_struct(new Botan::ElGamal_PublicKey(group, safe_get(y)));
      return 0;
      }
   catch(std::exception& exn)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, exn.what());
      }

   return -1;
#else
   BOTAN_UNUSED(key, p, g, y);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_privkey_load_elgamal(botan_privkey_t* key,
                               botan_mp_t p, botan_mp_t g, botan_mp_t x)
   {
#if defined(BOTAN_HAS_ELGAMAL)
   *key = nullptr;
   try
      {
      Botan::Null_RNG null_rng;
      Botan::DL_Group group(safe_get(p), safe_get(g));
      *key = new botan_privkey_struct(new Botan::ElGamal_PrivateKey(null_rng, group, safe_get(x)));
      return 0;
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }
   return -1;
#else
   BOTAN_UNUSED(key, p, g, x);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_pubkey_get_field(botan_mp_t output,
                           botan_pubkey_t key,
                           const char* field_name_cstr)
   {
   if(field_name_cstr == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

   const std::string field_name(field_name_cstr);

   return BOTAN_FFI_DO(Botan::Public_Key, key, k, {
      safe_get(output) = pubkey_get_field(k, field_name);
      });
   }

int botan_privkey_get_field(botan_mp_t output,
                                      botan_privkey_t key,
                                      const char* field_name_cstr)
   {
   if(field_name_cstr == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

   const std::string field_name(field_name_cstr);

   return BOTAN_FFI_DO(Botan::Private_Key, key, k, {
      safe_get(output) = privkey_get_field(k, field_name);
      });
   }

int botan_privkey_rsa_get_p(botan_mp_t p, botan_privkey_t key)
   {
   return botan_privkey_get_field(p, key, "p");
   }

int botan_privkey_rsa_get_q(botan_mp_t q, botan_privkey_t key)
   {
   return botan_privkey_get_field(q, key, "q");
   }

int botan_privkey_rsa_get_n(botan_mp_t n, botan_privkey_t key)
   {
   return botan_privkey_get_field(n, key, "n");
   }

int botan_privkey_rsa_get_e(botan_mp_t e, botan_privkey_t key)
   {
   return botan_privkey_get_field(e, key, "e");
   }

int botan_privkey_rsa_get_d(botan_mp_t d, botan_privkey_t key)
   {
   return botan_privkey_get_field(d, key, "d");
   }

int botan_pubkey_rsa_get_e(botan_mp_t e, botan_pubkey_t key)
   {
   return botan_pubkey_get_field(e, key, "e");
   }

int botan_pubkey_rsa_get_n(botan_mp_t n, botan_pubkey_t key)
   {
   return botan_pubkey_get_field(n, key, "n");
   }

int botan_privkey_dsa_get_x(botan_mp_t x, botan_privkey_t key)
   {
   return botan_privkey_get_field(x, key, "x");
   }

int botan_pubkey_dsa_get_p(botan_mp_t p, botan_pubkey_t key)
   {
   return botan_pubkey_get_field(p, key, "p");
   }
int botan_pubkey_dsa_get_q(botan_mp_t q, botan_pubkey_t key)
   {
   return botan_pubkey_get_field(q, key, "q");
   }
int botan_pubkey_dsa_get_g(botan_mp_t g, botan_pubkey_t key)
   {
   return botan_pubkey_get_field(g, key, "g");
   }
int botan_pubkey_dsa_get_y(botan_mp_t y, botan_pubkey_t key)
   {
   return botan_pubkey_get_field(y, key, "y");
   }


int botan_privkey_destroy(botan_privkey_t key)
   {
   delete key;
   return 0;
   }

int botan_pubkey_destroy(botan_pubkey_t key)
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
   return BOTAN_FFI_DO(Botan::Public_Key, key, k, { return write_str_output(out, out_len, k.algo_name()); });
   }

int botan_pubkey_check_key(botan_pubkey_t key, botan_rng_t rng, uint32_t flags)
   {
   const bool strong = (flags & BOTAN_CHECK_KEY_EXPENSIVE_TESTS);

   return BOTAN_FFI_DO(Botan::Public_Key, key, k,
                       { return (k.check_key(safe_get(rng), strong) == true) ? 0 : -1; });
   }

int botan_privkey_check_key(botan_privkey_t key, botan_rng_t rng, uint32_t flags)
   {
   const bool strong = (flags & BOTAN_CHECK_KEY_EXPENSIVE_TESTS);
   return BOTAN_FFI_DO(Botan::Private_Key, key, k,
                       { return (k.check_key(safe_get(rng), strong) == true) ? 0 : -1; });
   }

int botan_pubkey_export(botan_pubkey_t key, uint8_t out[], size_t* out_len, uint32_t flags)
   {
   return BOTAN_FFI_DO(Botan::Public_Key, key, k, {
      if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_DER)
         return write_vec_output(out, out_len, Botan::X509::BER_encode(k));
      else if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_PEM)
         return write_str_output(out, out_len, Botan::X509::PEM_encode(k));
      else
         return -2;
      });
   }

int botan_privkey_export(botan_privkey_t key, uint8_t out[], size_t* out_len, uint32_t flags)
   {
   return BOTAN_FFI_DO(Botan::Private_Key, key, k, {
      if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_DER)
         return write_vec_output(out, out_len, Botan::PKCS8::BER_encode(k));
      else if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_PEM)
         return write_str_output(out, out_len, Botan::PKCS8::PEM_encode(k));
      else
         return -2;
      });
   }

int botan_privkey_export_encrypted(botan_privkey_t key,
                                   uint8_t out[], size_t* out_len,
                                   botan_rng_t rng_obj,
                                   const char* pass,
                                   const char* /*ignored - pbe*/,
                                   uint32_t flags)
   {
   return botan_privkey_export_encrypted_pbkdf_iter(key, out, out_len, rng_obj, pass, 100000, nullptr, nullptr, flags);
   }

int botan_privkey_export_encrypted_pbkdf_msec(botan_privkey_t key,
                                              uint8_t out[], size_t* out_len,
                                              botan_rng_t rng_obj,
                                              const char* pass,
                                              uint32_t pbkdf_msec,
                                              size_t* pbkdf_iters_out,
                                              const char* maybe_cipher,
                                              const char* maybe_pbkdf_hash,
                                              uint32_t flags)
   {
   return BOTAN_FFI_DO(Botan::Private_Key, key, k, {
      const std::chrono::milliseconds pbkdf_time(pbkdf_msec);
      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);

      std::string cipher;
      if(maybe_cipher)
         {
         cipher = maybe_cipher;
         }

      std::string pbkdf_hash;
      if(maybe_pbkdf_hash)
         {
         pbkdf_hash = maybe_pbkdf_hash;
         }

      if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_DER)
         {
         return write_vec_output(out, out_len,
                                 Botan::PKCS8::BER_encode_encrypted_pbkdf_msec(k, rng, pass, pbkdf_time, pbkdf_iters_out, cipher, pbkdf_hash));
         }
      else if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_PEM)
         {
         return write_str_output(out, out_len,
                                 Botan::PKCS8::PEM_encode_encrypted_pbkdf_msec(k, rng, pass, pbkdf_time, pbkdf_iters_out, cipher, pbkdf_hash));
         }
      else
         {
         return -2;
         }
      });
   }

int botan_privkey_export_encrypted_pbkdf_iter(botan_privkey_t key,
                                              uint8_t out[], size_t* out_len,
                                              botan_rng_t rng_obj,
                                              const char* pass,
                                              size_t pbkdf_iter,
                                              const char* maybe_cipher,
                                              const char* maybe_pbkdf_hash,
                                              uint32_t flags)
   {
   return BOTAN_FFI_DO(Botan::Private_Key, key, k, {
      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);

      std::string cipher;
      if(maybe_cipher)
         {
         cipher = maybe_cipher;
         }

      std::string pbkdf_hash;
      if(maybe_pbkdf_hash)
         {
         pbkdf_hash = maybe_pbkdf_hash;
         }

      if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_DER)
         {
         return write_vec_output(out, out_len,
                                 Botan::PKCS8::BER_encode_encrypted_pbkdf_iter(k, rng, pass, pbkdf_iter, cipher, pbkdf_hash));
         }
      else if(flags == BOTAN_PRIVKEY_EXPORT_FLAG_PEM)
         {
         return write_str_output(out, out_len,
                                 Botan::PKCS8::PEM_encode_encrypted_pbkdf_iter(k, rng, pass, pbkdf_iter, cipher, pbkdf_hash));
         }
      else
         {
         return -2;
         }
      });
   }

int botan_pubkey_estimated_strength(botan_pubkey_t key, size_t* estimate)
   {
   return BOTAN_FFI_DO(Botan::Public_Key, key, k, { *estimate = k.estimated_strength(); });
   }

int botan_pubkey_fingerprint(botan_pubkey_t key, const char* hash_fn,
                             uint8_t out[], size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::Public_Key, key, k, {
      std::unique_ptr<Botan::HashFunction> h(Botan::HashFunction::create(hash_fn));
      return write_vec_output(out, out_len, h->process(k.public_key_bits()));
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

      *op = nullptr;

      if(flags != 0)
         return BOTAN_FFI_ERROR_BAD_FLAG;

      std::unique_ptr<Botan::PK_Encryptor> pk(new Botan::PK_Encryptor_EME(safe_get(key_obj), Botan::system_rng(), padding));
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
   return BOTAN_FFI_DO(Botan::PK_Encryptor, op, o, {
      return write_vec_output(out, out_len, o.encrypt(plaintext, plaintext_len, safe_get(rng_obj)));
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

      *op = nullptr;

      if(flags != 0)
         return BOTAN_FFI_ERROR_BAD_FLAG;

      std::unique_ptr<Botan::PK_Decryptor> pk(new Botan::PK_Decryptor_EME(safe_get(key_obj), Botan::system_rng(), padding));
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
                        const uint8_t ciphertext[], size_t ciphertext_len)
   {
   return BOTAN_FFI_DO(Botan::PK_Decryptor, op, o, {
      return write_vec_output(out, out_len, o.decrypt(ciphertext, ciphertext_len));
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

      *op = nullptr;

      if(flags != 0)
         return BOTAN_FFI_ERROR_BAD_FLAG;

      std::unique_ptr<Botan::PK_Signer> pk(new Botan::PK_Signer(safe_get(key_obj),Botan::system_rng(),  hash));
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
   return BOTAN_FFI_DO(Botan::PK_Signer, op, o, { o.update(in, in_len); });
   }

int botan_pk_op_sign_finish(botan_pk_op_sign_t op, botan_rng_t rng_obj, uint8_t out[], size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::PK_Signer, op, o, {
      return write_vec_output(out, out_len, o.signature(safe_get(rng_obj)));
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
   return BOTAN_FFI_DO(Botan::PK_Verifier, op, o, { o.update(in, in_len); });
   }

int botan_pk_op_verify_finish(botan_pk_op_verify_t op, const uint8_t sig[], size_t sig_len)
   {
   return BOTAN_FFI_DO(Botan::PK_Verifier, op, o, {
      const bool legit = o.check_signature(sig, sig_len);

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

      *op = nullptr;

      if(flags != 0)
         return BOTAN_FFI_ERROR_BAD_FLAG;

      std::unique_ptr<Botan::PK_Key_Agreement> pk(new Botan::PK_Key_Agreement(safe_get(key_obj), Botan::system_rng(), kdf));
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
   return BOTAN_FFI_DO(Botan::Private_Key, key, k, {
      if(auto kak = dynamic_cast<const Botan::PK_Key_Agreement_Key*>(&k))
         return write_vec_output(out, out_len, kak->public_value());
      return -2;
      });
   }

int botan_pk_op_key_agreement(botan_pk_op_ka_t op,
                              uint8_t out[], size_t* out_len,
                              const uint8_t other_key[], size_t other_key_len,
                              const uint8_t salt[], size_t salt_len)
   {
   return BOTAN_FFI_DO(Botan::PK_Key_Agreement, op, o, {
      auto k = o.derive_key(*out_len, other_key, other_key_len, salt, salt_len).bits_of();
      return write_vec_output(out, out_len, k);
      });
   }

int botan_x509_cert_load_file(botan_x509_cert_t* cert_obj, const char* cert_path)
   {
   try
      {
      if(!cert_obj || !cert_path)
         return -1;

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
      std::unique_ptr<Botan::X509_Certificate> c(new Botan::X509_Certificate(cert_path));

      if(c)
         {
         *cert_obj = new botan_x509_cert_struct(c.release());
         return 0;
         }
#else
      return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
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

int botan_x509_cert_load(botan_x509_cert_t* cert_obj, const uint8_t cert_bits[], size_t cert_bits_len)
   {
   try
      {
      if(!cert_obj || !cert_bits)
         return -1;

      Botan::DataSource_Memory bits(cert_bits, cert_bits_len);

      std::unique_ptr<Botan::X509_Certificate> c(new Botan::X509_Certificate(bits));

      if(c)
         {
         *cert_obj = new botan_x509_cert_struct(c.release());
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

int botan_x509_cert_destroy(botan_x509_cert_t cert)
   {
   delete cert;
   return 0;
   }

int botan_x509_cert_get_time_starts(botan_x509_cert_t cert, char out[], size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, { return write_str_output(out, out_len, c.start_time()); });
   }

int botan_x509_cert_get_time_expires(botan_x509_cert_t cert, char out[], size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, { return write_str_output(out, out_len, c.end_time()); });
   }

int botan_x509_cert_get_serial_number(botan_x509_cert_t cert, uint8_t out[], size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, { return write_vec_output(out, out_len, c.serial_number()); });
   }

int botan_x509_cert_get_fingerprint(botan_x509_cert_t cert, const char* hash, uint8_t out[], size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, { return write_str_output(out, out_len, c.fingerprint(hash)); });
   }

int botan_x509_cert_get_authority_key_id(botan_x509_cert_t cert, uint8_t out[], size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, { return write_vec_output(out, out_len, c.authority_key_id()); });
   }

int botan_x509_cert_get_subject_key_id(botan_x509_cert_t cert, uint8_t out[], size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, { return write_vec_output(out, out_len, c.subject_key_id()); });
   }

int botan_x509_cert_get_public_key_bits(botan_x509_cert_t cert, uint8_t out[], size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, { return write_vec_output(out, out_len, c.subject_public_key_bits()); });
   }


/*
int botan_x509_cert_path_verify(botan_x509_cert_t cert, const char* dir)
{
}
*/

int botan_x509_cert_get_public_key(botan_x509_cert_t cert, botan_pubkey_t* key)
   {
   try
      {
      if(key == nullptr)
         return -1;

      *key = nullptr;

#if defined(BOTAN_HAS_RSA)
      std::unique_ptr<Botan::Public_Key> publicKey(safe_get(cert).subject_public_key());
      *key = new botan_pubkey_struct(publicKey.release());
      return 0;
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
      }
   catch(std::exception& e)
      {
      log_exception(BOTAN_CURRENT_FUNCTION, e.what());
      }

   return BOTAN_FFI_ERROR_EXCEPTION_THROWN;
   }

int botan_x509_cert_get_issuer_dn(botan_x509_cert_t cert,
                                  const char* key, size_t index,
                                  uint8_t out[], size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, { return write_str_output(out, out_len, c.issuer_info(key).at(index)); });
   }

int botan_x509_cert_get_subject_dn(botan_x509_cert_t cert,
                                   const char* key, size_t index,
                                   uint8_t out[], size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, { return write_str_output(out, out_len, c.subject_info(key).at(index)); });
   }

int botan_x509_cert_to_string(botan_x509_cert_t cert, char out[], size_t* out_len)
   {
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, { return write_str_output(out, out_len, c.to_string()); });
   }

int botan_x509_cert_allowed_usage(botan_x509_cert_t cert, unsigned int key_usage)
   {
   return BOTAN_FFI_DO(Botan::X509_Certificate, cert, c, {
      const Botan::Key_Constraints k = static_cast<Botan::Key_Constraints>(key_usage);
      if(c.allowed_usage(k))
         return 0;
      return 1;
      });
   }

int botan_pkcs_hash_id(const char* hash_name, uint8_t pkcs_id[], size_t* pkcs_id_len)
   {
#if defined(BOTAN_HAS_HASH_ID)
   try
      {
      const std::vector<uint8_t> hash_id = Botan::pkcs_hash_id(hash_name);
      return write_output(pkcs_id, pkcs_id_len, hash_id.data(), hash_id.size());
      }
   catch(...)
      {
      return BOTAN_FFI_ERROR_EXCEPTION_THROWN;
      }
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_mceies_decrypt(botan_privkey_t mce_key_obj,
                         const char* aead,
                         const uint8_t ct[], size_t ct_len,
                         const uint8_t ad[], size_t ad_len,
                         uint8_t out[], size_t* out_len)
   {
   try
      {
      Botan::Private_Key& key = safe_get(mce_key_obj);

#if defined(BOTAN_HAS_MCELIECE) && defined(BOTAN_HAS_MCEIES)
      Botan::McEliece_PrivateKey* mce = dynamic_cast<Botan::McEliece_PrivateKey*>(&key);
      if(!mce)
         return -2;

      const Botan::secure_vector<uint8_t> pt = mceies_decrypt(*mce, ct, ct_len, ad, ad_len, aead);
      return write_vec_output(out, out_len, pt);
#else
      return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
      }
   catch(std::exception& e)
      {
      return ffi_error_exception_thrown(e.what());
      }
   }

int botan_mceies_encrypt(botan_pubkey_t mce_key_obj,
                         botan_rng_t rng_obj,
                         const char* aead,
                         const uint8_t pt[], size_t pt_len,
                         const uint8_t ad[], size_t ad_len,
                         uint8_t out[], size_t* out_len)
   {
   try
      {
      Botan::Public_Key& key = safe_get(mce_key_obj);
      Botan::RandomNumberGenerator& rng = safe_get(rng_obj);

#if defined(BOTAN_HAS_MCELIECE) && defined(BOTAN_HAS_MCEIES)
      Botan::McEliece_PublicKey* mce = dynamic_cast<Botan::McEliece_PublicKey*>(&key);
      if(!mce)
         return -2;

      Botan::secure_vector<uint8_t> ct = mceies_encrypt(*mce, pt, pt_len, ad, ad_len, rng, aead);
      return write_vec_output(out, out_len, ct);
#else
      return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
      }
   catch(std::exception& e)
      {
      return ffi_error_exception_thrown(e.what());
      }
   }

/*
int botan_tls_channel_init_client(botan_tls_channel_t* channel,
                                  botan_tls_channel_output_fn output_fn,
                                  botan_tls_channel_data_cb data_cb,
                                  botan_tls_channel_alert_cb alert_cb,
                                  botan_tls_channel_session_established session_cb,
                                  const char* server_name)
   {

   }
*/

}

