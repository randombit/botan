/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/internal/ffi_util.h>
#include <botan/aead.h>

extern "C" {

using namespace Botan_FFI;

struct botan_cipher_struct final : public botan_struct<Botan::Cipher_Mode, 0xB4A2BF9C>
   {
   explicit botan_cipher_struct(Botan::Cipher_Mode* x) : botan_struct(x) {}
   Botan::secure_vector<uint8_t> m_buf;
   };

int botan_cipher_init(botan_cipher_t* cipher, const char* cipher_name, uint32_t flags)
   {
   return ffi_guard_thunk(__func__, [=]() -> int {
      const bool encrypt_p = ((flags & BOTAN_CIPHER_INIT_FLAG_MASK_DIRECTION) == BOTAN_CIPHER_INIT_FLAG_ENCRYPT);
      const Botan::Cipher_Dir dir = encrypt_p ? Botan::ENCRYPTION : Botan::DECRYPTION;
      std::unique_ptr<Botan::Cipher_Mode> mode(Botan::Cipher_Mode::create(cipher_name, dir));
      if(!mode)
         return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
      *cipher = new botan_cipher_struct(mode.release());
      return BOTAN_FFI_SUCCESS;
      });
   }

int botan_cipher_destroy(botan_cipher_t cipher)
   {
   return BOTAN_FFI_CHECKED_DELETE(cipher);
   }

int botan_cipher_clear(botan_cipher_t cipher)
   {
   return BOTAN_FFI_DO(Botan::Cipher_Mode, cipher, c, { c.clear(); });
   }

int botan_cipher_reset(botan_cipher_t cipher)
   {
   return BOTAN_FFI_DO(Botan::Cipher_Mode, cipher, c, { c.reset(); });
   }

int botan_cipher_output_length(botan_cipher_t cipher, size_t in_len, size_t* out_len)
   {
   if(out_len == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

   return BOTAN_FFI_DO(Botan::Cipher_Mode, cipher, c, { *out_len = c.output_length(in_len); });
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

int botan_cipher_get_keyspec(botan_cipher_t cipher,
                             size_t* out_minimum_keylength,
                             size_t* out_maximum_keylength,
                             size_t* out_keylength_modulo)
   {
   return BOTAN_FFI_DO(Botan::Cipher_Mode, cipher, c, {
      if(out_minimum_keylength)
         *out_minimum_keylength = c.key_spec().minimum_keylength();
      if(out_maximum_keylength)
         *out_maximum_keylength = c.key_spec().maximum_keylength();
      if(out_keylength_modulo)
         *out_keylength_modulo = c.key_spec().keylength_multiple();
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
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::Cipher_Mode& cipher = safe_get(cipher_obj);
      cipher.start(nonce, nonce_len);
      cipher_obj->m_buf.reserve(cipher.update_granularity());
      return BOTAN_FFI_SUCCESS;
      });
   }

int botan_cipher_update(botan_cipher_t cipher_obj,
                        uint32_t flags,
                        uint8_t output_ptr[],
                        size_t orig_output_size,
                        size_t* output_written,
                        const uint8_t input_ptr[],
                        size_t orig_input_size,
                        size_t* input_consumed)
   {
   return ffi_guard_thunk(__func__, [=]() -> int {

      size_t input_size = orig_input_size;
      size_t output_size = orig_output_size;
      const uint8_t* input = input_ptr;
      uint8_t* output = output_ptr;

      using namespace Botan;
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
         catch(Invalid_Authentication_Tag&)
            {
            return BOTAN_FFI_ERROR_BAD_MAC;
            }

         *output_written = mbuf.size();

         if(mbuf.size() <= output_size)
            {
            copy_mem(output, mbuf.data(), mbuf.size());
            mbuf.clear();
            return BOTAN_FFI_SUCCESS;
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
            return BOTAN_FFI_SUCCESS;
            }

         return -1;
         }

      const size_t ud = cipher.update_granularity();
      BOTAN_ASSERT(cipher.update_granularity() > cipher.minimum_final_size(), "logic error");

      mbuf.resize(ud);
      size_t taken = 0, written = 0;

      while(input_size >= ud && output_size >= ud)
         {
         // FIXME we can use process here and avoid the copy
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

      return BOTAN_FFI_SUCCESS;
      });
   }

int botan_cipher_set_associated_data(botan_cipher_t cipher,
                                     const uint8_t* ad,
                                     size_t ad_len)
   {
   return BOTAN_FFI_RETURNING(Botan::Cipher_Mode, cipher, c, {
      if(Botan::AEAD_Mode* aead = dynamic_cast<Botan::AEAD_Mode*>(&c))
         {
         aead->set_associated_data(ad, ad_len);
         return BOTAN_FFI_SUCCESS;
         }
      return BOTAN_FFI_ERROR_BAD_PARAMETER;
      });
   }

int botan_cipher_valid_nonce_length(botan_cipher_t cipher, size_t nl)
   {
   return BOTAN_FFI_RETURNING(Botan::Cipher_Mode, cipher, c, {
      return c.valid_nonce_length(nl) ? 1 : 0;
      });
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

int botan_cipher_name(botan_cipher_t cipher, char* name, size_t* name_len)
   {
   return BOTAN_FFI_DO(Botan::Cipher_Mode, cipher, c, {
      return write_str_output(name, name_len, c.name()); });
   }

}
