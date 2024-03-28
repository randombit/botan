/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/aead.h>
#include <botan/internal/ffi_util.h>
#include <botan/internal/stl_util.h>

extern "C" {

using namespace Botan_FFI;

struct botan_cipher_struct final : public botan_struct<Botan::Cipher_Mode, 0xB4A2BF9C> {
   public:
      explicit botan_cipher_struct(std::unique_ptr<Botan::Cipher_Mode> x,
                                   size_t update_size,
                                   size_t ideal_update_size) :
            botan_struct(std::move(x)), m_update_size(update_size), m_ideal_update_size(ideal_update_size) {
         BOTAN_DEBUG_ASSERT(ideal_update_size >= update_size);
         BOTAN_DEBUG_ASSERT(ideal_update_size % update_size == 0);
         m_buf.reserve(m_ideal_update_size);
      }

      Botan::secure_vector<uint8_t>& buf() { return m_buf; }

      size_t update_size() const { return m_update_size; }

      size_t ideal_update_size() const { return m_ideal_update_size; }

   private:
      Botan::secure_vector<uint8_t> m_buf;
      size_t m_update_size;
      size_t m_ideal_update_size;
};

namespace {

size_t ffi_choose_update_size(Botan::Cipher_Mode& mode) {
   const size_t update_granularity = mode.update_granularity();
   const size_t minimum_final_size = mode.minimum_final_size();

   /*
   * Return the minimum possible granularity given the FFI API constraints that
   * we require the returned size be > minimum final size.
   *
   * If the minimum final size is zero, or the update_granularity is
   * already greater, just use that.
   *
   * Otherwise scale the update_granularity to a sufficient size
   * to be greater than the minimum.
   */
   if(minimum_final_size == 0 || update_granularity > minimum_final_size) {
      BOTAN_ASSERT_NOMSG(update_granularity > 0);
      return update_granularity;
   }

   size_t buf_size = std::max(update_granularity, minimum_final_size + 1);
   if(buf_size % update_granularity != 0) {
      buf_size += update_granularity - (buf_size % update_granularity);
   }

   return buf_size;
}

}  // namespace

int botan_cipher_init(botan_cipher_t* cipher, const char* cipher_name, uint32_t flags) {
   return ffi_guard_thunk(__func__, [=]() -> int {
      const bool encrypt_p = ((flags & BOTAN_CIPHER_INIT_FLAG_MASK_DIRECTION) == BOTAN_CIPHER_INIT_FLAG_ENCRYPT);
      const Botan::Cipher_Dir dir = encrypt_p ? Botan::Cipher_Dir::Encryption : Botan::Cipher_Dir::Decryption;

      std::unique_ptr<Botan::Cipher_Mode> mode(Botan::Cipher_Mode::create(cipher_name, dir));
      if(!mode) {
         return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
      }

      const size_t update_size = ffi_choose_update_size(*mode);
      const size_t ideal_update_size = mode->ideal_granularity();

      *cipher = new botan_cipher_struct(std::move(mode), update_size, ideal_update_size);
      return BOTAN_FFI_SUCCESS;
   });
}

int botan_cipher_destroy(botan_cipher_t cipher) {
   return BOTAN_FFI_CHECKED_DELETE(cipher);
}

int botan_cipher_clear(botan_cipher_t cipher) {
   return BOTAN_FFI_VISIT(cipher, [](auto& c) { c.clear(); });
}

int botan_cipher_reset(botan_cipher_t cipher) {
   return BOTAN_FFI_VISIT(cipher, [](auto& c) { c.reset(); });
}

int botan_cipher_output_length(botan_cipher_t cipher, size_t in_len, size_t* out_len) {
   if(out_len == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(cipher, [=](const auto& c) { *out_len = c.output_length(in_len); });
}

int botan_cipher_query_keylen(botan_cipher_t cipher, size_t* out_minimum_keylength, size_t* out_maximum_keylength) {
   return BOTAN_FFI_VISIT(cipher, [=](const auto& c) {
      *out_minimum_keylength = c.key_spec().minimum_keylength();
      *out_maximum_keylength = c.key_spec().maximum_keylength();
   });
}

int botan_cipher_get_keyspec(botan_cipher_t cipher,
                             size_t* out_minimum_keylength,
                             size_t* out_maximum_keylength,
                             size_t* out_keylength_modulo) {
   return BOTAN_FFI_VISIT(cipher, [=](const auto& c) {
      if(out_minimum_keylength)
         *out_minimum_keylength = c.key_spec().minimum_keylength();
      if(out_maximum_keylength)
         *out_maximum_keylength = c.key_spec().maximum_keylength();
      if(out_keylength_modulo)
         *out_keylength_modulo = c.key_spec().keylength_multiple();
   });
}

int botan_cipher_set_key(botan_cipher_t cipher, const uint8_t* key, size_t key_len) {
   return BOTAN_FFI_VISIT(cipher, [=](auto& c) { c.set_key(key, key_len); });
}

int botan_cipher_start(botan_cipher_t cipher_obj, const uint8_t* nonce, size_t nonce_len) {
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::Cipher_Mode& cipher = safe_get(cipher_obj);
      cipher.start(nonce, nonce_len);
      return BOTAN_FFI_SUCCESS;
   });
}

int botan_cipher_update(botan_cipher_t cipher_obj,
                        uint32_t flags,
                        uint8_t output[],
                        size_t output_size,
                        size_t* output_written,
                        const uint8_t input[],
                        size_t input_size,
                        size_t* input_consumed) {
   return ffi_guard_thunk(__func__, [=]() -> int {
      using namespace Botan;
      Cipher_Mode& cipher = safe_get(cipher_obj);
      secure_vector<uint8_t>& mbuf = cipher_obj->buf();

      const bool final_input = (flags & BOTAN_CIPHER_UPDATE_FLAG_FINAL);

      if(final_input) {
         mbuf.assign(input, input + input_size);
         *input_consumed = input_size;
         *output_written = 0;

         try {
            cipher.finish(mbuf);
         } catch(Invalid_Authentication_Tag&) {
            return BOTAN_FFI_ERROR_BAD_MAC;
         }

         *output_written = mbuf.size();

         if(mbuf.size() <= output_size) {
            copy_mem(output, mbuf.data(), mbuf.size());
            mbuf.clear();
            return BOTAN_FFI_SUCCESS;
         }

         return -1;
      }

      if(input_size == 0) {
         return -1;
      }

      BufferSlicer in({input, input_size});
      BufferStuffer out({output, output_size});

      auto blockwise_update = [&](const size_t granularity) {
         mbuf.resize(granularity);

         while(in.remaining() >= granularity && out.remaining_capacity() >= granularity) {
            copy_mem(mbuf, in.take(granularity));
            const auto written_bytes = cipher.process(mbuf);
            BOTAN_ASSERT_NOMSG(written_bytes <= granularity);
            copy_mem(out.next(written_bytes), std::span(mbuf).first(written_bytes));
         }

         mbuf.clear();
      };

      // First, process as much data as possible in chunks of ideal granularity
      blockwise_update(cipher_obj->ideal_update_size());

      // Then process the remaining bytes in chunks of update_size() or, in one go
      // if update_size() is equal to 1 --> i.e. likely a stream cipher.
      const bool is_stream_cipher = (cipher_obj->update_size() == 1);
      const size_t tail_granularity =
         is_stream_cipher ? std::min(in.remaining(), out.remaining_capacity()) : cipher_obj->update_size();
      BOTAN_DEBUG_ASSERT(tail_granularity < cipher_obj->ideal_update_size());
      blockwise_update(tail_granularity);

      *output_written = output_size - out.remaining_capacity();
      *input_consumed = input_size - in.remaining();

      return BOTAN_FFI_SUCCESS;
   });
}

int botan_cipher_set_associated_data(botan_cipher_t cipher, const uint8_t* ad, size_t ad_len) {
   return BOTAN_FFI_VISIT(cipher, [=](auto& c) {
      if(Botan::AEAD_Mode* aead = dynamic_cast<Botan::AEAD_Mode*>(&c)) {
         aead->set_associated_data(ad, ad_len);
         return BOTAN_FFI_SUCCESS;
      }
      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   });
}

int botan_cipher_valid_nonce_length(botan_cipher_t cipher, size_t nl) {
   return BOTAN_FFI_VISIT(cipher, [=](const auto& c) { return c.valid_nonce_length(nl) ? 1 : 0; });
}

int botan_cipher_get_default_nonce_length(botan_cipher_t cipher, size_t* nl) {
   return BOTAN_FFI_VISIT(cipher, [=](const auto& c) { *nl = c.default_nonce_length(); });
}

int botan_cipher_get_update_granularity(botan_cipher_t cipher, size_t* ug) {
   return BOTAN_FFI_VISIT(cipher, [=](const auto& /*c*/) { *ug = cipher->update_size(); });
}

int botan_cipher_get_ideal_update_granularity(botan_cipher_t cipher, size_t* ug) {
   return BOTAN_FFI_VISIT(cipher, [=](const auto& c) { *ug = c.ideal_granularity(); });
}

int botan_cipher_get_tag_length(botan_cipher_t cipher, size_t* tl) {
   return BOTAN_FFI_VISIT(cipher, [=](const auto& c) { *tl = c.tag_size(); });
}

int botan_cipher_is_authenticated(botan_cipher_t cipher) {
   return BOTAN_FFI_VISIT(cipher, [=](const auto& c) { return c.authenticated() ? 1 : 0; });
}

int botan_cipher_name(botan_cipher_t cipher, char* name, size_t* name_len) {
   return BOTAN_FFI_VISIT(cipher, [=](const auto& c) { return write_str_output(name, name_len, c.name()); });
}
}
