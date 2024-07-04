/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/aead.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/ffi_util.h>
#include <botan/internal/stl_util.h>

#include <limits>

extern "C" {

using namespace Botan_FFI;

struct botan_cipher_struct final : public botan_struct<Botan::Cipher_Mode, 0xB4A2BF9C> {
   public:
      explicit botan_cipher_struct(std::unique_ptr<Botan::Cipher_Mode> x,
                                   size_t update_size,
                                   size_t ideal_update_size) :
            botan_struct(std::move(x)), m_update_size(update_size), m_ideal_update_size(ideal_update_size) {
         BOTAN_DEBUG_ASSERT(ideal_update_size >= update_size);
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

/**
 * Select an update size so that the following constraints are satisfies:
 *
 *   - greater than or equal to the mode's update granularity
 *   - greater than the mode's minimum final size
 *   - the mode's ideal update granularity is a multiple of this size
 *   - (optional) a power of 2
 *
 * Note that this is necessary mostly for backward-compatibility with previous
 * versions of the FFI (prior to Botan 3.5.0). For Botan 4.0.0 we should just
 * directly return the update granularity of the cipher mode and instruct users
 * to switch to botan_cipher_get_ideal_update_granularity() instead. See also
 * the discussion in GitHub Issue #4090.
 */
size_t ffi_choose_update_size(Botan::Cipher_Mode& mode) {
   const size_t update_granularity = mode.update_granularity();
   const size_t ideal_update_granularity = mode.ideal_granularity();
   const size_t minimum_final_size = mode.minimum_final_size();

   // If the minimum final size is zero, or the update_granularity is
   // already greater, just use that.
   if(minimum_final_size == 0 || update_granularity > minimum_final_size) {
      BOTAN_ASSERT_NOMSG(update_granularity > 0);
      return update_granularity;
   }

   // If the ideal granularity is a multiple of the minimum final size, we
   // might be able to use that if it stays within the ideal granularity.
   if(ideal_update_granularity % minimum_final_size == 0 && minimum_final_size * 2 <= ideal_update_granularity) {
      return minimum_final_size * 2;
   }

   // Otherwise, try to use the next power of two greater than the minimum
   // final size, if the ideal granularity is a multiple of that.
   BOTAN_ASSERT_NOMSG(minimum_final_size <= std::numeric_limits<uint16_t>::max());
   const size_t b1 = size_t(1) << Botan::ceil_log2(static_cast<uint16_t>(minimum_final_size));
   if(ideal_update_granularity % b1 == 0) {
      return b1;
   }

   // Last resort: Find the next integer greater than the minimum final size
   //              for which the ideal granularity is a multiple of.
   //              Most sensible cipher modes should never reach this point.
   BOTAN_ASSERT_NOMSG(minimum_final_size < ideal_update_granularity);
   size_t b2 = minimum_final_size + 1;
   for(; b2 < ideal_update_granularity && ideal_update_granularity % b2 != 0; ++b2) {}

   return b2;
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
      const size_t ideal_update_size = std::max(mode->ideal_granularity(), update_size);

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

      // If the cipher object's internal buffer contains residual data from
      // a previous invocation, we can be sure that botan_cipher_update() was
      // called with the final flag set but not enough buffer space was provided
      // to accommodate the final output.
      const bool was_finished_before = !mbuf.empty();
      const bool final_input = (flags & BOTAN_CIPHER_UPDATE_FLAG_FINAL);

      // Bring the output variables into a defined state.
      *output_written = 0;
      *input_consumed = 0;

      // Once the final flag was set once, it must always be set for
      // consecutive invocations.
      if(was_finished_before && !final_input) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }

      // If the final flag was set in a previous invocation, no more input
      // data can be processed.
      if(was_finished_before && input_size > 0) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }

      // Make sure that we always clear the internal buffer before returning
      // or aborting this invocation due to an exception.
      auto clean_buffer = scoped_cleanup([&mbuf] { mbuf.clear(); });

      if(final_input) {
         // If the final flag is set for the first time, we need to process the
         // remaining input data and then finalize the cipher object.
         if(!was_finished_before) {
            *input_consumed = input_size;
            mbuf.resize(input_size);
            copy_mem(mbuf, std::span(input, input_size));

            try {
               cipher.finish(mbuf);
            } catch(Invalid_Authentication_Tag&) {
               return BOTAN_FFI_ERROR_BAD_MAC;
            }
         }

         // At this point, the cipher object is finalized (potentially in a
         // previous invocation) and we can copy the final output to the caller.
         *output_written = mbuf.size();

         // Not enough space to copy the final output out to the caller.
         // Inform them how much space we need for a successful operation.
         if(output_size < mbuf.size()) {
            // This is the only place where mbuf is not cleared before returning.
            clean_buffer.disengage();
            return BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE;
         }

         // Copy the final output to the caller, mbuf is cleared afterwards.
         copy_mem(std::span(output, mbuf.size()), mbuf);
      } else {
         // Process data in a streamed fashion without finalizing. No data is
         // ever retained in the cipher object's internal buffer. If we run out
         // of either input data or output capacity, we stop and report that not
         // all bytes were processed via *output_written and *input_consumed.

         BufferSlicer in({input, input_size});
         BufferStuffer out({output, output_size});

         // Helper function to do blockwise processing of data.
         auto blockwise_update = [&](const size_t granularity) {
            if(granularity == 0) {
               return;
            }

            const size_t expected_output_per_iteration = cipher.requires_entire_message() ? 0 : granularity;
            mbuf.resize(granularity);

            while(in.remaining() >= granularity && out.remaining_capacity() >= expected_output_per_iteration) {
               copy_mem(mbuf, in.take(granularity));
               const auto written_bytes = cipher.process(mbuf);
               BOTAN_DEBUG_ASSERT(written_bytes == expected_output_per_iteration);
               if(written_bytes > 0) {
                  BOTAN_ASSERT_NOMSG(written_bytes <= granularity);
                  copy_mem(out.next(written_bytes), std::span(mbuf).first(written_bytes));
               }
            }
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

         // Inform the caller about the amount of data processed.
         *output_written = output_size - out.remaining_capacity();
         *input_consumed = input_size - in.remaining();
      }

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

int botan_cipher_requires_entire_message(botan_cipher_t cipher) {
   return BOTAN_FFI_VISIT(cipher, [=](const auto& c) { return c.requires_entire_message() ? 1 : 0; });
}

int botan_cipher_name(botan_cipher_t cipher, char* name, size_t* name_len) {
   return BOTAN_FFI_VISIT(cipher, [=](const auto& c) { return write_str_output(name, name_len, c.name()); });
}
}
