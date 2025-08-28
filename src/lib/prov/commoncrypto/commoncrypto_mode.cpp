/*
* Cipher Modes via CommonCrypto
* (C) 2018 Jose Pereira
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/commoncrypto.h>

#include <botan/block_cipher.h>
#include <botan/cipher_mode.h>
#include <botan/mem_ops.h>
#include <botan/internal/commoncrypto_utils.h>
#include <botan/internal/rounding.h>

#include <limits.h>

namespace Botan {

namespace {

class CommonCrypto_Cipher_Mode final : public Cipher_Mode {
   public:
      CommonCrypto_Cipher_Mode(std::string_view name, Cipher_Dir direction, const CommonCryptor_Opts& opts);

      ~CommonCrypto_Cipher_Mode();

      std::string provider() const override { return "commoncrypto"; }

      std::string name() const override { return m_mode_name; }

      size_t output_length(size_t input_length) const override;
      size_t update_granularity() const override;
      size_t ideal_granularity() const override;
      size_t minimum_final_size() const override;
      size_t bytes_needed_for_finalization(size_t final_input_length) const override;
      size_t default_nonce_length() const override;
      bool valid_nonce_length(size_t nonce_len) const override;
      void clear() override;
      void reset() override;
      Key_Length_Specification key_spec() const override;

      bool has_keying_material() const override { return m_key_set; }

   private:
      void key_schedule(std::span<const uint8_t> key) override;

      void start_msg(const uint8_t nonce[], size_t nonce_len) override;
      size_t process_msg(uint8_t msg[], size_t msg_len) override;
      size_t finish_msg(std::span<uint8_t> final_block, size_t input_bytes) override;

      const std::string m_mode_name;
      Cipher_Dir m_direction;
      CommonCryptor_Opts m_opts;
      CCCryptorRef m_cipher = nullptr;
      bool m_key_set;
      bool m_nonce_set;
};

CommonCrypto_Cipher_Mode::CommonCrypto_Cipher_Mode(std::string_view name,
                                                   Cipher_Dir direction,
                                                   const CommonCryptor_Opts& opts) :
      m_mode_name(name), m_direction(direction), m_opts(opts), m_key_set(false), m_nonce_set(false) {}

CommonCrypto_Cipher_Mode::~CommonCrypto_Cipher_Mode() {
   if(m_cipher) {
      CCCryptorRelease(m_cipher);
   }
}

void CommonCrypto_Cipher_Mode::start_msg(const uint8_t nonce[], size_t nonce_len) {
   if(!valid_nonce_length(nonce_len)) {
      throw Invalid_IV_Length(name(), nonce_len);
   }

   assert_key_material_set();

   if(nonce_len) {
      CCCryptorStatus status = CCCryptorReset(m_cipher, nonce);
      if(status != kCCSuccess) {
         throw CommonCrypto_Error("CCCryptorReset on start_msg", status);
      }
   }
   m_nonce_set = true;
}

size_t CommonCrypto_Cipher_Mode::process_msg(uint8_t msg[], size_t msg_len) {
   assert_key_material_set();
   BOTAN_STATE_CHECK(m_nonce_set);

   if(msg_len == 0) {
      return 0;
   }
   if(msg_len > INT_MAX) {
      throw Internal_Error("msg_len overflow");
   }
   size_t outl = CCCryptorGetOutputLength(m_cipher, msg_len, false);

   secure_vector<uint8_t> out(outl);

   if(m_opts.padding == ccNoPadding && msg_len % m_opts.block_size) {
      msg_len = outl;
   }

   CCCryptorStatus status = CCCryptorUpdate(m_cipher, msg, msg_len, out.data(), outl, &outl);
   if(status != kCCSuccess) {
      throw CommonCrypto_Error("CCCryptorUpdate", status);
   }
   copy_mem(msg, out.data(), outl);

   return outl;
}

size_t CommonCrypto_Cipher_Mode::finish_msg(std::span<uint8_t> buffer, size_t input_bytes) {
   assert_key_material_set();
   BOTAN_STATE_CHECK(m_nonce_set);

   BOTAN_ASSERT_NOMSG(buffer.size() >= input_bytes);

   const auto remaining_payload = buffer.first(input_bytes);
   const size_t written_in_last_process = process(remaining_payload);

   BOTAN_ASSERT_NOMSG(written_in_last_process <= buffer.size());
   const auto final_out = buffer.subspan(written_in_last_process);

   const size_t output_space_required = CCCryptorGetOutputLength(m_cipher, final_out.size(), true);
   if(output_space_required < final_out.size()) {
      throw Internal_Error("Insufficient space in buffer for finalization");
   }

   size_t written_in_finalization = 0;
   CCCryptorStatus status = CCCryptorFinal(m_cipher, final_out.data(), final_out.size(), &written_in_finalization);
   if(status != kCCSuccess) {
      throw CommonCrypto_Error("CCCryptorFinal", status);
   }

   const size_t output_bytes = written_in_last_process + written_in_finalization;
   BOTAN_ASSERT_NOMSG(output_bytes <= buffer.size());

   return output_bytes;
}

size_t CommonCrypto_Cipher_Mode::update_granularity() const {
   return m_opts.block_size;
}

size_t CommonCrypto_Cipher_Mode::ideal_granularity() const {
   return m_opts.block_size * BlockCipher::ParallelismMult;
}

size_t CommonCrypto_Cipher_Mode::minimum_final_size() const {
   if(m_direction == Cipher_Dir::Encryption)
      return 0;
   else
      return m_opts.block_size;
}

size_t CommonCrypto_Cipher_Mode::bytes_needed_for_finalization(size_t final_input_length) const {
   assert_key_material_set();
   BOTAN_ARG_CHECK(final_input_length >= minimum_final_size(), "Sufficient input");
   const auto expected_output_length = CCCryptorGetOutputLength(m_cipher, final_input_length, true);

   // Ensure that the finalization sees all input bytes or is large enough to
   // hold the expected encryption overhead.
   return std::max(expected_output_length, final_input_length);
}

size_t CommonCrypto_Cipher_Mode::default_nonce_length() const {
   return m_opts.block_size;
}

bool CommonCrypto_Cipher_Mode::valid_nonce_length(size_t nonce_len) const {
   return (nonce_len == 0 || nonce_len == m_opts.block_size);
}

size_t CommonCrypto_Cipher_Mode::output_length(size_t input_length) const {
   if(input_length == 0) {
      return m_opts.block_size;
   } else {
      return round_up(input_length, m_opts.block_size);
   }
}

void CommonCrypto_Cipher_Mode::clear() {
   m_key_set = false;

   if(m_cipher == nullptr) {
      return;
   }

   if(m_cipher) {
      CCCryptorRelease(m_cipher);
      m_cipher = nullptr;
   }
}

void CommonCrypto_Cipher_Mode::reset() {
   if(m_cipher == nullptr) {
      return;
   }

   m_nonce_set = false;

   CCCryptorStatus status = CCCryptorReset(m_cipher, nullptr);
   if(status != kCCSuccess) {
      throw CommonCrypto_Error("CCCryptorReset", status);
   }
}

Key_Length_Specification CommonCrypto_Cipher_Mode::key_spec() const {
   return m_opts.key_spec;
}

void CommonCrypto_Cipher_Mode::key_schedule(std::span<const uint8_t> key) {
   CCCryptorStatus status;
   CCOperation op = m_direction == Cipher_Dir::Encryption ? kCCEncrypt : kCCDecrypt;
   status = CCCryptorCreateWithMode(
      op, m_opts.mode, m_opts.algo, m_opts.padding, nullptr, key.data(), key.size(), nullptr, 0, 0, 0, &m_cipher);
   if(status != kCCSuccess) {
      throw CommonCrypto_Error("CCCryptorCreate", status);
   }

   m_key_set = true;
   m_nonce_set = false;
}
}  // namespace

std::unique_ptr<Cipher_Mode> make_commoncrypto_cipher_mode(std::string_view name, Cipher_Dir direction) {
   try {
      CommonCryptor_Opts opts = commoncrypto_opts_from_algo(name);
      return std::make_unique<CommonCrypto_Cipher_Mode>(name, direction, opts);
   } catch(CommonCrypto_Error& e) {
      return nullptr;
   }
}
}  // namespace Botan
