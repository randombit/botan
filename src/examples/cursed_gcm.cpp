
#include <botan/aead.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>

namespace CursedBotan {

using namespace Botan;

class Cursed_GCM_Mode : public AEAD_Mode
   {
   public:
      void set_associated_data_n(size_t idx, std::span<const uint8_t> ad) override final;

      std::string name() const override final;

      size_t update_granularity() const override final;

      size_t ideal_granularity() const override final;

      Key_Length_Specification key_spec() const override final;

      bool valid_nonce_length(size_t len) const override final;

      size_t tag_size() const override final { return 0; }

      void clear() override final;

      void reset() override final;

      std::string provider() const override final;

      bool has_keying_material() const override final;
   protected:
      Cursed_GCM_Mode(const std::string& cipher_name);

      ~Cursed_GCM_Mode();

      static const size_t GCM_BS = 16;

      const std::string m_cipher_name;

      std::unique_ptr<StreamCipher> m_ctr;
   private:
      void start_msg(const uint8_t nonce[], size_t nonce_len) override;

      void key_schedule(const uint8_t key[], size_t length) override;
   };

class Cursed_GCM_Encryption final : public Cursed_GCM_Mode
   {
   public:
      Cursed_GCM_Encryption(const std::string& cipher_name) :
         Cursed_GCM_Mode(cipher_name) {}

      size_t output_length(size_t input_length) const override
         { return input_length + tag_size(); }

      size_t minimum_final_size() const override { return 0; }

   private:
      size_t process_msg(uint8_t buf[], size_t size) override;
      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
   };

class Cursed_GCM_Decryption final : public Cursed_GCM_Mode
   {
   public:
      Cursed_GCM_Decryption(const std::string& cipher_name) :
         Cursed_GCM_Mode(cipher_name) {}

      size_t output_length(size_t input_length) const override
         {
         BOTAN_ARG_CHECK(input_length >= tag_size(), "Sufficient input");
         return input_length - tag_size();
         }

      size_t minimum_final_size() const override { return tag_size(); }

   private:
      size_t process_msg(uint8_t buf[], size_t size) override;
      void finish_msg(secure_vector<uint8_t>& final_block, size_t offset = 0) override;
   };

Cursed_GCM_Mode::Cursed_GCM_Mode(const std::string& cipher_name) :
   m_cipher_name(cipher_name)
   {
   // This is missing the check that the block cipher is 128 bits
   // but for this purposes it doesn't really matter, you're already
   // cursed.

   m_ctr = StreamCipher::create_or_throw("CTR-BE(" + m_cipher_name + ",4)");
   }

Cursed_GCM_Mode::~Cursed_GCM_Mode() = default;

void Cursed_GCM_Mode::clear()
   {
   m_ctr->clear();
   reset();
   }

void Cursed_GCM_Mode::reset()
   {
   }

std::string Cursed_GCM_Mode::name() const
   {
   return "Cursed_GCM/" + m_cipher_name;
   }

std::string Cursed_GCM_Mode::provider() const
   {
   return "base";
   }

size_t Cursed_GCM_Mode::update_granularity() const
   {
   return GCM_BS;
   }

size_t Cursed_GCM_Mode::ideal_granularity() const
   {
   return GCM_BS * std::max<size_t>(2, BOTAN_BLOCK_CIPHER_PAR_MULT);
   }

bool Cursed_GCM_Mode::valid_nonce_length(size_t len) const
   {
   // GCM does not support empty nonces
   return (len > 0);
   }

Key_Length_Specification Cursed_GCM_Mode::key_spec() const
   {
   return m_ctr->key_spec();
   }

bool Cursed_GCM_Mode::has_keying_material() const
   {
   return m_ctr->has_keying_material();
   }

void Cursed_GCM_Mode::key_schedule(const uint8_t key[], size_t keylen)
   {
   m_ctr->set_key(key, keylen);

   const std::vector<uint8_t> zeros(GCM_BS);
   m_ctr->set_iv(zeros.data(), zeros.size());

   secure_vector<uint8_t> H(GCM_BS);
   m_ctr->encipher(H);
   // throw away the GHASH key
   }

void Cursed_GCM_Mode::set_associated_data_n(size_t idx, std::span<const uint8_t> ad)
   {
   BOTAN_ARG_CHECK(idx == 0, "GCM: cannot handle non-zero index in set_associated_data_n");

   // The associated data would be included in the tag, which we don't emit.
   // Instead we just ignore it.
   BOTAN_UNUSED(ad);
   }

void Cursed_GCM_Mode::start_msg(const uint8_t nonce[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   std::vector<uint8_t> y0(GCM_BS);

   if(nonce_len == 12)
      {
      copy_mem(y0.data(), nonce, nonce_len);
      y0[15] = 1;
      }
   else
      {
      throw Not_Implemented("CursedGCM requires 96 bit nonce");
      //m_ghash->nonce_hash(m_y0, nonce, nonce_len);
      }

   m_ctr->set_iv(y0.data(), y0.size());

   clear_mem(y0.data(), y0.size());
   m_ctr->encipher(y0); // thrown away
   }

size_t Cursed_GCM_Encryption::process_msg(uint8_t buf[], size_t sz)
   {
   BOTAN_ARG_CHECK(sz % update_granularity() == 0, "Invalid buffer size");
   m_ctr->cipher(buf, buf, sz);
   return sz;
   }

void Cursed_GCM_Encryption::finish_msg(secure_vector<uint8_t>& buffer, size_t offset)
   {
   BOTAN_ARG_CHECK(offset <= buffer.size(), "Invalid offset");
   const size_t sz = buffer.size() - offset;
   uint8_t* buf = buffer.data() + offset;

   m_ctr->cipher(buf, buf, sz);
   }

size_t Cursed_GCM_Decryption::process_msg(uint8_t buf[], size_t sz)
   {
   BOTAN_ARG_CHECK(sz % update_granularity() == 0, "Invalid buffer size");
   m_ctr->cipher(buf, buf, sz);
   return sz;
   }

void Cursed_GCM_Decryption::finish_msg(secure_vector<uint8_t>& buffer, size_t offset)
   {
   BOTAN_ARG_CHECK(offset <= buffer.size(), "Invalid offset");
   const size_t sz = buffer.size() - offset;
   uint8_t* buf = buffer.data() + offset;

   BOTAN_ARG_CHECK(sz >= tag_size(), "input did not include the tag");

   const size_t remaining = sz - tag_size();

   // handle any final input before the tag
   if(remaining)
      {
      m_ctr->cipher(buf, buf, remaining);
      }

   // No mac to check!!!
   return;
   }

}

#include <botan/system_rng.h>
#include <botan/hex.h>
#include <iostream>

int main()
   {
   using namespace Botan;
   using namespace CursedBotan;

   uint8_t key[32];
   Botan::system_rng().randomize(key, sizeof(key));

   uint8_t nonce[12];
   Botan::system_rng().randomize(nonce, sizeof(nonce));

   std::unique_ptr<Cipher_Mode> cursed_enc = std::make_unique<Cursed_GCM_Encryption>("AES-256");
   std::unique_ptr<Cipher_Mode> cursed_dec = std::make_unique<Cursed_GCM_Decryption>("AES-256");

   auto normal_enc = AEAD_Mode::create("AES-256/GCM", Cipher_Dir::Encryption);
   auto normal_dec = AEAD_Mode::create("AES-256/GCM", Cipher_Dir::Decryption);

   cursed_enc->set_key(key, sizeof(key));
   cursed_dec->set_key(key, sizeof(key));

   normal_enc->set_key(key, sizeof(key));
   normal_dec->set_key(key, sizeof(key));

   cursed_enc->start(nonce, sizeof(nonce));
   cursed_dec->start(nonce, sizeof(nonce));
   normal_enc->start(nonce, sizeof(nonce));
   normal_dec->start(nonce, sizeof(nonce));

   std::vector<uint8_t> plaintext(33);
   Botan::system_rng().randomize(plaintext.data(), plaintext.size());

   std::cout << "Init   PT: " << hex_encode(plaintext) << "\n";

   secure_vector<uint8_t> cursed_ct(plaintext.begin(), plaintext.end());
   cursed_enc->finish(cursed_ct);

   std::cout << "Cursed CT: " << hex_encode(cursed_ct) << "\n";

   secure_vector<uint8_t> normal_ct(plaintext.begin(), plaintext.end());
   normal_enc->finish(normal_ct);

   std::cout << "Normal CT: " << hex_encode(normal_ct) << "\n";

   cursed_dec->finish(cursed_ct);
   std::cout << "Cursed PT: " << hex_encode(cursed_ct) << "\n";

   }
