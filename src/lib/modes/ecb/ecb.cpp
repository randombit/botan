/*
* ECB Mode
* (C) 1999-2009,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/mode_utils.h>
#include <botan/ecb.h>

namespace Botan {

template<typename T>
Transform* make_ecb_mode(const Transform::Spec& spec)
   {
   std::unique_ptr<BlockCipher> bc(get_block_cipher(spec.arg(0)));
   std::unique_ptr<BlockCipherModePaddingMethod> pad(get_bc_pad(spec.arg(1, "NoPadding")));
   if(bc && pad)
      return new T(bc.release(), pad.release());
   return nullptr;
   }

BOTAN_REGISTER_TRANSFORM(ECB_Encryption, make_ecb_mode<ECB_Encryption>);
BOTAN_REGISTER_TRANSFORM(ECB_Decryption, make_ecb_mode<ECB_Decryption>);

ECB_Mode::ECB_Mode(BlockCipher* cipher, BlockCipherModePaddingMethod* padding) :
   m_cipher(cipher),
   m_padding(padding)
   {
   if(!m_padding->valid_blocksize(cipher->block_size()))
      throw std::invalid_argument("Padding " + m_padding->name() +
                                  " cannot be used with " +
                                  cipher->name() + "/ECB");
   }

void ECB_Mode::clear()
   {
   m_cipher->clear();
   }

std::string ECB_Mode::name() const
   {
   return cipher().name() + "/ECB/" + padding().name();
   }

size_t ECB_Mode::update_granularity() const
   {
   return cipher().parallel_bytes();
   }

Key_Length_Specification ECB_Mode::key_spec() const
   {
   return cipher().key_spec();
   }

size_t ECB_Mode::default_nonce_length() const
   {
   return 0;
   }

bool ECB_Mode::valid_nonce_length(size_t n) const
   {
   return (n == 0);
   }

void ECB_Mode::key_schedule(const byte key[], size_t length)
   {
   m_cipher->set_key(key, length);
   }

secure_vector<byte> ECB_Mode::start_raw(const byte[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   return secure_vector<byte>();
   }

size_t ECB_Encryption::minimum_final_size() const
   {
   return 0;
   }

size_t ECB_Encryption::output_length(size_t input_length) const
   {
   return round_up(input_length, cipher().block_size());
   }

void ECB_Encryption::update(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = buffer.data() + offset;

   const size_t BS = cipher().block_size();

   BOTAN_ASSERT(sz % BS == 0, "ECB input is full blocks");
   const size_t blocks = sz / BS;

   cipher().encrypt_n(buf, buf, blocks);
   }

void ECB_Encryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;

   const size_t BS = cipher().block_size();

   const size_t bytes_in_final_block = sz % BS;

   padding().add_padding(buffer, bytes_in_final_block, BS);

   if(buffer.size() % BS)
      throw std::runtime_error("Did not pad to full block size in " + name());

   update(buffer, offset);
   }

size_t ECB_Decryption::output_length(size_t input_length) const
   {
   return input_length;
   }

size_t ECB_Decryption::minimum_final_size() const
   {
   return cipher().block_size();
   }

void ECB_Decryption::update(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = buffer.data() + offset;

   const size_t BS = cipher().block_size();

   BOTAN_ASSERT(sz % BS == 0, "Input is full blocks");
   size_t blocks = sz / BS;

   cipher().decrypt_n(buf, buf, blocks);
   }

void ECB_Decryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;

   const size_t BS = cipher().block_size();

   if(sz == 0 || sz % BS)
      throw Decoding_Error(name() + ": Ciphertext not a multiple of block size");

   update(buffer, offset);

   const size_t pad_bytes = BS - padding().unpad(&buffer[buffer.size()-BS], BS);
   buffer.resize(buffer.size() - pad_bytes); // remove padding
   }

}
