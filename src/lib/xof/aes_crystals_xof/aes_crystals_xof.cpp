/*
 * XOF based on AES-256/CTR for CRYSTALS Kyber/Dilithium 90s-modes
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/aes_crystals_xof.h>

#include <botan/exceptn.h>
#include <botan/stream_cipher.h>
#include <botan/internal/fmt.h>

namespace Botan {

AES_256_CTR_XOF::AES_256_CTR_XOF() : m_stream_cipher(StreamCipher::create_or_throw(name())) {}

AES_256_CTR_XOF::~AES_256_CTR_XOF() = default;

void AES_256_CTR_XOF::reset() {
   m_stream_cipher->clear();
}

void AES_256_CTR_XOF::start_msg(std::span<const uint8_t> iv, std::span<const uint8_t> key) {
   m_stream_cipher->set_key(key);
   m_stream_cipher->set_iv(iv);
}

bool AES_256_CTR_XOF::valid_salt_length(size_t iv_length) const {
   return m_stream_cipher->valid_iv_length(iv_length);
}

Key_Length_Specification AES_256_CTR_XOF::key_spec() const {
   return m_stream_cipher->key_spec();
}

std::unique_ptr<XOF> AES_256_CTR_XOF::copy_state() const {
   throw Not_Implemented(fmt("Copying the state of XOF {} is not implemented", name()));
}

void AES_256_CTR_XOF::add_data(std::span<const uint8_t> input) {
   if(!input.empty()) {
      throw Not_Implemented(fmt("XOF {} does not support data input", name()));
   }
}

void AES_256_CTR_XOF::generate_bytes(std::span<uint8_t> output) {
   m_stream_cipher->write_keystream(output);
}

}  // namespace Botan
