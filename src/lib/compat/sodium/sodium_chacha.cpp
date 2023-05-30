/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sodium.h>

#include <botan/stream_cipher.h>

namespace Botan {

int Sodium::crypto_stream_chacha20(uint8_t out[], size_t out_len, const uint8_t nonce[], const uint8_t key[]) {
   auto chacha = StreamCipher::create_or_throw("ChaCha(20)");
   chacha->set_key(key, crypto_stream_chacha20_KEYBYTES);
   chacha->set_iv(nonce, crypto_stream_chacha20_NONCEBYTES);
   chacha->write_keystream(out, out_len);
   return 0;
}

int Sodium::crypto_stream_chacha20_xor(
   uint8_t out[], const uint8_t in[], size_t in_len, const uint8_t nonce[], const uint8_t key[]) {
   return crypto_stream_chacha20_xor_ic(out, in, in_len, nonce, 0, key);
}

int Sodium::crypto_stream_chacha20_xor_ic(
   uint8_t out[], const uint8_t in[], size_t in_len, const uint8_t nonce[], uint64_t ic, const uint8_t key[]) {
   if((ic >> 6) != 0) {  // otherwise multiply overflows
      return -1;
   }

   auto chacha = StreamCipher::create_or_throw("ChaCha(20)");
   chacha->set_key(key, crypto_stream_chacha20_KEYBYTES);
   chacha->set_iv(nonce, crypto_stream_chacha20_NONCEBYTES);
   chacha->seek(ic * 64);
   chacha->cipher(in, out, in_len);
   return 0;
}

int Sodium::crypto_stream_chacha20_ietf(uint8_t out[], size_t out_len, const uint8_t nonce[], const uint8_t key[]) {
   auto chacha = StreamCipher::create_or_throw("ChaCha(20)");
   chacha->set_key(key, crypto_stream_chacha20_ietf_KEYBYTES);
   chacha->set_iv(nonce, crypto_stream_chacha20_ietf_NONCEBYTES);
   chacha->write_keystream(out, out_len);
   return 0;
}

int Sodium::crypto_stream_chacha20_ietf_xor(
   uint8_t out[], const uint8_t in[], size_t in_len, const uint8_t nonce[], const uint8_t key[]) {
   return crypto_stream_chacha20_ietf_xor_ic(out, in, in_len, nonce, 0, key);
}

int Sodium::crypto_stream_chacha20_ietf_xor_ic(
   uint8_t out[], const uint8_t in[], size_t in_len, const uint8_t nonce[], uint32_t ic, const uint8_t key[]) {
   auto chacha = StreamCipher::create_or_throw("ChaCha(20)");
   chacha->set_key(key, crypto_stream_chacha20_ietf_KEYBYTES);
   chacha->set_iv(nonce, crypto_stream_chacha20_ietf_NONCEBYTES);
   chacha->seek(static_cast<uint64_t>(ic) * 64);
   chacha->cipher(in, out, in_len);
   return 0;
}

int Sodium::crypto_stream_xchacha20(uint8_t out[], size_t out_len, const uint8_t nonce[], const uint8_t key[]) {
   auto chacha = StreamCipher::create_or_throw("ChaCha(20)");
   chacha->set_key(key, crypto_stream_xchacha20_KEYBYTES);
   chacha->set_iv(nonce, crypto_stream_xchacha20_NONCEBYTES);
   chacha->write_keystream(out, out_len);
   return 0;
}

int Sodium::crypto_stream_xchacha20_xor(
   uint8_t out[], const uint8_t in[], size_t in_len, const uint8_t nonce[], const uint8_t key[]) {
   return crypto_stream_xchacha20_xor_ic(out, in, in_len, nonce, 0, key);
}

int Sodium::crypto_stream_xchacha20_xor_ic(
   uint8_t out[], const uint8_t in[], size_t in_len, const uint8_t nonce[], uint64_t ic, const uint8_t key[]) {
   if((ic >> 6) != 0) {  // otherwise multiply overflows
      return -1;
   }

   auto chacha = StreamCipher::create_or_throw("ChaCha(20)");
   chacha->set_key(key, crypto_stream_xchacha20_KEYBYTES);
   chacha->set_iv(nonce, crypto_stream_xchacha20_NONCEBYTES);
   chacha->seek(ic * 64);
   chacha->cipher(in, out, in_len);
   return 0;
}

}  // namespace Botan
