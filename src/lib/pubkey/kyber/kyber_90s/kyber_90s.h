/*
 * Symmetric primitives for Kyber (90s mode)
 * (C) 2022 Jack Lloyd
 * (C) 2022 Hannes Rantzsch, René Meusel, neXenio GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_KYBER_90S_H_
#define BOTAN_KYBER_90S_H_

#include <botan/hash.h>
#include <botan/stream_cipher.h>

#include <botan/internal/kyber_symmetric_primitives.h>

#include <array>
#include <memory>

namespace Botan {

class Kyber_90s_Symmetric_Primitives : public Kyber_Symmetric_Primitives
   {
   public:
      Kyber_90s_Symmetric_Primitives() :
         m_sha512(HashFunction::create_or_throw("SHA-512")),
         m_sha256(HashFunction::create_or_throw("SHA-256")),
         m_aes256_ctr(StreamCipher::create_or_throw("CTR-BE(AES-256)"))
         {}

      std::unique_ptr<HashFunction> G() const override
         {
         return m_sha512->new_object();
         }

      std::unique_ptr<HashFunction> H() const override
         {
         return m_sha256->new_object();
         }

      std::unique_ptr<HashFunction> KDF() const override
         {
         return m_sha256->new_object();
         }

      std::unique_ptr<StreamCipher> XOF(const std::vector<uint8_t>& seed,
                                        const std::tuple<uint8_t, uint8_t>& matrix_position) const override
         {
         std::array<uint8_t, 12> iv = {std::get<0>(matrix_position), std::get<1>(matrix_position), 0};

         auto cipher = m_aes256_ctr->new_object();
         cipher->set_key(seed);
         cipher->set_iv(iv.data(), iv.size());

         return cipher;
         }

      secure_vector<uint8_t> PRF(const secure_vector<uint8_t>& seed, const uint8_t nonce,
                                 const size_t outlen) const override
         {
         m_aes256_ctr->set_key(seed);

         const std::array<uint8_t, 12> iv = {nonce, 0};
         m_aes256_ctr->set_iv(iv.data(), iv.size());

         secure_vector<uint8_t> out(outlen);
         m_aes256_ctr->write_keystream(out.data(), out.size());

         return out;
         }

   private:
      std::unique_ptr<HashFunction> m_sha512;
      std::unique_ptr<HashFunction> m_sha256;
      std::unique_ptr<StreamCipher> m_aes256_ctr;
   };

} // namespace Botan

#endif
