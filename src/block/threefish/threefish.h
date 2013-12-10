/*
* Threefish
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_THREEFISH_H__
#define BOTAN_THREEFISH_H__

#include <botan/transform.h>

namespace Botan {

/**
* Threefish-512
*/
class BOTAN_DLL Threefish_512 : public Transformation
   {
   public:
      secure_vector<byte> start(const byte tweak[], size_t tweak_len) override;

      void update(secure_vector<byte>& blocks, size_t offset) override;

      void finish(secure_vector<byte>& final_block, size_t offset) override;

      size_t output_length(size_t input_length) const override;

      size_t update_granularity() const override;

      size_t minimum_final_size() const override;

      size_t default_nonce_length() const override;

      bool valid_nonce_length(size_t nonce_len) const override;

      Key_Length_Specification key_spec() const override;

      std::string name() const { return "Threefish-512"; }

      void clear();

   private:
      void key_schedule(const byte key[], size_t key_len) override;

      secure_vector<u64bit> m_T;
      secure_vector<u64bit> m_K;
   };

}

#endif
