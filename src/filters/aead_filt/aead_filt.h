/*
* Filter interface for AEAD modes
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_AEAD_FILTER_H__
#define BOTAN_AEAD_FILTER_H__

#include <botan/key_filt.h>
#include <botan/buf_filt.h>
#include <botan/aead.h>
#include <memory>

namespace Botan {

/**
* Filter interface for AEAD modes like EAX and GCM
*/
class BOTAN_DLL AEAD_Filter : public Keyed_Filter,
                              private Buffered_Filter
   {
   public:
      AEAD_Filter(AEAD_Mode* aead);

      /**
      * Set associated data that is not included in the ciphertext but
      * that should be authenticated. Must be called after set_key
      * and before end_msg.
      *
      * @param ad the associated data
      * @param ad_len length of add in bytes
      */
      void set_associated_data(const byte ad[], size_t ad_len);

      void set_iv(const InitializationVector& iv) override;

      void set_key(const SymmetricKey& key) override;

      Key_Length_Specification key_spec() const override;

      bool valid_iv_length(size_t length) const override;

      std::string name() const override;

   private:
      void write(const byte input[], size_t input_length) override;
      void start_msg() override;
      void end_msg() override;

      void buffered_block(const byte input[], size_t input_length) override;
      void buffered_final(const byte input[], size_t input_length) override;

      class Nonce_State
         {
         public:
            void update(const InitializationVector& iv);
            std::vector<byte> get();
         private:
            bool m_fresh_nonce = false;
            std::vector<byte> m_nonce;
         };

      Nonce_State m_nonce;
      std::unique_ptr<AEAD_Mode> m_aead;

   };

}

#endif
