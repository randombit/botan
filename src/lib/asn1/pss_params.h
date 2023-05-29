/*
* (C) 2017 Daniel Neus
*     2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PSS_PARAMS_H_
#define BOTAN_PSS_PARAMS_H_

#include <botan/asn1_obj.h>
#include <string>

namespace Botan {

class PSS_Params final : public ASN1_Object {
   public:
      static PSS_Params from_emsa_name(std::string_view emsa_name);

      PSS_Params(std::string_view hash_fn, size_t salt_len);

      PSS_Params(const uint8_t der[], size_t der_len);

      template <typename Alloc>
      PSS_Params(const std::vector<uint8_t, Alloc>& vec) : PSS_Params(vec.data(), vec.size()) {}

      const AlgorithmIdentifier& hash_algid() const { return m_hash; }

      const AlgorithmIdentifier& mgf_algid() const { return m_mgf; }

      const AlgorithmIdentifier& mgf_hash_algid() const { return m_mgf_hash; }

      size_t salt_length() const { return m_salt_len; }

      size_t trailer_field() const { return m_trailer_field; }

      std::string hash_function() const { return hash_algid().oid().to_formatted_string(); }

      std::string mgf_function() const { return mgf_algid().oid().to_formatted_string(); }

      std::vector<uint8_t> serialize() const;

      void encode_into(DER_Encoder& to) const override;

      void decode_from(BER_Decoder& from) override;

   private:
      AlgorithmIdentifier m_hash;
      AlgorithmIdentifier m_mgf;
      AlgorithmIdentifier m_mgf_hash;
      size_t m_salt_len;
      size_t m_trailer_field;
};

}  // namespace Botan

#endif
