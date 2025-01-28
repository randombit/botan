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

/**
* PSS parameters type
*
* Handles encoding/decoding of RSASSA-PSS-params from RFC 3447
*
* Only MGF1 is supported, and the trailer field must 1 (ie the variant
* from IEEE 1363a using a hash identifier is not supported)
*/
class BOTAN_PUBLIC_API(3, 7) PSS_Params final : public ASN1_Object {
   public:
      /**
      * Note that the only valid strings you can pass to this function
      * are values returned by EMSA::name() and these may change in a
      * minor release.
      */
      static PSS_Params from_emsa_name(std::string_view emsa_name);

      PSS_Params(std::string_view hash_fn, size_t salt_len);

      /**
      * Decode an encoded RSASSA-PSS-params
      */
      PSS_Params(std::span<const uint8_t> der);

      const AlgorithmIdentifier& hash_algid() const { return m_hash; }

      const AlgorithmIdentifier& mgf_algid() const { return m_mgf; }

      const AlgorithmIdentifier& mgf_hash_algid() const { return m_mgf_hash; }

      size_t salt_length() const { return m_salt_len; }

      size_t trailer_field() const { return m_trailer_field; }

      std::string hash_function() const { return hash_algid().oid().to_formatted_string(); }

      std::string mgf_function() const { return mgf_algid().oid().to_formatted_string(); }

      std::vector<uint8_t> serialize() const;

      void encode_into(DER_Encoder& to) const override;

   private:
      // We don't currently support uninitialized PSS_Params
      void decode_from(BER_Decoder& from) override;

      AlgorithmIdentifier m_hash;
      AlgorithmIdentifier m_mgf;
      AlgorithmIdentifier m_mgf_hash;
      size_t m_salt_len;
      size_t m_trailer_field;
};

}  // namespace Botan

#endif
