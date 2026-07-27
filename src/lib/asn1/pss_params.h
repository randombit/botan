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
      * are values returned by SignaturePaddingScheme::name() and
      * these may change in a minor release.
      */
      static PSS_Params from_padding_name(std::string_view padding_name);

      /**
      * Note that the only valid strings you can pass to this function
      * are values returned by SignaturePaddingScheme::name() and
      * these may change in a minor release.
      */
      BOTAN_DEPRECATED("Use PSS_Params::from_padding_name")
      static PSS_Params from_emsa_name(std::string_view padding_name) {
         return PSS_Params::from_padding_name(padding_name);
      }

      /**
      * Create PSS parameters using MGF1 with the same hash as the message hash
      *
      * @param hash_fn the name of the hash function to use
      * @param salt_len the salt length in bytes
      */
      PSS_Params(std::string_view hash_fn, size_t salt_len);

      /**
      * Decode an encoded RSASSA-PSS-params
      */
      BOTAN_FUTURE_EXPLICIT PSS_Params(std::span<const uint8_t> der);

      /**
      * Return the AlgorithmIdentifier of the hash used to hash the message
      */
      const AlgorithmIdentifier& hash_algid() const { return m_hash; }

      /**
      * Return the AlgorithmIdentifier of the mask generation function
      */
      const AlgorithmIdentifier& mgf_algid() const { return m_mgf; }

      /**
      * Return the AlgorithmIdentifier of the hash used within the mask generation function
      */
      const AlgorithmIdentifier& mgf_hash_algid() const { return m_mgf_hash; }

      /**
      * Return the salt length in bytes
      */
      size_t salt_length() const { return m_salt_len; }

      /**
      * Return the trailer field; only a value of 1 is supported
      */
      size_t trailer_field() const { return m_trailer_field; }

      /**
      * Return the name of the hash used to hash the message
      */
      std::string hash_function() const { return hash_algid().oid().to_formatted_string(); }

      /**
      * Return the name of the mask generation function; only MGF1 is supported
      */
      std::string mgf_function() const { return mgf_algid().oid().to_formatted_string(); }

      /**
      * Return the DER encoding of these RSASSA-PSS-params
      */
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
