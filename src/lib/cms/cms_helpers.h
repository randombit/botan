/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CMS_HELPERS_H_
#define BOTAN_CMS_HELPERS_H_

#include <botan/asn1_obj.h>
#include <botan/ber_dec.h>
#include <botan/cms.h>
#include <span>
#include <vector>

namespace Botan::CMS {

/**
* Encode a ContentInfo: SEQUENCE { contentType, [0] EXPLICIT content }.
* @p content is the full DER encoding of the inner content object.
*/
BOTAN_TEST_API std::vector<uint8_t> make_content_info(const OID& content_type, std::span<const uint8_t> content);

/**
* Decode a ContentInfo, requiring DER and rejecting trailing data.
* Returns the content type OID and the inner content object.
*/
BOTAN_TEST_API std::pair<OID, BER_Object> open_content_info(std::span<const uint8_t> content_info);

/**
* Given an IMPLICIT-tagged SET OF Attribute ([0] signedAttrs or [1]
* authAttrs), return its encoding with the universal SET OF tag, as
* used for signing and AAD computation.
*/
BOTAN_TEST_API std::vector<uint8_t> attrs_as_set_encoding(const BER_Object& obj);

/**
* Build the complete RecipientInfo encoding (the `ori [4]` alternative
* holding a KEMRecipientInfo) for an ML-KEM recipient.
*/
std::vector<uint8_t> kemri_create(const X509_Certificate& cert,
                                  std::span<const uint8_t> cek,
                                  RandomNumberGenerator& rng);

/**
* Attempt to recover the CEK from an OtherRecipientInfo of type
* KEMRecipientInfo. Returns nullopt if the rid does not match @p cert.
* @p ori_body is the contents of the [4] tagged OtherRecipientInfo.
*/
std::optional<secure_vector<uint8_t>> kemri_try_decrypt(std::span<const uint8_t> ori_body,
                                                        const Private_Key& key,
                                                        const X509_Certificate& cert,
                                                        RandomNumberGenerator& rng);

}  // namespace Botan::CMS

#endif
