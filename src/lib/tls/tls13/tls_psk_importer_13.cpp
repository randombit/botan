/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_psk_13.h>

#include <botan/assert.h>
#include <botan/hash.h>
#include <botan/kdf.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/loadstor.h>
#include <array>
#include <limits>

namespace Botan::TLS {

PSKImporter::PSKImporter(std::span<const uint8_t> key,
                         std::span<const uint8_t> identity,
                         std::span<const uint8_t> context,
                         std::string_view hash) :
      m_key(key.begin(), key.end()),
      m_identity(identity.begin(), identity.end()),
      m_context(context.begin(), context.end()),
      m_hash(hash) {
   BOTAN_ARG_CHECK(m_hash == "SHA-256" || m_hash == "SHA-384", "PSK importer hash must be SHA-256 or SHA-384");
   // RFC 9258 5.1:
   //    struct {
   //       opaque external_identity<1...2^16-1>;
   //       opaque context<0..2^16-1>;
   //       uint16 target_protocol;
   //       uint16 target_kdf;
   //    } ImportedIdentity;

   BOTAN_ARG_CHECK(!m_identity.empty(), "PSK importer identity must not be empty");

   // The derived imported PSK identity (above) ends up as a TLS PSK identity
   // (opaque<1..2^16-1>), so the whole assembled value must fit in.
   BOTAN_ARG_CHECK(m_identity.size() + m_context.size() + 8 <= std::numeric_limits<uint16_t>::max(),
                   "PSK importer identity + context too long for a TLS PSK identity");
}

ExternalPSK PSKImporter::derive_imported_psk(Protocol_Version version, std::string_view target_hash) const {
   BOTAN_ARG_CHECK(version == Protocol_Version::TLS_V13 || version == Protocol_Version::DTLS_V13,
                   "PSK importer is only defined for (D)TLS 1.3");
   BOTAN_ARG_CHECK(target_hash == "SHA-256" || target_hash == "SHA-384",
                   "PSK importer target hash must be SHA-256 or SHA-384");

   // TODO(DTLS1.3): This duplicates Cipher_State::hkdf_expand_label

   const uint16_t target_protocol = version.version_code();
   const uint16_t target_kdf = (target_hash == "SHA-256") ? uint16_t(0x0001) : uint16_t(0x0002);

   // Build imported PSK identity (RFC 9258, Section 5.1):
   //   external_identity (length-prefixed) || context (length-prefixed) ||
   //   target_protocol (2 bytes) || target_kdf (2 bytes)
   const auto id_len = static_cast<uint16_t>(m_identity.size());
   const auto ctx_len = static_cast<uint16_t>(m_context.size());

   const auto imported_identity = concat<std::vector<uint8_t>>(
      store_be(id_len), m_identity, store_be(ctx_len), m_context, store_be(target_protocol), store_be(target_kdf));

   // RFC 9258 5.1: "The hash function used for HKDF is that which is
   // associated with the EPSK. It is not the hash function associated
   // with ImportedIdentity.target_kdf."
   auto hash_fn = HashFunction::create_or_throw(m_hash);
   hash_fn->update(imported_identity);
   const auto identity_hash = hash_fn->final_stdvec();

   // HKDF-Extract(0, epsk) -- using the EPSK's hash per above
   const size_t psk_hash_len = hash_fn->output_length();
   auto hkdf_extract = KDF::create_or_throw("HKDF-Extract(" + m_hash + ")");

   const std::vector<uint8_t> salt(psk_hash_len, 0);
   const auto epskx = hkdf_extract->derive_key(psk_hash_len, m_key, salt, {});

   // HKDF-Expand-Label(epskx, "derived psk", Hash(ImportedIdentity), L)
   //
   // Two distinct hashes are in play here and it is easy to conflate them:
   //
   //  * The HKDF used for Extract and Expand is the one associated with the
   //    EPSK (m_hash). RFC 9258 5.1: "The hash function used for HKDF is
   //    that which is associated with the EPSK. It is not the hash function
   //    associated with ImportedIdentity.target_kdf."
   //
   //  * The output length L, by contrast, is taken from the *target* KDF,
   //    not the EPSK's hash. RFC 9258 5.1: "L corresponds to the KDF
   //    output length of ImportedIdentity.target_kdf [...] For hash-based
   //    KDFs, such as HKDF_SHA256 (0x0001), this is the length of the
   //    hash function output, e.g., 32 octets for SHA256."
   //
   // So e.g. a SHA-256 EPSK imported for a SHA-384 target cipher suite runs
   // HKDF-SHA-256 (driven by m_hash) and emits 48 bytes (driven by target_hash).
   const std::string target_hash_str(target_hash);
   auto target_hash_fn = HashFunction::create_or_throw(target_hash_str);
   const size_t target_hash_len = target_hash_fn->output_length();
   const auto expand_out_len = static_cast<uint16_t>(target_hash_len);

   auto hkdf_expand = KDF::create_or_throw("HKDF-Expand(" + m_hash + ")");

   // RFC 9147 5.9
   //    Section 7.1 of RFC 9846 specifies that HKDF-Expand-Label uses a label
   //    prefix of "tls13 ". For DTLS 1.3, that label SHALL be "dtls13". [...]
   //    Note that there is no trailing space; this is necessary in order to
   //    keep the overall label size inside of one hash iteration because "DTLS"
   //    is one letter longer than "TLS".
   const auto prefixed_label = [&]() -> std::array<uint8_t, 17> {
      if(!version.is_datagram_protocol()) {
         return {'t', 'l', 's', '1', '3', ' ', 'd', 'e', 'r', 'i', 'v', 'e', 'd', ' ', 'p', 's', 'k'};
      } else {
         return {'d', 't', 'l', 's', '1', '3', 'd', 'e', 'r', 'i', 'v', 'e', 'd', ' ', 'p', 's', 'k'};
      }
   }();

   // TLS 1.3 HkdfLabel: length (2) || label length (1) || label || context length (1) || context

   const auto prefixed_label_len = static_cast<uint8_t>(prefixed_label.size());
   const auto identity_hash_len = static_cast<uint8_t>(identity_hash.size());
   const auto hkdf_label = concat<std::vector<uint8_t>>(store_be(expand_out_len),
                                                        store_be(prefixed_label_len),
                                                        prefixed_label,
                                                        store_be(identity_hash_len),
                                                        identity_hash);

   secure_vector<uint8_t> ipskx(target_hash_len);
   hkdf_expand->derive_key(ipskx, epskx, hkdf_label, {});

   const std::string wire_identity(imported_identity.begin(), imported_identity.end());
   return ExternalPSK(wire_identity, target_hash_str, std::move(ipskx), true);
}

}  // namespace Botan::TLS
