/*
* PKCS#12 KDF (RFC 7292 Appendix B)
* (C) 2026 Damiano Mazzella
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PKCS12_KDF_H_
#define BOTAN_PKCS12_KDF_H_

#include <botan/types.h>
#include <cstdint>
#include <string_view>

namespace Botan {

/**
 * Derive a key using the PKCS#12 KDF (RFC 7292 Appendix B)
 *
 * @param out output buffer
 * @param out_len length of output in bytes
 * @param password the password (will be converted to UTF-16BE)
 * @param salt the salt value
 * @param salt_len length of salt in bytes
 * @param iterations number of hash iterations
 * @param id purpose ID: 1 = key, 2 = IV, 3 = MAC key
 * @param hash_algo hash algorithm to use (default: SHA-1, also supports SHA-256)
 */
BOTAN_TEST_API void pkcs12_kdf(uint8_t out[],
                               size_t out_len,
                               std::string_view password,
                               const uint8_t salt[],
                               size_t salt_len,
                               size_t iterations,
                               uint8_t id,
                               std::string_view hash_algo = "SHA-1");

}  // namespace Botan

#endif
