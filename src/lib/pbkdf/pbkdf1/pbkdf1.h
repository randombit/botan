/*
* PBKDF1
* (C) 2026 Damiano Mazzella
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BOTAN_PBKDF1_H__
#define BOTAN_BOTAN_PBKDF1_H__

#include <botan/pwdhash.h>
#include <botan/secmem.h>
#include <botan/hash.h>
#include <botan/pbkdf.h>

namespace Botan {

/**
 * Derive a key using PKCS#12 PBKDF1 (RFC 7292 Appendix B)
 *
 * @param out output buffer
 * @param out_len length of output in bytes
 * @param password the password (will be converted to UTF-16BE)
 * @param salt the salt value
 * @param salt_len length of salt in bytes
 * @param iterations number of iterations
 * @param id purpose ID (1=key, 2=IV, 3=MAC)
 * @param hash_algo hash algorithm to use (default: SHA-1, also supports SHA-256)
 */
void pbkdf1(uint8_t out[],
            size_t out_len,
            std::string_view password,
            const uint8_t salt[],
            size_t salt_len,
            size_t iterations,
            uint8_t id,
            std::string_view hash_algo = "SHA-1");

}  // namespace Botan

#endif