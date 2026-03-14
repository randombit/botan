/*
* PKCS#12 PBE (RFC 7292 Appendix B)
* (C) 2026 Damiano Mazzella
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PKCS12_PBE_H_
#define BOTAN_PKCS12_PBE_H_

#include <botan/asn1_obj.h>
#include <botan/secmem.h>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace Botan {

class RandomNumberGenerator;

/**
* Decrypt data protected by PKCS#12 PBE (RFC 7292 Appendix B) or PBES2.
* @param ciphertext the encrypted data
* @param password the decryption password
* @param pbe_algo the AlgorithmIdentifier from the EncryptedData structure
*/
secure_vector<uint8_t> pkcs12_pbe_decrypt(std::span<const uint8_t> ciphertext,
                                          std::string_view password,
                                          const AlgorithmIdentifier& pbe_algo);

/**
* Encrypt data using PKCS#12 PBE (RFC 7292 Appendix B) or PBES2.
* @param plaintext the data to encrypt
* @param password the encryption password
* @param algo algorithm name: "PBE-SHA1-3DES" (default), "PBE-SHA1-2DES",
*             "PBES2-SHA256-AES256", "PBES2-SHA256-AES128"
* @param iterations PBKDF iteration count
* @param rng a random number generator
* @return the AlgorithmIdentifier and encrypted data
*/
std::pair<AlgorithmIdentifier, std::vector<uint8_t>> pkcs12_pbe_encrypt(std::span<const uint8_t> plaintext,
                                                                        std::string_view password,
                                                                        std::string_view algo,
                                                                        size_t iterations,
                                                                        RandomNumberGenerator& rng);

}  // namespace Botan

#endif
