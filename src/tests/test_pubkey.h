
#include <botan/pubkey.h>

using namespace Botan;

size_t validate_encryption(Botan::PK_Encryptor& e, Botan::PK_Decryptor& d,
                           const std::string& algo, const std::string& input,
                           const std::string& random, const std::string& exp);

size_t validate_signature(PK_Verifier& v, PK_Signer& s, const std::string& algo,
                          const std::string& input,
                          RandomNumberGenerator& rng,
                          const std::string& exp);

size_t validate_signature(PK_Verifier& v, PK_Signer& s, const std::string& algo,
                          const std::string& input,
                          const std::string& random,
                          const std::string& exp);

size_t validate_kas(PK_Key_Agreement& kas, const std::string& algo,
                    const std::vector<byte>& pubkey, const std::string& output,
                    size_t keylen);
