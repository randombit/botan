OpenSSL 1.1 to Botan 3.x Migration
==================================

This aims to be a rough guide for migrating applications from OpenSSL 1.1 to Botan 3.x.

This guide attempts to be, but is not, complete. If you run into a problem while
migrating code that does not seem to be described here, please open an issue on
`GitHub <https://github.com/randombit/botan/issues>`_.

.. note::
   The OpenSSL code snippets in this guide may not be 100% correct. They are
   intended to show the differences in using OpenSSL's and Botan's APIs
   rather to be a complete and correct example.

General Remarks
----------------

* Botan is a C++ library, whereas OpenSSL is a C library
* Botan also provides a :doc:`C API <api_ref/ffi>` for most of its functionality,
  but it is not a 1:1 mapping of the C++ API
* With OpenSSL's API, there are sometimes multiple ways to achieve the same result,
  whereas Botan's API is more consistent
* OpenSSL's API is mostly underdocumented, whereas Botan targets 100% Doxygen
  coverage for all public API
* It is often hard to find example code for OpenSSL, whereas Botan provides
  many :ref:`examples <index:examples>` and lots of
  `test code <https://github.com/randombit/botan/tree/master/src/tests>`_.

X.509
------

Consider the following application code that uses OpenSSL to verify a
certificate chain consisting of an end-entity certificate, two untrusted intermediate
certificates, and a trusted root certificate.

.. code-block:: cpp

    #include <openssl/x509.h>
    #include <openssl/pem.h>
    #include <openssl/ssl.h>

    int main() {
        // Create a new X.509 store
        X509_STORE *store = X509_STORE_new();

        // Load the root certificate
        FILE* rootCertFileHandle = fopen("root.crt", "r");
        X509* rootCert = PEM_read_X509(rootCertFileHandle, NULL, NULL, NULL);
        X509_STORE_add_cert(store, rootCert);
        fclose(rootCertFileHandle);

        // Create a new X.509 store context
        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        X509_STORE_CTX_init(ctx, store, NULL, NULL);

        // Load the intermediate certificates
        FILE* intermediateCertFileHandle1 = fopen("int2.crt", "r");
        FILE* intermediateCertFileHandle2 = fopen("int1.crt", "r");
        X509* intermediateCert1 = PEM_read_X509(intermediateCertFileHandle1, NULL, NULL, NULL);
        X509* intermediateCert2 = PEM_read_X509(intermediateCertFileHandle2, NULL, NULL, NULL);
        X509_STORE_CTX_trusted_stack(ctx, sk_X509_new_null());
        sk_X509_push(X509_STORE_CTX_get0_untrusted(ctx), intermediateCert1);
        sk_X509_push(X509_STORE_CTX_get0_untrusted(ctx), intermediateCert2);
        fclose(intermediateCertFileHandle1);
        fclose(intermediateCertFileHandle2);

        // Load the end-entity certificate
        FILE* endEntityCertFileHandle = fopen("ee.crt", "r");
        X509* endEntityCert = PEM_read_X509(endEntityCertFileHandle, NULL, NULL, NULL);
        X509_STORE_CTX_set_cert(ctx, endEntityCert);
        fclose(endEntityCertFileHandle);

        // Verify the certificate chain
        int result = X509_verify_cert(ctx);
        if(result != 1) {
            // Verification failed
            X509_STORE_CTX_free(ctx);
            X509_STORE_free(store);
            return -1;
        }

        // Verification succeeded
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        return 0;
    }

First, we create a new ``X509_STORE`` object and add the trusted root certificate.
Then we add the intermediate certificates to the untrusted certificate stack.
Finally, we set the end-entity certificate and call ``X509_verify_cert()`` to verify
the whole certificate chain.

Here is the equivalent C++ code using Botan:

.. literalinclude:: /../src/examples/x509_path.cpp
   :language: cpp

First, we create a ``Certificate_Store_In_Memory`` object and add the trusted root certificate.
Additionally, we use ``System_Certificate_Store`` to load all trusted root certificates from
the operating system's certificate store to trust. Botan provides several different
:ref:`api_ref/x509:certificate stores`, including certificate stores that load certificates
from a directory or from an SQL database. It even provides an interface for implementing
your own certificate store.
Then we add the end-entity certificate and the intermediate certificates to the ``end_certs`` chain.
Optionally, we can set up path validation restrictions, specify usage and hostname for DNS,
and then call ``x509_path_validate()`` to :ref:`verify the certificate chain <api_ref/x509:path validation>`.


Random Number Generation
-------------------------

Consider the following application code to generate random bytes using OpenSSL.

.. code-block:: cpp

    #include <openssl/rand.h>
    #include <iostream>

    int main() {
        unsigned char buffer[16]; // Buffer to hold 16 random bytes

        if(RAND_bytes(buffer, sizeof(buffer)) != 1) {
            std::cerr << "Error generating random bytes.\n";
            return 1;
        }

        // Print the random bytes in hexadecimal format
        for(int i = 0; i < sizeof(buffer); i++) {
            printf("%02X", buffer[i]);
        }
        printf("\n");

        return 0;
    }

This example uses the ``RAND_bytes()`` function to generate 16 random bytes, e.g.,
for a 128-bit AES key, and prints it on the console.

Here is the equivalent C++ code using Botan:

.. code-block:: cpp

    #include <botan/auto_rng.h>
    #include <botan/hex.h>
    #include <iostream>

    int main() {
        Botan::AutoSeeded_RNG rng;

        const Botan::secure_vector<uint8_t> buffer = rng.random_vec(16);

        // Print the random bytes in hexadecimal format
        std::cout << Botan::hex_encode(buffer) << std::endl;

        return 0;
    }

This snippet uses the ``AutoSeeded_RNG`` class to generate the 16 random bytes. Botan provides different
:ref:`api_ref/rng:random number generators`, including system-specific as well as system-independent
software and hardware-based generators, and a comprehensive interface for implementing
your own random number generator, if required. ``AutoSeeded_RNG`` is the recommended random number
generator for most applications.
The ``random_vec()`` function returns the requested number of random bytes passed.
Botan provides a ``hex_encode()`` function that converts the random bytes to a hexadecimal string.

Hash Functions
---------------

Consider the following application code to hash some data using OpenSSL.

.. code-block:: cpp

    #include <openssl/evp.h>
    #include <openssl/sha.h>
    #include <iostream>
    #include <vector>

    void printHash(EVP_MD_CTX* ctx, const std::string& name) {
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int lengthOfHash = 0;

        EVP_DigestFinal_ex(ctx, hash, &lengthOfHash);

        std::cout << name << ": ";
        for(unsigned int i = 0; i < lengthOfHash; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        std::cout << std::endl;
    }

    int main() {
        EVP_MD_CTX *ctx1 = EVP_MD_CTX_new();
        EVP_MD_CTX *ctx2 = EVP_MD_CTX_new();
        EVP_MD_CTX *ctx3 = EVP_MD_CTX_new();

        EVP_DigestInit_ex(ctx1, EVP_sha256(), NULL);
        EVP_DigestInit_ex(ctx2, EVP_sha384(), NULL);
        EVP_DigestInit_ex(ctx3, EVP_sha3_512(), NULL);

        std::vector<uint8_t> buffer(2048);
        while(std::cin.good()) {
            std::cin.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
            std::streamsize bytesRead = std::cin.gcount();

            EVP_DigestUpdate(ctx1, buffer.data(), bytesRead);
            EVP_DigestUpdate(ctx2, buffer.data(), bytesRead);
            EVP_DigestUpdate(ctx3, buffer.data(), bytesRead);
        }

        printHash(ctx1, "SHA-256");
        printHash(ctx2, "SHA-384");
        printHash(ctx3, "SHA-3-512");

        EVP_MD_CTX_free(ctx1);
        EVP_MD_CTX_free(ctx2);
        EVP_MD_CTX_free(ctx3);

        return 0;
    }

This example uses the ``EVP_DigestInit_ex()``, ``EVP_DigestUpdate()``, and ``EVP_DigestFinal_ex()``
functions to hash data using SHA-256, SHA-384, and SHA-3-512. The ``printHash()`` function is used
to print the hash values in hexadecimal format.

Here is the equivalent C++ code using Botan:

.. literalinclude:: /../src/examples/hash.cpp
   :language: cpp

This example uses the ``HashFunction`` interface to hash data using SHA-256, SHA-384, and SHA-3-512.
The ``hash()`` function is used to hash the data and the ``output_length()`` function is used to
determine the length of the hash value. Botan provides a comprehensive list of
:doc:`hash functions <api_ref/hash>`, including all SHA-2 and SHA-3 variants, as well as
:doc:`message authentication codes <api_ref/message_auth_codes>` and :doc:`key derivation functions <api_ref/kdf>`.

Symmetric Encryption
---------------------

Consider the following application code to encrypt some data with AES using OpenSSL.

.. code-block:: cpp

    #include <openssl/aes.h>
    #include <openssl/evp.h>
    #include <iostream>
    #include <iomanip>

    int main() {
        // Hex-encoded key and plaintext block
        const char* key_hex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
        const char* plaintext_hex = "00112233445566778899AABBCCDDEEFF";

        // Convert hex-encoded key and plaintext block to binary
        unsigned char key[32], plaintext[16];
        for(int i = 0; i < 32; i++) {
            sscanf(&key_hex[i*2], "%02x", &key[i]);
        }
        for(int i = 0; i < 16; i++) {
            sscanf(&plaintext_hex[i*2], "%02x", &plaintext[i]);
        }

        // Encrypt
        unsigned char ciphertext[16], iv_enc[AES_BLOCK_SIZE] = {0};
        EVP_CIPHER_CTX *ctx_enc = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx_enc, EVP_aes_256_cbc(), NULL, key, iv_enc);
        int outlen1;
        EVP_EncryptUpdate(ctx_enc, ciphertext, &outlen1, plaintext, sizeof(plaintext));
        EVP_EncryptFinal_ex(ctx_enc, ciphertext + outlen1, &outlen1);

        // Print ciphertext in hexadecimal format
        for(int i = 0; i < 16; i++) {
            printf("%02X", ciphertext[i]);
        }
        printf("\n");

        return 0;
    }

This example uses the ``EVP_EncryptInit_ex()``, ``EVP_EncryptUpdate()``, and ``EVP_EncryptFinal_ex()``
functions to encrypt a 128-bit plaintext block with a 256-bit key using AES. The key and plaintext block
are hex-decoded and converted to binary before encryption.

Here is the equivalent C++ code using Botan:

.. literalinclude:: /../src/examples/aes_cbc.cpp
   :language: cpp

This example uses the ``CipherMode`` interface to encrypt a 128-bit plaintext block
with a 256-bit key using AES in CBC mode with PKCS#7 padding.
The ``set_key()`` function is used to set the key and the ``start()`` and ``finish()`` functions
are used to encrypt the plaintext block.

To learn more about the ``BlockCipher`` and ``CipherMode`` interfaces, including a list of all
available block ciphers and cipher modes, see the :ref:`api_ref/block_cipher:block ciphers` and
:ref:`api_ref/cipher_modes:cipher modes` handbook sections.

Asymmetric Encryption
---------------------------------

Consider the following application code to encrypt some data with RSA using OpenSSL.

.. code-block:: cpp

    #include <openssl/evp.h>
    #include <openssl/pem.h>
    #include <openssl/rsa.h>
    #include <openssl/err.h>
    #include <string.h>
    #include <stdio.h>

    int main() {
        // Load public key
        FILE* pubKeyFile = fopen("public.pem", "r");
        if(pubKeyFile == NULL) {
            fprintf(stderr, "Error opening public key file.\n");
            return 1;
        }
        EVP_PKEY* pubKey = PEM_read_PUBKEY(pubKeyFile, NULL, NULL, NULL);
        fclose(pubKeyFile);

        // Load private key
        FILE* privKeyFile = fopen("private.pem", "r");
        if(privKeyFile == NULL) {
            fprintf(stderr, "Error opening private key file.\n");
            return 1;
        }
        EVP_PKEY* privKey = PEM_read_PrivateKey(privKeyFile, NULL, NULL, NULL);
        fclose(privKeyFile);

        // String to encrypt
        unsigned char* plaintext = "Your great-grandfather gave this watch to your granddad for good luck. Unfortunately, Dane's luck wasn't as good as his old man's.";
        size_t plaintext_len = strlen(plaintext);

        // Encrypt
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubKey, NULL);
        EVP_PKEY_encrypt_init(ctx);
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
        size_t encrypted_len;
        EVP_PKEY_encrypt(ctx, NULL, &encrypted_len, plaintext, plaintext_len);
        unsigned char* encrypted = (unsigned char*)malloc(encrypted_len);
        EVP_PKEY_encrypt(ctx, encrypted, &encrypted_len, plaintext, plaintext_len);

        // Decrypt
        EVP_PKEY_CTX *ctx2 = EVP_PKEY_CTX_new(privKey, NULL);
        EVP_PKEY_decrypt_init(ctx2);
        EVP_PKEY_CTX_set_rsa_padding(ctx2, RSA_PKCS1_OAEP_PADDING);
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx2, EVP_sha256());
        size_t decrypted_len;
        EVP_PKEY_decrypt(ctx2, NULL, &decrypted_len, encrypted, encrypted_len);
        unsigned char* decrypted = (unsigned char*)malloc(decrypted_len + 1);
        EVP_PKEY_decrypt(ctx2, decrypted, &decrypted_len, encrypted, encrypted_len);
        decrypted[decrypted_len] = '\0';

        // Print encrypted and decrypted strings
        for(size_t i = 0; i < encrypted_len; i++) {
            printf("%02X", encrypted[i]);
        }
        printf("\n");
        printf("%s\n", decrypted);

        // Clean up
        EVP_PKEY_free(pubKey);
        EVP_PKEY_free(privKey);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_CTX_free(ctx2);
        free(encrypted);
        free(decrypted);

        return 0;
    }

This example uses OpenSSL'S EVP interface, specifically ``EVP_PKEY_encrypt()``
and ``EVP_PKEY_decrypt()`` functions to encrypt and decrypt a string using RSA.
The public and private keys are loaded from files.
The ``EVP_PKEY_CTX_set_rsa_padding()`` and ``EVP_PKEY_CTX_set_rsa_oaep_md()`` functions are used
to set the padding scheme and the hash function for RSA-OAEP.

Here is the equivalent C++ code using Botan:

.. literalinclude:: /../src/examples/rsa_encrypt.cpp
   :language: cpp

This example uses the ``PK_Encryptor_EME`` and ``PK_Decryptor_EME`` classes to
:ref:`encrypt and decrypt <api_ref/pubkey:public key encryption/decryption>`.
a message using :ref:`api_ref/pubkey:rsa`. The public and private keys are
:ref:`loaded from files <api_ref/pubkey:serializing private keys using pkcs #8>`.
The padding scheme and :doc:`hash function <api_ref/hash>` are passed as a string parameter.

Asymmetric Signatures
----------------------------

Consider the following application code to sign some data with ECDSA using OpenSSL.

.. code-block:: cpp

    #include <openssl/ec.h>
    #include <openssl/obj_mac.h>
    #include <openssl/err.h>
    #include <openssl/ecdsa.h>
    #include <openssl/pem.h>
    #include <openssl/sha.h>
    #include <iostream>

    int main() {
        EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp521r1);

        if(ec_key == NULL) {
            fprintf(stderr, "Error creating EC_KEY structure.\n");
            return 1;
        }

        if(!EC_KEY_generate_key(ec_key)) {
            fprintf(stderr, "Error generating key.\n");
            ERR_print_errors_fp(stderr);
            EC_KEY_free(ec_key);
            return 1;
        }

        // String to sign
        std::string plaintext = "This is a tasty burger!";

        // Hash the plaintext
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)plaintext.c_str(), plaintext.size(), hash);

        // Sign the hash
        ECDSA_SIG* sig = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, ec_key);
        if(sig == NULL) {
            std::cerr << "Error signing: " << ERR_error_string(ERR_get_error(), NULL) << "\n";
            return 1;
        }

        // Print the signature
        const BIGNUM* r;
        const BIGNUM* s;
        ECDSA_SIG_get0(sig, &r, &s);
        char* r_hex = BN_bn2hex(r);
        char* s_hex = BN_bn2hex(s);
        std::cout << "Signature: (" << r_hex << ", " << s_hex << ")\n";

        // Clean up
        EC_KEY_free(ec_key);
        ECDSA_SIG_free(sig);
        OPENSSL_free(r_hex);
        OPENSSL_free(s_hex);
        return 0;
    }

This snippet uses OpenSSL's ECDSA interface, specifically ``ECDSA_do_sign()``,
to sign a string message using ECDSA. The private key is loaded from a file.
The ``SHA256()`` function is used to hash the plaintext before signing.

Here is the equivalent C++ code using Botan:

.. literalinclude:: /../src/examples/ecdsa.cpp
   :language: cpp

This example uses the ``PK_Signer`` and ``PK_Verifier`` classes to sign and verify
a message using :ref:`api_ref/pubkey:ecdsa`. The private key is similary
:ref:`loaded from a file <api_ref/pubkey:serializing private keys using pkcs #8>`.
The :doc:`hash function <api_ref/hash>` is passed as a string parameter.
``PK_Verifier::check_signature()`` is used to
:ref:`verify the signature <api_ref/pubkey:public key signature schemes>`.
