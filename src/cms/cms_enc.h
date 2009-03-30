/*
* CMS Encoding
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CMS_ENCODER_H__
#define BOTAN_CMS_ENCODER_H__

#include <botan/x509cert.h>
#include <botan/x509stor.h>
#include <botan/pkcs8.h>
#include <botan/symkey.h>

namespace Botan {

/*
* CMS Encoding Operation
*/
class BOTAN_DLL CMS_Encoder
   {
   public:

      void encrypt(RandomNumberGenerator&,
                   const X509_Certificate&, const std::string = "");

      void encrypt(RandomNumberGenerator& rng,
                   const std::string&, const std::string& = "");

      void encrypt(RandomNumberGenerator& rng,
                   const SymmetricKey&, const std::string& = "");

      void authenticate(const X509_Certificate&, const std::string& = "");
      void authenticate(const std::string&, const std::string& = "");
      void authenticate(const SymmetricKey&, const std::string& = "");

      void sign(const X509_Certificate& cert,
                const PKCS8_PrivateKey& key,
                RandomNumberGenerator& rng,
                const std::vector<X509_Certificate>& cert_chain,
                const std::string& hash,
                const std::string& padding);

      void digest(const std::string& = "");

      void compress(const std::string&);
      static bool can_compress_with(const std::string&);

      SecureVector<byte> get_contents();
      std::string PEM_contents();

      void set_data(const std::string&);
      void set_data(const byte[], u32bit);

      CMS_Encoder(const std::string& str) { set_data(str); }
      CMS_Encoder(const byte buf[], u32bit length) { set_data(buf, length); }
   private:
      void add_layer(const std::string&, DER_Encoder&);

      void encrypt_ktri(RandomNumberGenerator&,
                        const X509_Certificate&, PK_Encrypting_Key*,
                        const std::string&);
      void encrypt_kari(RandomNumberGenerator&,
                        const X509_Certificate&, X509_PublicKey*,
                        const std::string&);

      SecureVector<byte> do_encrypt(RandomNumberGenerator& rng,
                                    const SymmetricKey&, const std::string&);

      static SecureVector<byte> make_econtent(const SecureVector<byte>&,
                                              const std::string&);

      static SymmetricKey setup_key(RandomNumberGenerator& rng,
                                    const std::string&);

      static SecureVector<byte> wrap_key(RandomNumberGenerator& rng,
                                         const std::string&,
                                         const SymmetricKey&,
                                         const SymmetricKey&);

      static SecureVector<byte> encode_params(const std::string&,
                                              const SymmetricKey&,
                                              const InitializationVector&);

      SecureVector<byte> data;
      std::string type;
   };

}

#endif
