/*************************************************
* PKCS #8 Header File                            *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_PKCS8_H__
#define BOTAN_PKCS8_H__

#include <botan/x509_key.h>
#include <botan/ui.h>

namespace Botan {

/*************************************************
* PKCS #8 Private Key                            *
*************************************************/
class PKCS8_PrivateKey : public virtual X509_PublicKey
   {
   public:
      virtual SecureVector<byte> DER_encode_priv() const = 0;
      virtual void BER_decode_priv(DataSource&) = 0;
      virtual ~PKCS8_PrivateKey() {}
   };

/*************************************************
* PKCS #8 General Exception                      *
*************************************************/
struct PKCS8_Exception : public Decoding_Error
   {
   PKCS8_Exception(const std::string& error) :
      Decoding_Error("PKCS #8: " + error) {}
   };

namespace PKCS8 {

/*************************************************
* PKCS #8 Private Key Encoding/Decoding          *
*************************************************/
void encode(const PKCS8_PrivateKey&, Pipe&, X509_Encoding = PEM);
void encrypt_key(const PKCS8_PrivateKey&, Pipe&, const std::string&,
                 const std::string& = "", X509_Encoding = PEM);

std::string PEM_encode(const PKCS8_PrivateKey&);
std::string PEM_encode(const PKCS8_PrivateKey&, const std::string&,
                       const std::string& = "");

PKCS8_PrivateKey* load_key(DataSource&, const User_Interface&);
PKCS8_PrivateKey* load_key(DataSource&, const std::string& = "");

PKCS8_PrivateKey* load_key(const std::string&, const User_Interface&);
PKCS8_PrivateKey* load_key(const std::string&, const std::string& = "");

PKCS8_PrivateKey* copy_key(const PKCS8_PrivateKey&);

}

}

#endif
