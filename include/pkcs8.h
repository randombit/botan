/*************************************************
* PKCS #8 Header File                            *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_PKCS8_H__
#define BOTAN_PKCS8_H__

#include <botan/x509_key.h>
#include <botan/ui.h>

namespace Botan {

/*************************************************
* PKCS #8 Private Key Encoder                    *
*************************************************/
class PKCS8_Encoder
   {
   public:
      virtual AlgorithmIdentifier alg_id() const = 0;
      virtual MemoryVector<byte> key_bits() const = 0;
      virtual ~PKCS8_Encoder() {}
   };

/*************************************************
* PKCS #8 Private Key Decoder                    *
*************************************************/
class PKCS8_Decoder
   {
   public:
      virtual void alg_id(const AlgorithmIdentifier&) = 0;
      virtual void key_bits(const MemoryRegion<byte>&) = 0;
      virtual ~PKCS8_Decoder() {}
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
void encode(const Private_Key&, Pipe&, X509_Encoding = PEM);
void encrypt_key(const Private_Key&, Pipe&, const std::string&,
                 const std::string& = "", X509_Encoding = PEM);

std::string PEM_encode(const Private_Key&);
std::string PEM_encode(const Private_Key&, const std::string&,
                       const std::string& = "");

Private_Key* load_key(DataSource&, const User_Interface&);
Private_Key* load_key(DataSource&, const std::string& = "");

Private_Key* load_key(const std::string&, const User_Interface&);
Private_Key* load_key(const std::string&, const std::string& = "");

Private_Key* copy_key(const Private_Key&);

}

}

#endif
