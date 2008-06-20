/*************************************************
* PKCS #8 Header File                            *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_PKCS8_H__
#define BOTAN_PKCS8_H__

#include <botan/x509_key.h>
#include <botan/ui.h>
#include <botan/enums.h>

namespace Botan {

/*************************************************
* PKCS #8 Private Key Encoder                    *
*************************************************/
class BOTAN_DLL PKCS8_Encoder
   {
   public:
      virtual AlgorithmIdentifier alg_id() const = 0;
      virtual MemoryVector<byte> key_bits() const = 0;
      virtual ~PKCS8_Encoder() {}
   };

/*************************************************
* PKCS #8 Private Key Decoder                    *
*************************************************/
class BOTAN_DLL PKCS8_Decoder
   {
   public:
      virtual void alg_id(const AlgorithmIdentifier&) = 0;
      virtual void key_bits(const MemoryRegion<byte>&) = 0;
      virtual ~PKCS8_Decoder() {}
   };

/*************************************************
* PKCS #8 General Exception                      *
*************************************************/
struct BOTAN_DLL PKCS8_Exception : public Decoding_Error
   {
   PKCS8_Exception(const std::string& error) :
      Decoding_Error("PKCS #8: " + error) {}
   };

namespace PKCS8 {

/*************************************************
* PKCS #8 Private Key Encoding/Decoding          *
*************************************************/
BOTAN_DLL void encode(const Private_Key&, Pipe&, X509_Encoding = PEM);
BOTAN_DLL std::string PEM_encode(const Private_Key&);

BOTAN_DLL void encrypt_key(const Private_Key&,
                           Pipe&,
                           RandomNumberGenerator&,
                           const std::string&,
                           const std::string& = "",
                           X509_Encoding = PEM);

BOTAN_DLL std::string PEM_encode(const Private_Key&,
                                 RandomNumberGenerator&,
                                 const std::string&,
                                 const std::string& = "");

BOTAN_DLL Private_Key* load_key(DataSource&, RandomNumberGenerator&,
                                const User_Interface&);
BOTAN_DLL Private_Key* load_key(DataSource&, RandomNumberGenerator&,
                                const std::string& = "");

BOTAN_DLL Private_Key* load_key(const std::string&,
                                RandomNumberGenerator&,
                                const User_Interface&);
BOTAN_DLL Private_Key* load_key(const std::string&,
                                RandomNumberGenerator&,
                                const std::string& = "");

BOTAN_DLL Private_Key* copy_key(const Private_Key&,
                                RandomNumberGenerator& rng);

}

}

#endif
