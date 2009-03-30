/*
* EAC1_1 CVC ADO
* (C) 2008 Falko Strenzke
*          strenzke@flexsecure.de
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_EAC_CVC_ADO_H__
#define BOTAN_EAC_CVC_ADO_H__

#include <botan/x509_key.h>
#include <botan/pubkey_enums.h>
#include <botan/pubkey.h>
#include <botan/ecdsa.h>
#include <botan/eac_obj.h>
#include <botan/cvc_req.h>
#include <string>

namespace Botan {

/**
* This class represents a TR03110 (EAC) v1.1 CVC ADO request
*/

 // CRTP continuation from EAC1_1_obj
class BOTAN_DLL EAC1_1_ADO : public EAC1_1_obj<EAC1_1_ADO>
   {
   public:
      friend class EAC1_1_obj<EAC1_1_ADO>;

      /**
      * Construct a CVC ADO request from a DER encoded CVC ADO request file.
      * @param str the path to the DER encoded file
      */
      EAC1_1_ADO(const std::string& str);

      /**
      * Construct a CVC ADO request from a data source
      * @param source the data source
      */
      EAC1_1_ADO(std::tr1::shared_ptr<DataSource> source);

      /**
      * Create a signed CVC ADO request from to be signed (TBS) data
      * @param signer the signer used to sign the CVC ADO request
      * @param tbs_bits the TBS data to sign
      */
      static MemoryVector<byte> make_signed(
         std::auto_ptr<PK_Signer> signer,
         const MemoryRegion<byte>& tbs_bits,
         RandomNumberGenerator& rng);

      /**
      * Get the CAR of this CVC ADO request
      * @result the CAR of this CVC ADO request
      */
      ASN1_Car get_car() const;

      /**
      * Get the CVC request contained in this object.
      * @result the CVC request inside this CVC ADO request
      */
      EAC1_1_Req get_request() const;

      /**
      * Encode this object into a pipe. Only DER is supported.
      * @param out the pipe to encode this object into
      * @param encoding the encoding type to use, must be DER
      */
      void encode(Pipe& out, X509_Encoding encoding) const;

      bool operator==(EAC1_1_ADO const& rhs) const;

      /**
      * Get the TBS data of this CVC ADO request.
      * @result the TBS data
      */
      SecureVector<byte> tbs_data() const;

      virtual ~EAC1_1_ADO() {}
   private:
      ASN1_Car m_car;
      EAC1_1_Req m_req;

      void force_decode();
      static void decode_info(SharedPtrConverter<DataSource> source,
                              SecureVector<byte> & res_tbs_bits,
                              ECDSA_Signature & res_sig);
   };

inline bool operator!=(EAC1_1_ADO const& lhs, EAC1_1_ADO const& rhs)
   {
   return (!(lhs == rhs));
   }

}

#endif


