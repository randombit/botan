/*
* EAC1_1 CVC Request
* (C) 2008 Falko Strenzke
*          strenzke@flexsecure.de
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_EAC_CVC_REQ_H__
#define BOTAN_EAC_CVC_REQ_H__

#include <botan/x509_key.h>
#include <botan/pubkey_enums.h>
#include <botan/cvc_gen_cert.h>
#include <botan/cvc_req.h>

namespace Botan {

/**
* This class represents TR03110 v1.1 EAC CV Certificate Requests.
*/
class BOTAN_DLL EAC1_1_Req : public EAC1_1_gen_CVC<EAC1_1_Req>
   {
   public:
      friend class EAC1_1_Req_CA;
      friend class EAC1_1_ADO;
      friend class EAC1_1_obj<EAC1_1_Req>;

      /**
      * Compare for equality with other
      * @param other compare for equality with this object
      */
      bool operator==(const EAC1_1_Req& other) const;

      /**
      * Construct a CVC request from a data source.
      * @param source the data source
      */
      EAC1_1_Req(std::tr1::shared_ptr<DataSource> source);

      /**
      * Construct a CVC request from a DER encoded CVC reqeust file.
      * @param str the path to the DER encoded file
      */
      EAC1_1_Req(const std::string& str);

      virtual ~EAC1_1_Req(){}
   private:
      void force_decode();
      EAC1_1_Req() {}
   };

/*
* Comparison Operator
*/
inline bool operator!=(EAC1_1_Req const& lhs, EAC1_1_Req const& rhs)
   {
   return !(lhs == rhs);
   }

}

#endif
