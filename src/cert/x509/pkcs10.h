/*
* PKCS #10
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PKCS10_H__
#define BOTAN_PKCS10_H__

#include <botan/x509_obj.h>
#include <botan/pkcs8.h>
#include <botan/datastor.h>
#include <vector>

namespace Botan {

/**
* PKCS #10 Certificate Request.
*/
class BOTAN_DLL PKCS10_Request : public X509_Object
   {
   public:
      /**
      * Get the subject public key.
      * @return the subject public key
      */
      Public_Key* subject_public_key() const;

      /**
      * Get the raw DER encoded public key.
      * @return the raw DER encoded public key
      */
      MemoryVector<byte> raw_public_key() const;

      /**
      * Get the subject DN.
      * @return the subject DN
      */
      X509_DN subject_dn() const;

      /**
      * Get the subject alternative name.
      * @return the subject alternative name.
      */
      AlternativeName subject_alt_name() const;

      /**
      * Get the key constraints for the key associated with this
      * PKCS#10 object.
      * @return the key constraints
      */
      Key_Constraints constraints() const;

      /**
      * Get the extendend key constraints (if any).
      * @return the extended key constraints
      */
      std::vector<OID> ex_constraints() const;

      /**
      * Find out whether this is a CA request.
      * @result true if it is a CA request, false otherwise.
      */
      bool is_CA() const;

      /**
      * Return the constraint on the path length defined
      * in the BasicConstraints extension.
      * @return the path limit
      */
      u32bit path_limit() const;

      /**
      * Get the challenge password for this request
      * @return the challenge password for this request
      */
      std::string challenge_password() const;

      /**
      * Create a PKCS#10 Request from a data source.
      * @param source the data source providing the DER encoded request
      */
      PKCS10_Request(DataSource& source);

      /**
      * Create a PKCS#10 Request from a file.
      * @param filename the name of the file containing the DER or PEM
      * encoded request file
      */
      PKCS10_Request(const std::string& filename);
   private:
      void force_decode();
      void handle_attribute(const Attribute&);

      Data_Store info;
   };

}

#endif
