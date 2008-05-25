/*************************************************
* X.509 SIGNED Object Header File                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_SIGNED_OBJECT_H__
#define BOTAN_SIGNED_OBJECT_H__

#include <botan/asn1_obj.h>
#include <botan/pipe.h>
#include <vector>

namespace Botan {

/*************************************************
    * Generic SIGNED Object                    *
*************************************************/
    class Signed_Object
    {
        public:
            virtual SecureVector<byte> tbs_data() const = 0;
            virtual SecureVector<byte> get_concat_sig() const = 0;  // NOTE: this is here
                                                            // only because abstract
                                                            // signature objects have
                                                            // not yet been introduced
            /**
            * Get the signature algorithm identifier used to sign this object.
            * @result the signature algorithm identifier
            */
            AlgorithmIdentifier signature_algorithm() const;

            virtual bool check_signature(class Public_Key&) const = 0;
            virtual void encode(Pipe&, X509_Encoding = PEM) const = 0;
            SecureVector<byte> BER_encode() const;
            std::string PEM_encode() const;

            Signed_Object(SharedPtrConverter<DataSource>, const std::string&);
            Signed_Object(const std::string&, const std::string&);
            virtual ~Signed_Object() {}
        protected:
            void do_decode();
            Signed_Object() {}
            AlgorithmIdentifier sig_algo;
            SecureVector<byte> tbs_bits;
            std::string PEM_label_pref;
            std::vector<std::string> PEM_labels_allowed;
        private:

            virtual void force_decode() = 0;

    };

}

#endif
