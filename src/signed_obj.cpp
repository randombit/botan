/*************************************************
* X.509 SIGNED Object Source File                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/x509_obj.h>
#include <botan/x509_key.h>
#include <botan/look_pk.h>
#include <botan/oids.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/parsing.h>
#include <botan/pem.h>
#include <algorithm>
#include <botan/pointers.h>
#include <iostream>
namespace Botan {


/*************************************************
* Return a BER encoded X.509 object              *
*************************************************/
    SecureVector<byte> Signed_Object::BER_encode() const
    {
        Pipe ber;
        ber.start_msg();
        encode(ber, RAW_BER);
        ber.end_msg();
        return ber.read_all();
    }

/*************************************************
* Return a PEM encoded X.509 object              *
*************************************************/
    std::string Signed_Object::PEM_encode() const
    {
        Pipe pem;
        pem.start_msg();
        encode(pem, PEM);
        pem.end_msg();
        return pem.read_all_as_string();
    }


/*************************************************
* Return the algorithm used to sign this object  *
*************************************************/
    AlgorithmIdentifier Signed_Object::signature_algorithm() const
    {
        return sig_algo;
    }


/*************************************************
* Try to decode the actual information           *
*************************************************/
            void Signed_Object::do_decode()
            {
                try {
                    force_decode();
                }
                catch(Decoding_Error& e)
                {
                    const std::string what = e.what();
                    throw Decoding_Error(PEM_label_pref + " decoding failed (" +
                            what.substr(23, std::string::npos) + ")");
                }
                catch(Invalid_Argument& e)
                {
                    const std::string what = e.what();
                    throw Decoding_Error(PEM_label_pref + " decoding failed (" +
                            what.substr(7, std::string::npos) + ")");
                }
            }

}
