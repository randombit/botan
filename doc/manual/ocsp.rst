OCSP
========================================

A client makes an OCSP request to what is termed an 'OCSP responder'.
This responder returns a signed response attesting that the
certificate in question has not been revoked. One common way of making
OCSP requests is via HTTP, see :rfc:`2560` Appendix A for details.

.. cpp:class:: OCSP::Request

 .. cpp:function:: OCSP::Request(const X509_Certificate& issuer_cert, \
                                 const X509_Certificate& subject_cert)

      Create a new OCSP request

 .. cpp:function:: std::vector<byte> BER_encode() const

      Encode the current OCSP request as a binary string.

 .. cpp:function:: std::string base64_encode() const

      Encode the current OCSP request as a base64 string.

.. cpp:class:: OCSP::Response

  .. cpp:function:: OCSP::Response(const Certificate_Store& trusted_roots, \
                                   const std::vector<byte>& response)

       Deserializes *response* sent by a responder, and checks that it
       was signed by a certificate associated with one of the CAs
       stored in *trusted_roots*.

  .. cpp:function:: bool affirmative_response_for(const X509_Certificate& issuer, \
                                                  const X509_Certificate& subject) const

      Returns true if and only if this OCSP response is not an error,
      is signed correctly, and the response indicates that *subject*
      is not currently revoked.


.. cpp:function:: OCSP::Response online_check(const X509_Certificate& issuer, \
                                              const X509_Certificate& subject, \
                                              const Certificate_Store* trusted_roots)

      Attempts to contact the OCSP responder specified in the subject certificate
      and 
      
