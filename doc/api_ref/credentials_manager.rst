
Credentials Manager
==================================================

A ``Credentials_Manager`` is a way to abstract how the application
stores credentials. The main user is the :doc:`tls` implementation.

Certificate-based Authentication
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``Credentials_Manager`` provides hooks for applications to control the
certificates used in TLS. Both for authenticating themselves and to define the
trusted certificate authorities.

API Overview
~~~~~~~~~~~~

.. container:: toggle

   .. doxygenclass:: Botan::Credentials_Manager
      :members: trusted_certificate_authorities,find_cert_chain,cert_chain,cert_chain_single_type,private_key_for

Preshared Keys
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

TLS supports the use of pre shared keys for authentication. Note that in
Botan 3.0 we support PSK based authentication in TLS 1.2 only. Support for
TLS 1.3 might come in a later release. Using the ``Credentials_Manager``
applications can define the PSK secret to be used.

API Overview
~~~~~~~~~~~~

.. container:: toggle

   .. doxygenclass:: Botan::Credentials_Manager
      :members: psk,psk_identity_hint,psk_identity
      :no-link:
