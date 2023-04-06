PSK Database
======================

.. versionadded:: 2.4.0

Many applications need to store pre-shared keys (hereafter PSKs) for
authentication purposes.

An abstract interface to PSK stores, along with some implementations
of same, are provided in ``psk_db.h``

API Overview
------------

.. container:: toggle

   .. doxygenclass:: Botan::PSK_Database
      :members:

Encrypted PSK Database
----------------------

The same header also provides a specific instantiation of ``PSK_Database`` which
encrypts both names and PSKs. It must be subclassed to provide the storage.

.. container:: toggle

   .. doxygenclass:: Botan::Encrypted_PSK_Database
      :members: Encrypted_PSK_Database,kv_set,kv_get,kv_get_all

A subclass of ``Encrypted_PSK_Database`` which stores data in a SQL database
is also available.

.. container:: toggle

   .. doxygenclass:: Botan::Encrypted_PSK_Database_SQL
      :members: Encrypted_PSK_Database_SQL
