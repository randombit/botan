
.. _versioning:

Versioning
========================================

All versions are of the tuple (major,minor,patch).

As of Botan 2.0.0, Botan uses semantic versioning. The minor number increases if
any feature addition is made. The patch version is used to indicate a release
where only bug fixes were applied. If an incompatible API change is required,
the major version will be increased.

The library has functions for checking compile-time and runtime versions.

The build-time version information is defined in `botan/build.h`

.. doxygendefine:: BOTAN_VERSION_MAJOR

.. doxygendefine:: BOTAN_VERSION_MINOR

.. doxygendefine:: BOTAN_VERSION_PATCH

.. doxygendefine:: BOTAN_VERSION_DATESTAMP

.. doxygendefine:: BOTAN_DISTRIBUTION_INFO

.. doxygendefine:: BOTAN_VERSION_VC_REVISION

The runtime version information, and some helpers for compile time
version checks, are included in `botan/version.h`

.. doxygenfunction:: Botan::version_string

.. doxygenfunction:: Botan::version_major

.. doxygenfunction:: Botan::version_minor

.. doxygenfunction:: Botan::version_patch

.. doxygenfunction:: Botan::version_datestamp

.. doxygenfunction:: Botan::runtime_version_check

.. doxygendefine:: BOTAN_VERSION_CODE_FOR
