
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

.. c:macro:: BOTAN_VERSION_MAJOR

   The major version of the release.

.. c:macro:: BOTAN_VERSION_MINOR

   The minor version of the release.

.. c:macro:: BOTAN_VERSION_PATCH

   The patch version of the release.

.. c:macro:: BOTAN_VERSION_DATESTAMP

   Expands to an integer of the form YYYYMMDD if this is an official
   release, or 0 otherwise. For instance, 1.10.1, which was released
   on July 11, 2011, has a `BOTAN_VERSION_DATESTAMP` of 20110711.

.. c:macro:: BOTAN_DISTRIBUTION_INFO

   .. versionadded:: 1.9.3

   A macro expanding to a string that is set at build time using the
   ``--distribution-info`` option. It allows a packager of the library
   to specify any distribution-specific patches. If no value is given
   at build time, the value is the string "unspecified".

.. c:macro:: BOTAN_VERSION_VC_REVISION

   .. versionadded:: 1.10.1

   A macro expanding to a string that is set to a revision identifier
   corresponding to the source, or "unknown" if this could not be
   determined. It is set for all official releases, and for builds that
   originated from within a git checkout.

The runtime version information, and some helpers for compile time
version checks, are included in `botan/version.h`

.. cpp:function:: std::string version_string()

   Returns a single-line string containing relevant information about
   this build and version of the library in an unspecified format.

.. cpp:function:: uint32_t version_major()

   Returns the major part of the version.

.. cpp:function:: uint32_t version_minor()

   Returns the minor part of the version.

.. cpp:function:: uint32_t version_patch()

   Returns the patch part of the version.

.. cpp:function:: uint32_t version_datestamp()

   Return the datestamp of the release (or 0 if the current version is
   not an official release).

.. cpp:function:: std::string runtime_version_check(uint32_t major, uint32_t minor, uint32_t patch)

   Call this function with the compile-time version being built against, eg::

      Botan::runtime_version_check(BOTAN_VERSION_MAJOR, BOTAN_VERSION_MINOR, BOTAN_VERSION_PATCH)

   It will return an empty string if the versions match, or otherwise
   an error message indicating the discrepancy. This only is useful in
   dynamic libraries, where it is possible to compile and run against
   different versions.

.. c:macro:: BOTAN_VERSION_CODE_FOR(maj,min,patch)

   Return a value that can be used to compare versions. The current
   (compile-time) version is available as the macro
   `BOTAN_VERSION_CODE`. For instance, to choose one code path for
   version 2.1.0 and later, and another code path for older releases::

      #if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(2,1,0)
         // 2.1+ code path
      #else
         // code path for older versions
      #endif

