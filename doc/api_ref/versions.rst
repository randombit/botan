
.. _versioning:

Versioning
========================================

All versions are of the tuple (major,minor,patch).

As of Botan 2.0.0, Botan uses semantic versioning. The minor number increases if
any feature addition is made. The patch version is used to indicate a release
where only bug fixes were applied. If an incompatible API change is required,
the major version will be increased.

The library has functions for checking compile-time and runtime versions.

The build-time version information is defined in ``botan/build.h``

.. c:macro:: BOTAN_VERSION_MAJOR

   The major version of the release.

.. c:macro:: BOTAN_VERSION_MINOR

   The minor version of the release.

.. c:macro:: BOTAN_VERSION_PATCH

   The patch version of the release.

.. c:macro:: BOTAN_VERSION_DATESTAMP

   Expands to an integer of the form YYYYMMDD if this is an official
   release, or 0 otherwise. For instance, 3.6.1, which was released
   on October 26, 2024, has a ``BOTAN_VERSION_DATESTAMP`` of 20241026.

   .. warning::

      This macro is deprecated and will be removed in Botan4. Use
      :cpp:func:`version_datestamp`

.. c:macro:: BOTAN_DISTRIBUTION_INFO

   .. versionadded:: 1.9.3

   A macro expanding to a string that is set at build time using the
   ``--distribution-info`` option. It allows a packager of the library
   to specify any distribution-specific patches. If no value is given
   at build time, the value is the string "unspecified".

   .. warning::

      This macro is deprecated and will be removed in Botan4. Use
      :cpp:func:`version_distribution_info`

.. c:macro:: BOTAN_VERSION_VC_REVISION

   .. versionadded:: 1.10.1

   A macro expanding to a string that is set to a revision identifier
   corresponding to the source, or "unknown" if this could not be
   determined. It is set for all official releases.

   .. warning::

      This macro is deprecated and will be removed in Botan4. Use
      :cpp:func:`version_vc_revision`

The runtime version information, and some helpers for compile time
version checks, are included in ``botan/version.h``

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

.. cpp:function:: std::optional<std::string> version_vc_revision()

   .. versionadded:: 3.8

   Returns a string that is set to a revision identifier corresponding to the
   source, or ``nullopt`` if this could not be determined. It is set for all
   official releases, and for builds that originated from within a git checkout.

.. cpp:function:: std::optional<std::string> version_distribution_info()

   .. versionadded:: 3.8

   Return any string that is set at build time using the ``--distribution-info``
   option. It allows a packager of the library to specify any distribution-specific
   patches. If no value is given at build time, returns ``nullopt``.

.. c:macro:: BOTAN_VERSION_CODE_FOR(maj,min,patch)

   Return a value that can be used to compare versions. The current
   (compile-time) version is available as the macro
   ``BOTAN_VERSION_CODE``. For instance, to choose one code path for
   version 3.4.0 and later, and another code path for older releases::

      #if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(3,4,0)
         // 3.4+ code path
      #else
         // code path for older versions
      #endif

