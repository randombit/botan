=================================
libsodium Compatible Interfaces
=================================

To ease transitions, Botan includes an interface compatible with libsodium in
``sodium.h``. All declarations are in the ``Botan::Sodium`` namespace but
otherwise are named as and should act like their equivalents in libsodium.

The functions are not documented here since we don't recommend using them
generally; consult the libsodium documentation instead.

The implementation of the compatibility shim, in ``src/lib/compat/sodium``, may
prove a useful reference if you wish to remove uses of the sodium API and
instead use the native Botan APIs.
