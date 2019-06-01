
ABI Stability
====================

Botan uses semantic versioning for the API; if API features are added the minor
version increases, whereas if API compatibility breaks occur the major version
is increased.

However no guarantees about ABI are made between releases. Maintaining an ABI
compatible release in a complex C++ API is exceedingly expensive in development
time; just adding a single member variable or virtual function is enough to
cause ABI issues.

If ABI changes, the soname revision will increase to prevent applications from
linking against a potentially incompatible version at runtime.

If you are concerned about long-term ABI issues, considering using the C API
instead; this subset *is* ABI stable.

You can review a report on ABI changes to Botan at
https://abi-laboratory.pro/tracker/timeline/botan/
