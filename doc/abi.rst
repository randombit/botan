
API/ABI Stability
====================

API of release branches is stable; that is to say code that compiles and works
against 2.0.0 should also compile with all later 2.x.x versions. The API on
master is completely fair game and may change at any time.

Maintaining a consistent ABI while evolving a complex C++ API is exceedingly
expensive in development time. It is likely ABI breakage will occur at least
occasionally even in release branches. In these cases, the soname revision will
increase to prevent applications from linking against a potentially incompatible
version at runtime.

You can review a report on ABI changes to Botan at
https://abi-laboratory.pro/tracker/timeline/botan/
