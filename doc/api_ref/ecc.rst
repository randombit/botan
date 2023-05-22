Elliptic Curve Operations
============================

In addition to high level operations for signatures, key agreement,
and message encryption using elliptic curve cryptography, the library
contains lower level interfaces for performing operations such as
elliptic curve point multiplication.

Only curves over prime fields are supported.

Many of these functions take a workspace, either a vector of words or
a vector of BigInts. These are used to minimize memory allocations
during common operations.

.. warning::
   You should only use these interfaces if you know what you are doing.

.. doxygenclass:: Botan::EC_Group
   :members:

.. doxygenclass:: Botan::EC_Point
   :members:



