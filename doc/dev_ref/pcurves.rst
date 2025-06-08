Custom Elliptic Curve
===================================

Some products or protocols use custom designed (or even classified) elliptic
curve parameters.

The default way of supporting curves like this is to use the constructor of
``EC_Group`` which accepts the various parameters as integers. This uses the
generic elliptic curve logic, which is already reasonably fast.

However in certain cases the best possible performance is required, perhaps
because the hardware it is being deployed on is old/underpowered. The library
provides an escape hatch to support this, where a custom curve is supported
using the same curve-specific logic as used to implement common curves like
P-256.

.. warning::

   This process is documented for convenience but NOT OFFICIALLY SUPPORTED.
   If you need to use this, please consider the life choices that brought you
   to this point.

The groups supported by the library are specified in a file
``src/build-data/ec_groups.txt``, which contains entries like

.. code-block:: text

   Name = secp256r1
   OID = 1.2.840.10045.3.1.7
   Impl = pcurve generic legacy
   P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
   A = -3
   B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
   X = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
   Y = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
   N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

.. note::

   Not all curve parameters can be supported by this process. In particular,
   it is required that

   1) The prime field is between 192 and 512 bits, and a multiple of 32 bits.
   2) The prime must be congruent to 3 modulo 4.
   3) The group order must have the same bit length as the prime.
   4) The group must be prime order; no cofactors are allowed.

To add a new curve with curve specific optimizations, do the following:

1) Add a new block to ``ec_groups.txt`` specifying the parameters. The
   important value is that ``Impl`` contains ``pcurve``. If you only want to
   support the group using the new dedicated implementation that will be
   generated in a later step, you can skip ``generic`` and ``legacy`` here.

2) Add the OID to ``src/build-data/oids.txt`` in the ``[ecc_param]`` block - the
   OID name should match the value of ``Name`` in ``ec_groups.txt``

3) Run ``./src/scripts/dev_tools/gen_ec_groups.py``. This script requires the
   Jinja2 template library, and the program ``addchain`` from
   https://github.com/mmcloughlin/addchain

4) Run ``./src/scripts/dev_tools/gen_oids.py`` to regenerate the OID lookup table
