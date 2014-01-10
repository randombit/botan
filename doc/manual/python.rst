
Python Binding
========================================

.. highlight:: python

.. note::

   The Python binding should be considered alpha software, and the
   interfaces may change in the future.

Botan includes a binding for Python, implemented using Boost.Python.

As you can see, it is not currently documented, though there are a few
examples under `src/scripts/examples`, such as RSA:

.. literalinclude:: ../../src/scripts/examples/rsa.py

and EAX encryption using a passphrase:

.. literalinclude:: ../../src/scripts/examples/cipher.py
