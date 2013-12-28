
Python Binding
========================================

.. highlight:: python

.. note::

   The Python binding should be considered alpha software, and the
   interfaces may change in the future.

Botan includes a binding for Python, implemented using Boost.Python.

As you can see, it is not currently documented, though there are a few
examples under `examples/python`, such as RSA

.. literalinclude:: examples/python/rsa.py

and EAX encryption using a passphrase:

.. literalinclude:: examples/python/cipher.py
