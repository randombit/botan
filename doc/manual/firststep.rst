
Getting Started
========================================

All declarations in the library are contained within the namespace
``Botan``, so you need to either prefix types with ``Botan::`` or add
a ``using`` declaration in your code. All examples will assume a
``using`` declaration.

All library headers are included like so::

  #include <botan/auto_rng.h>

Pitfalls
----------------------------------------

Use a ``try``/``catch`` block inside your ``main`` function, and catch
any ``std::exception`` throws (remember to catch by reference, as
``std::exception::what`` is polymorphic)::

  int main()
     {
     try
        {
        LibraryInitializer init;

        // ...
        }
     catch(std::exception& e)
        {
        std::cerr << e.what() << "\n";
        }
     }

This is not strictly required, but if you don't, and Botan throws an
exception, the runtime will call ``std::terminate``, which usually
calls ``abort`` or something like it, leaving you (or worse, a user of
your application) wondering what went wrong.
