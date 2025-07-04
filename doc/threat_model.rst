
Threat Model
=====================

It is somewhat difficult to fully articulate a threat model for any library since it may
be used in different contexts. However, this document attempts to clearly state which
attackers are considered in-scope (and thus which countermeasures are in place), and which
are not.

The basic threat model Botan is written for is described well in "The Program Counter
Security Model" (Molnar, Piotrowski, Schultz, Wagner).

We assume an attacker exists who is capable of colocating their attack code on the same
CPU (eg via SMT) and performing analysis based on side channels in cache, TLB or branch
predictor resources. A somewhat stronger model is in the context of SGX enclaves, where it
is practical for an attacker to cause code in an SGX enclave to single-step the execution
and precisely measure each conditional jump and memory access.

This also covers the (weaker) threat model of an attacker on the same LAN who is
performing attacks based purely on timing of operations.

Wherever possible, code that manipulates secret data (for example when generating an ECDSA
signature or decrypting an AES ciphertext) is written to be "constant time"; avoiding any
conditional jumps or memory accesses where the predicate is (derived from) secret
information. Botan uses extensive annotations (``CT::poison``) to indicate which values
are secret, and uses automated analysis (currently using ``valgrind``, though support for
other tools is welcome) to verify that the assembly created by the compiler in fact avoids
all conditional jumps. This testing step is essential as some compilers (notably Clang)
are excellent at performing range analysis of values and will sometimes generate
conditional jumps even when the code as written appears to avoid such operations.  Botan's
CI runs these tests automatically against GCC and Clang on x86-64 and aarch64, with a
range of different optimization levels.

Some algorithms have a structure which allows for very practical blinding/re-randomization
of the operations. This is used as an additional countermeasure in case some particular
combination of compiler, compiler options, and target architecture results in a
conditional jump being inserted in an unexpected place. For example during ECDSA signing,
the inversion of ``k``, the scalar multiplication of ``g*k`` and the recombination of
``x * r + m`` are all blinded, even though all of the relevant arithmetic operations are
written and tested to avoid side channels.

For more about specific side channel countermeasures, see :ref:`side_channels`.

Out Of Scope
-----------------

* Attacks based on ALU side channels (such as contention on the multiplication unit
  leaking the Hamming weight of the multiplier) are currently out of scope, though
  randomized blinding may be helpful in some circumstances.

* Power analysis attacks and EM side channel attacks are considered out of scope.
  Preventing these attacks requires hardware support and a system-wide view of how leakage
  is handled. That said, patches which make it easier to use Botan in a system which must
  address these issues would be accepted.
