
#if defined(__x86_64__) && defined(__ILP32__)
  X32

#elif defined(__x86_64__) || defined(_M_X64)
  X86_64

#elif defined(__i386__) || defined(__i386) || defined(_M_IX86)
  X86_32

#elif defined(__aarch64__) || defined(__ARM_ARCH_ISA_A64)
  ARM64

#elif defined(__arm__) || defined(_M_ARM) || defined(__ARM_ARCH_7A__)
  ARM32

#elif defined(__powerpc64__) || defined(__ppc64__) || defined(_ARCH_PPC64)
  PPC64

#elif defined(__powerpc__) || defined(__ppc__) || defined(_ARCH_PPC)

  #if defined(__SPE__)
     POWERPCSPE
  #else
     PPC32
  #endif

#elif defined(__mips__) || defined(__mips)

  #if defined(__LP64__) || defined(_LP64)
  MIPS64
  #else
  MIPS32
  #endif

#elif defined(__sparc__)

  #if defined(__LP64__) || defined(_LP64)
  SPARC64
  #else
  SPARC32
  #endif

#elif defined(__alpha__)
  ALPHA

#elif defined(__hppa__) || defined(__hppa)
  HPPA

#elif defined(__ia64__)
  IA64

#elif defined(__m68k__)
  M68K

#elif defined(__sh__)
  SH

#elif defined(__s390x__)
  S390X

#elif defined(__s390__)
  S390

#elif defined(__riscv)

  #if defined(__LP64__)
     RISCV64
  #else
     RISCV32
  #endif

#else
  UNKNOWN

#endif
