
Build Log
========================================

To report build results (successful or not), email the `development
list <http://lists.randombit.net/mailman/listinfo/botan-devel/>`_ your
results and relevant system information (OS versions, compiler name
and version, CPU architecture and other hardware information,
configuration settings).

Debian reports the build results for 1.8 on `a number of platforms
<http://buildd.debian.org/pkg.cgi?pkg=botan1.8>`_.

===========   =======   ===================   ========================   ============================   ========
Date          Version   OS                    CPU                        Compiler                       Results
===========   =======   ===================   ========================   ============================   ========
2011-05-09    1.9.17    Debian 6.0            Intel Atom D510            GCC 4.4.5                      OK
2010-05-09    1.9.17    Gentoo 10.0           PowerPC G5                 GCC 4.4.5                      OK
2011-05-02    1.9.17    FreeBSD 8.2           x86-64                     GCC 4.2.1                      OK
2011-04-25    1.9.16    Gentoo 10.0           Intel Core i7-860          Clang 2.9                      Miscompiles SSE2 IDEA
2011-04-23    1.9.16    Gentoo 10.0           Intel Core i7-860          Sun C++ 5.10                   OK
2011-04-22    1.9.16    Gentoo 10.0           Intel Core i7-860          Intel C++ 11.1                 OK
2011-04-15    1.9.16    Haiku R1-alpha2       x86                        GCC 4.3.3                      OK
2011-04-15    1.9.16    Haiku R1-alpha2       x86                        GCC 2.95.3                     Can't compile
2011-04-15    1.9.16    Windows 7             x86-64                     Visual C++ 16.00.30319.01      OK
2011-04-15    1.9.16    QNX 6.4.1             i386                       GCC 4.3.3                      OK
2011-03-29    1.9.15    Gentoo 10.0           Intel Core i5-520M         GCC 4.5.2                      OK
2011-03-21    1.9.15    Ark Linux             x86-64                     GCC 4.6.0-pre                  OK
2011-03-21    1.9.15    Ark Linux             x86-32                     GCC 4.6.0-pre                  OK
2011-03-21    1.9.15    Ark Linux             ARM                        GCC 4.6.0-pre                  OK
2011-03-18    1.9.14    Debian 6.0            Intel Atom D510            GCC 4.4.5                      OK
2011-03-01    1.9.14    OpenBSD 4.6           UltraSPARC IIIi            GCC 4.2.4                      OK
2011-03-01    1.9.14    OpenBSD 4.7           i386                       GCC 4.2.4                      OK
2011-03-01    1.9.14    Debian 6.0            Intel Madison IA-64        GCC 4.4.5                      OK
2011-03-01    1.9.14    Ubuntu 9.10           ARM Cortex-A8              GCC 4.4.1                      OK
2011-03-01    1.9.14    Debian 5.0            PowerPC G5/970             GCC 4.3.2                      OK
2011-03-01    1.9.14    Windows 7 x64         Intel Core i5-520M         Visual C++ 15.00.30729.01      OK (32/64)
2011-03-01    1.9.14    Gentoo 10.0           Intel Core i7-860          Open64 4.2.1                   OK
2011-03-01    1.9.14    Gentoo 10.0           Intel Core i7-860          Sun C++ 5.10                   OK
2011-03-01    1.9.14    Gentoo 10.0           Intel Core i7-860          Intel C++ 11.1                 OK
2011-03-01    1.9.14    Gentoo 10.0           Intel Core i7-860          GCC 4.5.2                      OK
2011-02-14    1.9.13    NetBSD 5.1            Intel Xeon P4              GNU GCC 4.1.3                  OK
2011-01-14    1.9.12    FreeBSD 8.1           x86-64                     Clang 2.9                      OK
2010-11-29    1.9.11    Windows 7 x64         Intel Core i5-520M         Visual C++ 15.00.30729.01      OK (32/64)
2010-11-29    1.9.11    Gentoo 10.0           Intel Core i7-860          GNU GCC 4.1.2, 4.4.5, 4.5.1    OK
2010-11-29    1.9.11    Debian 5.0            PowerPC G5/970             GCC 4.3.2                      OK
2010-11-29    1.9.11    Gentoo 10.0           Intel Core i7-860          Intel C++ 11.1                 OK
2010-11-29    1.9.11    Gentoo 10.0           Intel Core i7-860          Clang 2.8                      Miscompiles SSE2 IDEA
2010-11-29    1.9.11    Debian 5.0 (32 bit)   UltraSPARC T1 Niagra       GCC 4.3.2                      OK
2010-09-07    1.9.11    Gentoo 10.0           Intel Core i7-860          Sun C++ 5.10                   OK
2010-08-12    1.9.10    Debian 5.0            Xeon X5450 Harpertown      GCC 4.3.2                      OK
2010-08-12    1.9.10    Ubuntu 9.04           Intel Atom N270            GCC 4.3.3                      OK
2010-08-12    1.9.10    Debian 5.0            Intel Prescott             GCC 4.3.2                      OK
2010-08-08    1.9.10    Gentoo 10.0           Intel Core i7-860          GCC 3.4.6                      OK
2010-08-08    1.9.10    Gentoo 10.0           Intel Core i7-860          GCC 4.1.2                      OK
2010-08-08    1.9.10    Gentoo 10.0           Intel Core i7-860          GCC 4.3.5                      OK
2010-08-08    1.9.10    Gentoo 10.0           Intel Core i7-860          GCC 4.4.4                      OK
2010-08-08    1.9.10    Gentoo 10.0           Intel Core i7-860          GCC 4.5.1                      OK
2010-08-08    1.9.10    Gentoo 10.0           Intel Core i7-860          Clang SVN                      Miscompiles Turing
2010-07-27    1.9.9     Debian 5.0            AMD Magny-Cours            GCC 4.3.2, 4.5.0               OK
2010-06-16    1.9.8     Gentoo 10.0           Intel Core2 Q6600          Intel C++ 11.1                 OK
2010-06-16    1.9.8     Debian 5.0 (32 bit)   UltraSPARC T1 Niagra       GCC 4.3.2                      OK
2010-06-16    1.9.8     Debian 5.0            Intel Madison IA-64        GCC 4.3.2                      OK
2010-06-16    1.9.8     Gentoo 10.0           IBM POWER5+                GCC 4.1.2, 4.2.4, 4.3.2        OK
2010-06-16    1.9.8     OpenBSD 4.6           UltraSPARC IIIi            GCC 3.3.5, 4.2.4               OK
2010-06-16    1.9.8     FreeBSD 8.0           AMD Opteron 252            GCC 4.2.1                      OK
2010-06-16    1.9.8     gNewSense             MIPS Loongson-2 (64)       GCC 4.3.2                      OK
2010-06-16    1.9.8     Ubuntu 9.10           ARM Cortex-A8              GCC 4.4.1                      OK
2010-06-11    1.9.8     Gentoo 10.0           Intel Core2 Q6600          GCC 3.4.6, 4.1.2               OK
2010-06-11    1.9.8     Windows 7 x64         Intel Core i5-520M         Visual C++ 15.00.30729.01      OK (32 and 64 bit)
2010-06-11    1.9.8     Gentoo 10.0           Intel Core i5-520M         GCC 4.5.0                      OK
2010-06-01    1.9.8     OpenBSD 4.7           i386                       GCC 3.3.5                      OK
2010-05-03    1.9.7     Windows 7 x64         Intel Core i5-520M         Visual C++ 15.00.30729.01      OK
2010-04-27    1.9.7     Gentoo 10.0           PPC 970FX (G5)             GCC 4.3.4                      OK
2010-04-27    1.9.7     Gentoo 10.0           Intel Core2 Q6600          GCC 4.4.3, 4.5.0               OK
2010-03-18    1.9.4     Gentoo 10.0           Intel Core2 Q6600          GCC 4.4.3                      OK
2010-03-18    1.9.4     Debian 5.0            UltraSPARC II (64)         GCC 4.3.2                      OK
2010-03-18    1.9.4     Gentoo 10.0           PowerPC G5                 GCC 4.3.4                      OK
2010-03-18    1.9.4     Gentoo 10.0           IBM POWER5+                GCC 4.3.2                      OK
2010-03-15    1.9.4     Windows XP            x86                        Visual C++ 15.00.30729.01      OK
2010-03-10    1.9.4     FreeBSD 8.0           AMD Opteron 252            GCC 4.2.1                      OK, but missing includes
2009-12-29    1.9.4     Debian 4.0            PowerPC G4 7455            GCC 4.1.2                      OK
2009-12-23    1.9.4     Debian 5.0            Xeon X5450 Harpertown      GCC 4.3.2                      OK
2009-11-13    1.9.3     Debian 5.0            UltraSPARC II              GCC 4.3.2                      OK
2009-11-10    1.9.2     Debian 4.0            PowerPC G4                 GCC 4.1.2                      OK
2009-11-03    1.9.2     Debian Linux 4.0      AMD Opteron 8354           GCC 4.4.1                      OK
2009-10-27    1.9.2     Debian Linux 5.0      Xeon X5450 Harpertown      GCC 4.3.2                      OK
2009-10-23    1.9.1     Gentoo Linux          Intel Core2 Q6600          GCC 4.4.1, Intel C++ 11.1      OK
2009-10-23    1.9.1     Gentoo Linux          AMD Opteron 2212           GCC 4.3.4                      OK
2009-09-24    1.9.0     Debian 4.0            AMD Opteron 8354           GCC 4.1.2, 4.4.1               OK
2010-07-01    1.8.9     OpenSUSE 10.3         Intel Core2                GCC 4.2.1                      OK
2010-06-22    1.8.9     Slackware 13.1        Intel E5400 (64)           GCC 4.4.4                      OK
2010-06-22    1.8.9     Slackware 13.1        Pentium-M (32)             GCC 4.4.4                      OK
2010-06-16    1.8.9     Debian 5.0 (32 bit)   UltraSPARC T1 Niagra       GCC 4.3.2 (GCC TR1)            Crashes in GF(p) tests
2010-03-18    1.8.8     Debian 5.0            UltraSPARC II (64)         GCC 4.3.2                      OK
2008-10-23    1.8.7     Gentoo 2008.0         PPC 970FX (G5)             GCC 4.3.4                      OK
2009-10-07    1.8.7     Debian GNU/Hurd 0.3   i686                       GCC 4.3.4                      OK
2009-09-08    1.8.7     Gentoo 2008.0         Intel Core2 Q6600          GCC 4.4.1                      OK
2009-09-04    1.8.6     Gentoo 2008.0         PPC 970FX (G5)             GCC 4.3.4                      OK
2009-08-13    1.8.6     Gentoo 2008.0         Intel Core2 Q6600          GCC 4.3.3                      OK
2009-08-13    1.8.6     Windows XP            x86                        Visual C++ 15.00.30729.01      OK (no TR1)
2009-08-03    1.8.5     openSuSE 10.3         x86                        GCC 4.2.1                      OK
2009-08-03    1.8.5     Gentoo 2008.0         Intel Core2 Q6600          Open64 4.2.1                   BAD: Miscompiles several ciphers
2009-07-31    1.8.5     Solaris 11            x86                        Sun C++ 5.9                    OK, but minor build problems
2009-07-30    1.8.5     Gentoo 2006.1         UltraSPARC IIe (32)        GCC 3.4.6                      OK (no TR1)
2009-07-25    1.8.5     Debian 4.0            AMD Opteron 2212           GCC 4.1.2                      OK
2009-07-23    1.8.5     Gentoo 2008.0         Marvel Feroceon 88FR131    GCC 4.1.2                      OK
2009-07-23    1.8.5     Debian 5.0            Intel Xscale 80219         GCC 4.3.2                      OK
2009-07-23    1.8.5     Debian 5.0            UltraSPARC II (64)         GCC 4.3.2                      OK
2009-07-23    1.8.5     Debian 5.0            UltraSPARC II (32)         GCC 4.3.2                      BAD: bus error in GF(p)
2009-07-23    1.8.5     Debian 5.0            UltraSPARC II (32)         GCC 4.1.3                      BAD: miscompiles BigInt code
2009-07-23    1.8.5     Debian 4.0            PowerPC G4                 GCC 4.1.2                      OK
2009-07-23    1.8.5     Debian 4.0            PowerPC G5                 GCC 4.1.2                      OK
2009-07-23    1.8.5     Debian 5.0            Intel Madison IA-64        GCC 4.1.3, 4.3.2               OK
2009-07-23    1.8.5     Debian 5.0            HP-PA PA8600               GCC 4.3.2                      OK
2009-07-23    1.8.5     Mandriva 2008.1       MIPS Loongson-2 (32)       GCC 4.2.3                      OK
2009-07-23    1.8.5     gNewSense             MIPS Loongson-2 (64)       GCC 4.3.2                      OK
2009-07-21    1.8.5     Windows XP            x86                        Visual C++ 15.00.30729.01      OK (no TR1)
2009-07-21    1.8.5     Gentoo 2008.0         Intel Core2 Q6600          GCC 4.1.2, 4.3.3               OK
2009-07-21    1.8.5     Gentoo 2008.0         Intel Core2 Q6600          Intel C++ 10.1 20080801        OK
2009-07-21    1.8.5     Gentoo 2008.0         AMD Opteron 2212           GCC 4.3.3                      OK
2009-07-21    1.8.5     Ubuntu 8.04           Intel Xeon X5492           GCC 4.2.4                      OK
2009-07-21    1.8.5     MacOS X 10.5.6        Intel Core 2 Duo T5600     GCC 4.0.1                      OK
2009-07-21    1.8.5     Solaris 10            AMD Opteron                GCC 3.4.3                      OK (no TR1)
2008-07-11    1.8.3     Fedora 11             Intel Pentium E5200        GCC 4.4.0                      OK
2008-07-10    1.8.3     Gentoo 2008.0         PPC 970FX (G5)             GCC 4.3.1                      OK
2008-07-10    1.8.3     Gentoo 2008.0         IBM POWER5+                GCC 4.2.2                      OK
2009-07-10    1.8.3     Gentoo 2008.0         AMD Opteron 2212           GCC 4.3.3                      OK
2009-07-10    1.8.3     Ubuntu 8.04           Intel Xeon X5492           GCC 4.2.4                      OK
2009-07-10    1.8.3     MacOS X 10.5.6        Intel Core 2 Duo T5600     GCC 4.0.1                      OK
2009-07-10    1.8.3     Debian 5.0.1          Intel Core 2 Duo T5600     GCC 4.3.2                      OK
2009-07-10    1.8.3     Fedora 10             Intel Core 2 Duo T5600     GCC 4.3.2                      OK
2009-07-10    1.8.3     Solaris 10            AMD Opteron                GCC 3.4.3                      OK (no TR1)
2009-07-09    1.8.3     Gentoo 2008.0         Intel Core2 Q6600          Intel C++ 10.1 20080801        OK
2009-07-02    1.8.3     Gentoo 2008.0         Intel Core2 Q6600          GCC 4.3.3                      OK
2009-07-02    1.8.3     FreeBSD 7.0           x86-64                     GCC 4.2.1                      OK
2009-07-02    1.8.3     Windows XP            x86                        Visual C++ 15.00.30729.01      OK (no TR1)
2008-12-27    1.8.0     Ubuntu 8.04           Pentium 4-M                GCC 4.2.3                      OK
2008-12-14    1.8.0     FreeBSD 7.0           x86-64                     GCC 4.2.1                      OK
2008-12-10    1.8.0     Gentoo 2007.0         Intel Core2 Q6600          GCC 4.1.2, 4.2.4, 4.3.2        OK
2008-12-05    1.7.24    Gentoo 2007.0         Intel Core2 Q6600          GCC 4.1.2, 4.2.4, 4.3.2        OK
2008-12-04    1.7.24    Gentoo 2007.0         Intel Core2 Q6600          Intel 10.1-20080801            OK
2008-12-03    1.7.24    Solaris 10            x86                        GCC 3.4.3                      OK (small patch needed, fixed in 1.8.0)
2008-11-24    1.7.23    Gentoo 2007.0         Intel Core2 Q6600          GCC 4.1.2                      OK
2008-11-24    1.7.23    Gentoo 2007.0         Intel Core2 Q6600          GCC 4.2.4                      OK
2008-11-24    1.7.23    Gentoo 2007.0         Intel Core2 Q6600          GCC 4.3.2                      OK
2008-11-24    1.7.23    Gentoo 2007.0         Intel Core2 Q6600          GCC 4.4-20081017               OK
2008-11-24    1.7.23    Gentoo 2007.0         Intel Core2 Q6600 (32)     GCC 4.1.2, 4.2.4               OK
2008-11-24    1.7.23    Gentoo 2007.0         Intel Core2 Q6600 (32)     GCC 4.3.2                      OK (with Boost 1.35 TR1)
2008-11-24    1.7.23    Gentoo 2007.0         Intel Core2 Q6600 (32)     GCC 4.3.2                      Crashes (with libstdc++ TR1)
2008-11-24    1.7.23    Gentoo 2007.0         Intel Core2 Q6600          Intel C++ 9.1-20061101         OK
2008-11-24    1.7.23    Gentoo 2007.0         Intel Core2 Q6600          Intel C++ 10.1-20080801        OK
2008-11-24    1.7.23    Fedora 8              STI Cell PPU               GCC 4.1.2                      OK
2008-11-24    1.7.23    Fedora 8              STI Cell PPU               IBM XLC for Cell 0.9           45 minute link. Miscompiles DES
2008-11-24    1.7.23    Gentoo 2007.0         IBM POWER5+                GCC 4.1.2, 4.2.2, 4.3.1        OK
2008-11-24    1.7.23    Gentoo 2007.0         AMD Opteron 2212           GCC 3.3.6, 4.1.2, 4.3.2        OK (no TR1 with 3.3.6)
2008-11-24    1.7.23    Windows XP            x86                        Visual C++ 15.00.30729.01      OK (no TR1)
2008-11-09    1.7.20    Gentoo 2007.0         IBM POWER5+                GCC 4.1.2                      OK
2008-11-09    1.7.20    Gentoo 2007.0         Intel Core2 Q6600          GCC 4.3.2                      OK
2008-11-09    1.7.20    Windows XP            x86                        Visual C++ 15.00.30729.01      OK
2008-11-06    1.7.19    Gentoo 2007.0         IBM POWER5+                GCC 4.1.2                      OK
2008-11-06    1.7.19    Gentoo 2007.0         Intel Core2 Q6600          GCC 4.1.2, 4.3.1               OK
2008-11-06    1.7.19    Gentoo 2007.0         Intel Core2 Q6600          Intel C++ 9.1-20061101         OK
2008-11-06    1.7.19    Gentoo 2007.0         Intel Core2 Q6600          Intel C++ 10.1-20080801        OK
2008-11-06    1.7.19    Windows XP            x86                        Visual C++ 15.00.30729.01      OK
2008-11-03    1.7.19    FreeBSD 7.0           x86-64                     GCC 4.2.1                      OK
2008-10-24    1.7.18    Gentoo 2007.0         IBM POWER5+                GCC 4.2.2, 4.3.1               OK
2008-10-24    1.7.18    Fedora 8              STI Cell PPU               GCC 4.1.2                      OK
2008-10-22    1.7.18    Windows XP            Pentium 4-M                GCC 3.4.5 (MinGW)              OK
2008-10-22    1.7.18    Windows XP            Pentium 4-M                Visual C++ 15.00.30729.01      OK
2008-10-22    1.7.18    Gentoo 2007.0         IBM POWER5+                GCC 4.1.2                      OK
2008-10-22    1.7.18    Gentoo 2007.0         Intel Core2 Q6600          GCC 4.1.2, 4.2.4, 4.3.2        OK
2008-10-22    1.7.18    Gentoo 2007.0         Intel Core2 Q6600          Intel C++ 9.1-20061101         OK
2008-10-22    1.7.18    Gentoo 2007.0         Intel Core2 Q6600          Intel C++ 10.1-20080801        OK
2008-10-07    1.7.15    Gentoo 2007.0         IBM POWER5+                GCC 4.1.2                      OK
2008-10-07    1.7.15    Gentoo 2007.0         Intel Core2 Q6600          GCC 4.3.1                      OK
2008-09-30    1.7.14    Gentoo 2007.0         PPC 970FX (G5)             GCC 4.3.1                      OK
2008-09-30    1.7.14    Gentoo 2007.0         IBM POWER5+                GCC 4.1.2                      OK
2008-09-30    1.7.14    Gentoo 2007.0         Intel Core2 Q6600          GCC 4.3.1                      OK
2008-09-30    1.7.14    Gentoo 2007.0         Intel Core2 Q6600          Intel C++ 10.1.018             OK
2008-09-30    1.7.14    Windows XP            Pentium 4-M                Visual C++ 15.00.30729.01      OK
2008-09-30    1.7.14    Windows XP            Pentium 4-M                GCC 3.4.5 (MinGW)              OK
2008-09-18    1.7.12    Gentoo 2007.0         IBM POWER5+                GCC 4.1.2, 4.2.2               OK
2008-09-18    1.7.12    Gentoo 2007.0         Intel Core2 Q6600          GCC 4.2.4, 4.3.1               OK
2008-09-18    1.7.12    Gentoo 2007.0         Intel Core2 Q6600          Intel C++ 10.1.018             OK
2008-09-18    1.7.12    Windows XP            Pentium 4-M                Visual C++ 15.00.30729.01      OK
2008-09-18    1.7.12    Windows XP            Pentium 4-M                GCC 3.4.5 (MinGW)              OK
2008-09-16    1.7.12    Fedora 7              STI Cell PPU               GCC 4.1.2                      OK
2008-09-16    1.7.11    MacOS X 10.4 (32)     Intel Core2                GCC 4.0.1                      OK
2008-09-11    1.7.11    Gentoo 2007.0         Intel Core2 Q6600          GCC 4.3.1                      OK
2008-09-11    1.7.11    Windows XP            Pentium 4-M                Visual C++ 15.00.30729.01      OK
2008-09-08    1.7.9     Gentoo 2007.0         Intel Core2 Q6600          Intel C++ 10.1.018             OK
2008-08-28    1.7.9     Gentoo 2007.0         IBM POWER5+                GCC 4.1.2                      OK
2008-08-28    1.7.9     Gentoo 2007.0         IBM POWER5+                GCC 4.2.2                      OK
2008-08-28    1.7.9     Gentoo 2007.0         IBM POWER5+                GCC 4.3.1                      OK
2008-08-28    1.7.9     Gentoo                STI Cell PPU               GCC 4.1.2                      OK
2008-08-27    1.7.9     Gentoo                Intel Core2 Q6600          GCC 4.1.2                      OK
2008-08-27    1.7.9     Gentoo                Intel Core2 Q6600          GCC 4.2.4                      OK
2008-08-27    1.7.9     Gentoo                Intel Core2 Q6600          GCC 4.3.1                      OK
2008-08-27    1.7.9     Gentoo                Intel Core2 Q6600          GCC 4.4-20080822               OK
2008-08-27    1.7.9     Gentoo                Intel Core2 Q6600          Intel C++ 9.1-20061101         OK
2008-08-27    1.7.9     Gentoo                Intel Core2 Q6600          Intel C++ 10.1-20080602        OK
2008-08-27    1.7.9     Windows XP            Pentium 4-M                Visual C++ 2008                OK
2008-08-27    1.7.9     Windows XP            Pentium 4-M                GCC 3.4.5 (MinGW)              OK
2008-08-18    1.7.8     Ubuntu 8.04           Pentium 4-M                GCC 4.2.3                      OK
2008-08-18    1.7.8     Windows XP            Pentium 4-M                Visual C++ 2008                OK
2008-08-18    1.7.8     Windows XP            Pentium 4-M                GCC 3.4.5 (MinGW)              OK
2008-07-18    1.7.8     Gentoo                IBM POWER5+                GCC 4.1.2                      OK
2008-07-15    1.7.8     Gentoo                Intel Core2 Q6600          GCC 4.3.1                      OK
2008-07-06    1.7.7     Gentoo                Intel Core2 Q6600          PGI 7.2                        Miscompiles TEA, Turing, BigInt
2008-06-28    1.7.7     Gentoo                Pentium 4-M                GCC 4.1.2                      OK
2008-06-28    1.7.7     Gentoo                Intel Core2 Q6600          GCC 4.1.2, 4.2.4, 4.3.1        OK
2008-06-28    1.7.7     Gentoo                Intel Core2 Q6600          Intel C++ 10.1                 OK
2008-06-28    1.7.7     Gentoo                IBM POWER5+                GCC 4.1.2, 4.2.2               OK
2008-06-25    1.7.6     Gentoo                IBM POWER5+                GCC 4.1.2, 4.2.2               OK
2008-06-09    1.7.6     Gentoo                PPC 970FX (G5)             GCC 4.1.2                      OK
2008-05-14    1.7.6     Gentoo                Intel Core2 Q6600          Intel C++ 9.1                  Builds, but link problems
2008-05-14    1.7.6     Gentoo                Intel Core2 Q6600          GCC 4.2.3                      OK
2008-04-21    1.7.5     Gentoo                STI Cell PPU               GCC 4.1.2                      OK
2008-04-14    1.7.5     Debian                Pentium 4                  GCC 4.1.2                      OK
2008-04-13    1.7.5     Gentoo 2006.1         UltraSPARC II (32)         GCC 3.4.6                      OK
2008-04-12    1.7.5     RHEL3                 Pentium 4 Xeon             GCC 3.2.3                      OK
2008-04-12    1.7.5     Gentoo                Intel Core2 Q6600          Intel C++ 10.1                 OK
2008-04-12    1.7.5     Gentoo                AMD Opteron 2212           GCC 4.1.2                      OK
2008-04-12    1.7.5     Gentoo                Intel Core2 Q6600          GCC 4.2.3                      OK
2008-09-16    1.6.5     MacOS X 10.4          Intel Core2 (32)           GCC 4.0.1                      OK
2008-08-28    1.6.5     Gentoo 2007.0         IBM POWER5+                GCC 4.1.2, 4.2.2, 4.3.1        OK
2008-08-27    1.6.5     Gentoo                Intel Core2 Q6600          GCC 4.3.1, 4.4-20080822        OK
2008-08-18    1.6.4     Windows XP            Pentium 4-M                Visual C++ 2008                OK
2008-07-02    1.6.4     Solaris 10            x86-64                     Sun Forte 12                   OK
===========   =======   ===================   ========================   ============================   ========
