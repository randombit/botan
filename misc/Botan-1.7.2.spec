# Botan base spec file

# Note that some of the commands in here assume a GNU toolset, which is
# unfortunate and should probably be fixed.

##################################################
# Version numbers and config options             #
##################################################
%define MAJOR 1
%define MINOR 7
%define PATCH 2

%define ONLY_BASE_MODS 0

##################################################
# Hardware restrictions on various modules       #
##################################################
%define USE_TM_HARD i586 i686 athlon x86_64 ppc ppc64 alpha sparcv9 sparc64
%define MP64_ARCH    alpha ppc64 ia64 sparc64

##################################################
# Module settings                                #
##################################################
%define BASE_MODS alloc_mmap,ml_unix,es_egd,es_ftw,es_unix,fd_unix,tm_unix
%define EXTRA_MODS comp_bzip2,comp_zlib,mux_pthr,tm_posix,eng_gmp

%ifarch %{USE_TM_HARD}
  %{expand: %%define EXTRA_MODS %{EXTRA_MODS},tm_hard}
%endif

%ifarch %{USE_MP64}
  %{expand: %%define EXTRA_MODS %{EXTRA_MODS},mp_asm64}
%endif

%ifarch x86
  %{expand: %%define EXTRA_MODS %{EXTRA_MODS},mp_ia32,alg_ia32}
%endif

%ifarch x86_64
  %{expand: %%define EXTRA_MODS %{EXTRA_MODS},mp_amd64,alg_amd64}
%endif

%if %{ONLY_BASE_MODS}
  %define MODULES %{BASE_MODS}
%else
  %define MODULES %{BASE_MODS},%{EXTRA_MODS}
%endif

##################################################
# Descriptions                                   #
##################################################
%define VERSION %{MAJOR}.%{MINOR}.%{PATCH}

Name: Botan
Summary: A C++ crypto library
Version: %{VERSION}
Release: 1
License: BSD
Group: System Environment/Libraries
Source: http://botan.randombit.net/files/%{name}-%{VERSION}.tgz
URL: http://botan.randombit.net/
Packager: Jack Lloyd <lloyd@randombit.net>
Prefix: /usr
BuildRequires: perl make

%if ! %{ONLY_BASE_MODS}
Requires: zlib, bzip2 >= 1.0.2, gmp >= 4.1
BuildRequires: zlib-devel, bzip2-devel >= 1.0.2, gmp-devel >= 4.1
%endif

BuildRoot: %{_tmppath}/%{name}-%{version}-root

%description
Botan is a C++ library which provides support for many common
cryptographic operations, including encryption, authentication, and
X.509v3 certificates and CRLs. A wide variety of algorithms is
supported, including RSA, DSA, DES, AES, MD5, and SHA-1.

%package devel
Summary: Development files for Botan
Group: Development/Libraries
Requires: Botan = %{VERSION}
%description devel
This package contains the header files and libraries needed to develop
programs that use the Botan library.

##################################################
# Main Logic                                     #
##################################################
%prep
%setup -n Botan-%{VERSION}

%build
./configure.pl --noauto --modules=%{MODULES} gcc-%{_target_os}-%{_target_cpu}
make shared static

%clean
rm -rf $RPM_BUILD_ROOT

%install
ROOT="$RPM_BUILD_ROOT/usr"
make OWNER=`id -u` GROUP=`id -g` INSTALLROOT="$ROOT" install

# Need this since we're installing shared libs...
%post
if ! grep "^$RPM_INSTALL_PREFIX/lib$" /etc/ld.so.conf 2>&1 >/dev/null
then
   echo "$RPM_INSTALL_PREFIX/lib" >>/etc/ld.so.conf
fi
/sbin/ldconfig -X

%postun
RMDIR_IGNORE_NONEMPTY="rmdir --ignore-fail-on-non-empty"
/sbin/ldconfig -X
if [ -d $RPM_INSTALL_PREFIX/share/doc/Botan-%{VERSION} ]; then
   $RMDIR_IGNORE_NONEMPTY $RPM_INSTALL_PREFIX/share/doc/Botan-%{VERSION}
fi

%postun devel
RMDIR_IGNORE_NONEMPTY="rmdir --ignore-fail-on-non-empty"
if [ -d $RPM_INSTALL_PREFIX/include/botan ]; then
   $RMDIR_IGNORE_NONEMPTY $RPM_INSTALL_PREFIX/include/botan
fi

##################################################
# File Lists                                     #
##################################################
%files
%defattr(-,root,root)
%docdir /usr/share/doc/Botan-%{VERSION}/
/usr/share/doc/Botan-%{VERSION}/license.txt
/usr/share/doc/Botan-%{VERSION}/readme.txt
/usr/share/doc/Botan-%{VERSION}/log.txt
/usr/share/doc/Botan-%{VERSION}/thanks.txt
/usr/share/doc/Botan-%{VERSION}/credits.txt
/usr/share/doc/Botan-%{VERSION}/pgpkeys.asc
/usr/share/doc/Botan-%{VERSION}/info.txt
/usr/lib/libbotan-%{MAJOR}.%{MINOR}.%{PATCH}.so

%files devel
%defattr(-,root,root)
%docdir /usr/share/doc/Botan-%{VERSION}/
/usr/share/doc/Botan-%{VERSION}/api.tex
/usr/share/doc/Botan-%{VERSION}/api.pdf
/usr/share/doc/Botan-%{VERSION}/tutorial.tex
/usr/share/doc/Botan-%{VERSION}/tutorial.pdf
/usr/share/doc/Botan-%{VERSION}/todo.txt
/usr/lib/libbotan.so
/usr/lib/libbotan.a
/usr/include/botan/
/usr/bin/botan-config

##################################################
# Changelog                                      #
##################################################
%changelog
* Wed Mar 17 2004 lloyd@randombit.net
 - Changed EXTRA_MODS to include eng_gmp, not mp_gmp
 - Requires: included uneeded stuff if ONLY_BASE_MODS was used

* Sun Feb 1 2004 lloyd@randombit.net
 - The Source: tag pointed to nowhere
 - Removed the FIPS 140 stuff, it was messy and broken

* Mon Dec 1 2003 lloyd@randombit.net
 - Cleaned up module handling
 - Added a preliminary FIPS 140-2 toggle
 - Use %defattr

* Tue Nov 30 2003 lloyd@randombit.net
 - Default to installing into /usr instead of /usr/local
 - Use tm_hard on sparcv9

* Tue Nov 23 2003 lloyd@randombit.net
 - Cleaned up the declaration of TIMERS
