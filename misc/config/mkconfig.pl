#!/usr/bin/perl -w

use strict;
use DirHandle;
use File::Spec::Functions;

############################################################################
# Version numbers
my $MAJOR = 1;
my $MINOR = 5;
my $PATCH = 11;

#############################################################################
# Configuration options

my $OUTPUT_FILE = '../../configure.pl';

my $CODE_DIR = 'code';
my $ARCH_DIR = 'arch';
my $OS_DIR = 'os';
my $CC_DIR = 'cc';

#############################################################################
# The basic logic of the script

print "Writing config script to $OUTPUT_FILE\n";

open OUTPUT, ">$OUTPUT_FILE" or
  die "Couldn't open $OUTPUT_FILE for writing ($!)";
chmod 0700, $OUTPUT_FILE;

write_code($CODE_DIR, 'header.pl');

sub q { my($s) = @_; $s =~ s/^: {0,3}//gm; $s; }

print OUTPUT &q(<<ENDOFCONFIG);

my \$MAJOR_VERSION = $MAJOR;
my \$MINOR_VERSION = $MINOR;
my \$PATCH_VERSION = $PATCH;

ENDOFCONFIG

write_code($CODE_DIR, 'config.pl');

my %REALNAMES = ();

print_arch_defines($ARCH_DIR,\%REALNAMES);
print_os_defines($OS_DIR,\%REALNAMES);
print_cc_defines($CC_DIR,\%REALNAMES);
print_hash('REALNAME',%REALNAMES);

# Most of the code is kept in separate files for ease of editing
write_code($CODE_DIR,'main.pl');
write_code($CODE_DIR,'misc.pl');
write_code($CODE_DIR,'include.pl');
write_code($CODE_DIR,'conflict.pl');
write_code($CODE_DIR,'modloop.pl');
write_code($CODE_DIR,'modinfo.pl');
write_code($CODE_DIR,'loadmod.pl');
write_code($CODE_DIR,'help.pl');
write_code($CODE_DIR,'wag.pl');
write_code($CODE_DIR,'sysinfo.pl');
write_code($CODE_DIR,'makefile.pl');
write_code($CODE_DIR,'unixmake.pl');
write_code($CODE_DIR,'nmake.pl');
write_code($CODE_DIR,'pkg_conf.pl');

close OUTPUT;
exit;

#############################################################################
# Some utility code

sub write_code {
    my $fullpath = catfile($_[0],$_[1]);
    open CODEFILE, $fullpath or die "Couldn't open $fullpath ($!)";
    while(<CODEFILE>) {
        print OUTPUT;
    }
    close CODEFILE;
}

sub process {
    my $l = $_[0];
    chomp($l);
    $l =~ s/#.*//;
    $l =~ s/^\s*//;
    $l =~ s/\s*$//;
    $l =~ s/\s\s*/ /;
    $l =~ s/\t/ /;
    $l;
}

# These could be replaced by Data::Dumper, but it looks nicer with this...
sub print_hash {
    my($name,%HASH) = @_;
    print OUTPUT "my %$name = (\n";
    foreach(sort keys %HASH) {
        my $quoted = '\''.$_.'\'';
        if(defined($HASH{$_})) {
            printf OUTPUT "   %-16s => \'$HASH{$_}\',\n", $quoted;
        }
    }
    print OUTPUT ")\;\n\n";
}

sub print_hash_nodef {
    my($name,%HASH) = @_;
    print OUTPUT "my %$name = (\n";
    foreach(sort keys %HASH) {
        my $quoted = '\''.$_.'\'';
        if(defined($HASH{$_}) && $HASH{$_} ne '') {
            printf OUTPUT "   %-16s => \'$HASH{$_}\',\n", $quoted;
        }
    }
    print OUTPUT ")\;\n\n";
}

sub print_hash_of_hashes {
    my($hashname,%HASH) = @_;
    print OUTPUT "my %$hashname = (\n";
    foreach my $key (sort keys %HASH) {
        printf OUTPUT "   %-12s => {\n", '\''.$key.'\'';
        foreach(sort keys %{ $HASH{$key} }) {
            my $quoted = '\''.$_.'\'';
            if(defined($HASH{$key}{$_})) {
                printf OUTPUT "      %-12s => \'$HASH{$key}{$_}\',\n", $quoted;
            } else {
                printf OUTPUT "      %-12s => undef,\n", $quoted;
            }
        }
        print OUTPUT "      },\n";
    }
    print OUTPUT ")\;\n\n";
}

sub print_hash_of_arrays {
    my($hashname,%HASH) = @_;
    print OUTPUT "my %$hashname = (\n";
    foreach my $key (sort keys %HASH) {
        printf OUTPUT "   %-12s => [ ", '\''.$key.'\'';
        my $len = 0;
        foreach(sort keys %{ $HASH{$key} }) {
            my $quoted = '\''.$_.'\'';
            print OUTPUT "$quoted, ";
            $len += length("$quoted, ");
            if($len > 55) {
                print OUTPUT "\n                     "; $len = 0;
            }
        }
        print OUTPUT "],\n";
    }
    print OUTPUT ")\;\n\n";
}

#############################################################################
sub print_arch_defines {
    my(undef, $REALNAME) = @_;
    my $dir = new DirHandle $_[0];
    if(!defined $dir) {
        die "Couldn't open directory $_[0] ($!)";
    }

    my(%SUBMODEL_ALIAS,%DEFAULT_SUBMODEL,%ARCH,%ARCH_ALIAS);

    while(defined($_ = $dir->read)) {
        next if($_ eq '.' or $_ eq '..');
        my $arch = $_;
        my $filename = catfile($_[0], $arch);
        open ARCHFILE, "<$filename" or die "Couldn't open $filename, ($!)";

        $ARCH{$arch} = $arch;
        while(<ARCHFILE>) {
            $_ = process($_);
            next unless $_;

            $$REALNAME{$arch} = $1 if(/^realname \"(.*)\"/);
            $DEFAULT_SUBMODEL{$arch} = $1 if(/^default_submodel (.*)$/);

            # Read in a list of aliases and add them to ARCH_ALIAS
            if(/^<aliases>$/) {
                while(1) {
                    $_ = process($_ = <ARCHFILE>);
                    next unless $_;
                    last if(m@^</aliases>$@);
                    $ARCH_ALIAS{$_} = $arch;
                }
            }
            # Read in a list of submodels and add them to ARCH
            if(/^<submodels>$/) {
                while(1) {
                    $_ = process($_ = <ARCHFILE>);
                    next unless $_;
                    last if(m@^</submodels>$@);
                    $ARCH{$_} = $arch;
                }
            }

            # Read in a list of submodel aliases and add them to SUBMODEL_ALIAS
            if(/^<submodel_aliases>$/) {
                while(1) {
                    $_ = process($_ = <ARCHFILE>);
                    next unless $_;
                    last if(m@^</submodel_aliases>$@);
                    m/^(\S*) -> (\S*)$/;
                    $SUBMODEL_ALIAS{$1} = $2;
                }
            }
        }
    }
    undef $dir;

    print_hash('ARCH',%ARCH);
    print_hash('ARCH_ALIAS',%ARCH_ALIAS);
    print_hash('DEFAULT_SUBMODEL', %DEFAULT_SUBMODEL);
    print_hash('SUBMODEL_ALIAS',%SUBMODEL_ALIAS);
}

#############################################################################
sub print_os_defines {
    my(undef, $REALNAME) = @_;
    my $dir = new DirHandle $_[0];
    if(!defined $dir) {
        die "Couldn't open directory $_[0] ($!)";
    }

    my(%OS_SUPPORTS_ARCH,
       %OS_SUPPORTS_SHARED,
       %OS_TYPE,
       %INSTALL_INFO,
       %OS_OBJ_SUFFIX,
       %OS_SHARED_SUFFIX,
       %OS_STATIC_SUFFIX,
       %OS_AR_COMMAND,
       %OS_AR_NEEDS_RANLIB,
       %OS_ALIAS);

    while(defined($_ = $dir->read)) {
        next if($_ eq '.' or $_ eq '..');
        my $os = $_;

        my $filename = catfile($_[0], $os);
        open OSFILE, "<$filename" or die "Couldn't open $filename, ($!)";
        $OS_SHARED_SUFFIX{$os} = '';
        $OS_AR_COMMAND{$os} = '';

        # Default values
        while(<OSFILE>) {
            $_ = process($_);
            next unless $_;

            $$REALNAME{$os} = $1 if(/^realname \"(.*)\"/);
            $OS_TYPE{$os} = $1 if(/^os_type (.*)/);
            $OS_AR_COMMAND{$os} = $1 if(/^ar_command \"(.*)\"/);
            $OS_AR_NEEDS_RANLIB{$os} = 1 if(/^ar_needs_ranlib yes$/);
            $OS_AR_NEEDS_RANLIB{$os} = 0 if(/^ar_needs_ranlib no$/);
            $OS_OBJ_SUFFIX{$os} = $1 if(/^obj_suffix (.*)/);
            $OS_SHARED_SUFFIX{$os} = $1 if(/^so_suffix (.*)/);
            $OS_STATIC_SUFFIX{$os} = $1 if(/^static_suffix (.*)/);

            $INSTALL_INFO{$os}{'root'} = $1 if(/^install_root (.*)/);
            $INSTALL_INFO{$os}{'headers'} = $1 if(/^header_dir (.*)/);
            $INSTALL_INFO{$os}{'libs'} = $1 if(/^lib_dir (.*)/);
            $INSTALL_INFO{$os}{'docs'} = $1 if(/^doc_dir (.*)/);
            $INSTALL_INFO{$os}{'user'} = $1 if(/^install_user (.*)/);
            $INSTALL_INFO{$os}{'group'} = $1 if(/^install_group (.*)/);
            $INSTALL_INFO{$os}{'command'} = $1
                if(/^install_cmd (.*)/);


            if(/^<aliases>$/) {
                while(1) {
                    $_ = process($_ = <OSFILE>);
                    next unless $_;
                    last if(m@^</aliases>$@);
                    $OS_ALIAS{$_} = $os;
                }
            }
            if(/^<supports_shared>$/) {
                while(1) {
                    $_ = process($_ = <OSFILE>);
                    next unless $_;
                    last if(m@^</supports_shared>$@);
                    $OS_SUPPORTS_SHARED{$os}{$_} = undef;
                }
            }

            # Read in a list of architectures and add them to OS_SUPPORTS_ARCH
            if(/^<arch>$/) {
                while(1) {
                    $_ = process($_ = <OSFILE>);
                    next unless $_;
                    last if(m@^</arch>$@);
                    $OS_SUPPORTS_ARCH{$os}{$_} = undef;
                }
            }
        }
    }
    undef $dir;

    print_hash_of_arrays('OS_SUPPORTS_ARCH', %OS_SUPPORTS_ARCH);
    print_hash_of_arrays('OS_SUPPORTS_SHARED', %OS_SUPPORTS_SHARED);
    print_hash('OS_TYPE', %OS_TYPE);
    print_hash_nodef('OS_OBJ_SUFFIX', %OS_OBJ_SUFFIX);
    print_hash_nodef('OS_SHARED_SUFFIX', %OS_SHARED_SUFFIX);
    print_hash_nodef('OS_STATIC_SUFFIX', %OS_STATIC_SUFFIX);
    print_hash_nodef('OS_AR_COMMAND', %OS_AR_COMMAND);
    print_hash_nodef('OS_AR_NEEDS_RANLIB', %OS_AR_NEEDS_RANLIB);
    print_hash('OS_ALIAS', %OS_ALIAS);
    print_hash_of_hashes('INSTALL_INFO', %INSTALL_INFO);
}

#############################################################################
sub print_cc_defines {
    my(undef, $REALNAME) = @_;
    my $dir = new DirHandle $_[0];
    if(!defined $dir) {
        die "Couldn't open directory $_[0] ($!)";
    }

    # Hashes 'o plenty here
    my(%CC_BINARY_NAME,
       %CC_LIB_OPT_FLAGS,
       %CC_CHECK_OPT_FLAGS,
       %CC_WARN_FLAGS,
       %CC_LANG_FLAGS,
       %CC_SO_OBJ_FLAGS,
       %CC_SO_LINK_FLAGS,
       %CC_DEBUG_FLAGS,
       %CC_NO_DEBUG_FLAGS,
       %CC_MACH_OPT_FLAGS,
       %CC_MACH_OPT_FLAGS_RE,
       %CC_ABI_FLAGS,
       %CC_SUPPORTS_OS,
       %CC_SUPPORTS_ARCH,
       %CC_AR_COMMAND,
       %MAKEFILE_STYLE);

    while(defined($_ = $dir->read)) {
        next if($_ eq '.' or $_ eq '..');
        my $cc = $_;
        my $filename = catfile($_[0], $cc);
        open CCFILE, "<$filename" or die "Couldn't open $filename, ($!)";

        # Default to empty values, so they don't have to be explicitly set
        $CC_LIB_OPT_FLAGS{$cc} =
            $CC_CHECK_OPT_FLAGS{$cc} =
            $CC_LANG_FLAGS{$cc} =
            $CC_WARN_FLAGS{$cc} =
            $CC_SO_OBJ_FLAGS{$cc} =
            $CC_DEBUG_FLAGS{$cc} =
            $CC_AR_COMMAND{$cc} =
            $CC_NO_DEBUG_FLAGS{$cc} = '';

        while(<CCFILE>) {
            $_ = process($_);
            next unless $_;

            $$REALNAME{$cc} = $1 if(/^realname \"(.*)\"/);
            $CC_BINARY_NAME{$cc} = $1 if(/^binary_name \"(.*)\"/);

            $CC_LIB_OPT_FLAGS{$cc} = $1 if(/^lib_opt_flags \"(.*)\"/);

            $CC_CHECK_OPT_FLAGS{$cc} = $1
                if(/^check_opt_flags \"(.*)\"/);

            $CC_AR_COMMAND{$cc} = $1 if(/^ar_command \"(.*)\"/);
            $CC_LANG_FLAGS{$cc} = $1 if(/^lang_flags \"(.*)\"/);
            $CC_WARN_FLAGS{$cc} = $1 if(/^warning_flags \"(.*)\"/);
            $CC_SO_OBJ_FLAGS{$cc} = $1 if(/^so_obj_flags \"(.*)\"/);
            $CC_DEBUG_FLAGS{$cc} = $1 if(/^debug_flags \"(.*)\"/);
            $CC_NO_DEBUG_FLAGS{$cc} = $1 if(/^no_debug_flags \"(.*)\"/);
            $MAKEFILE_STYLE{$cc} = $1 if(/^makefile_style (.*)/);

            # Read in a list of supported CPU types
            if(/^<arch>$/) {
                while(1) {
                    $_ = process($_ = <CCFILE>);
                    next unless $_;
                    last if(m@^</arch>$@);
                    $CC_SUPPORTS_ARCH{$cc}{$_} = undef;
                }
            }

            # Read in a list of supported OSes
            if(/^<os>$/) {
                while(1) {
                    $_ = process($_ = <CCFILE>);
                    next unless $_;
                    last if(m@^</os>$@);
                    $CC_SUPPORTS_OS{$cc}{$_} = undef;
                }
            }

            # Read in a list of machine optimization flags
            if(/^<mach_opt>$/) {
                while(1) {
                    $_ = process($_ = <CCFILE>);
                    next unless $_;
                    last if(m@^</mach_opt>$@);
                    m/^(\S*) -> \"(.*)\" ?(.*)?$/;
                    $CC_MACH_OPT_FLAGS{$cc}{$1} = $2;
                    if($3 ne '') {
                        $CC_MACH_OPT_FLAGS_RE{$cc}{$1} = $3;
                    }
                }
            }

            # Some systems need certain flags passed for linking as well
            # (usually these change the ABI somehow). We just append this
            # value to the CXX variable, so it's used for all ops.
            if(/^<mach_abi_linking>$/) {
                while(1) {
                    $_ = process($_ = <CCFILE>);
                    next unless $_;
                    last if(m@^</mach_abi_linking>$@);
                    m/^(\S*) -> \"(.*)\"$/;
                    $CC_ABI_FLAGS{$cc}{$1} = $2;
                }
            }

            # Read in a list of flags to created a shared lib (and set soname)
            if(/^<so_link_flags>$/) {
                while(1) {
                    $_ = process($_ = <CCFILE>);
                    next unless $_;
                    last if(m@^</so_link_flags>$@);
                    m/^(\S*) -> \"(.*)\"$/;
                    $CC_SO_LINK_FLAGS{$cc}{$1} = $2;
                }
            }
        }
    }
    undef $dir;

    # Finally, print some stuff
    print_hash_of_arrays('CC_SUPPORTS_OS',%CC_SUPPORTS_OS);
    print_hash_of_arrays('CC_SUPPORTS_ARCH',%CC_SUPPORTS_ARCH);

    print_hash('CC_BINARY_NAME', %CC_BINARY_NAME);
    print_hash('CC_LIB_OPT_FLAGS', %CC_LIB_OPT_FLAGS);
    print_hash('CC_CHECK_OPT_FLAGS', %CC_CHECK_OPT_FLAGS);
    print_hash('CC_WARN_FLAGS', %CC_WARN_FLAGS);
    print_hash('CC_LANG_FLAGS', %CC_LANG_FLAGS);
    print_hash('CC_DEBUG_FLAGS', %CC_DEBUG_FLAGS);
    print_hash('CC_NO_DEBUG_FLAGS', %CC_NO_DEBUG_FLAGS);
    print_hash_of_hashes('CC_MACHINE_OPT_FLAGS', %CC_MACH_OPT_FLAGS);
    print_hash_of_hashes('CC_MACHINE_OPT_FLAGS_RE', %CC_MACH_OPT_FLAGS_RE);
    print_hash('CC_SO_OBJ_FLAGS', %CC_SO_OBJ_FLAGS);
    print_hash_of_hashes('CC_ABI_FLAGS', %CC_ABI_FLAGS);
    print_hash_of_hashes('CC_SO_LINK_FLAGS', %CC_SO_LINK_FLAGS);
    print_hash('CC_AR_COMMAND', %CC_AR_COMMAND);
    print_hash('MAKEFILE_STYLE', %MAKEFILE_STYLE);
}
