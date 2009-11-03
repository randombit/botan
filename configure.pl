#!/usr/bin/perl -w

require 5.006;

use strict;

use Config;
use Getopt::Long;
use File::Spec;
use File::Copy;
use File::Find;
use Sys::Hostname;

my $MAJOR_VERSION = 1;
my $MINOR_VERSION = 8;
my $PATCH_VERSION = 8;

my $VERSION_SUFFIX = '';

my $SO_PATCH_VERSION = 2;

my $VERSION_STRING = "$MAJOR_VERSION.$MINOR_VERSION.$PATCH_VERSION$VERSION_SUFFIX";
my $SO_VERSION_STRING = "$MAJOR_VERSION.$MINOR_VERSION.$SO_PATCH_VERSION$VERSION_SUFFIX";

##################################################
# Data                                           #
##################################################
my (%CPU, %OPERATING_SYSTEM, %COMPILER, %MODULES);

my @DOCS = (
   'api.pdf', 'tutorial.pdf', 'fips140.pdf',
   'api.tex', 'tutorial.tex', 'fips140.tex',
   'credits.txt', 'license.txt', 'log.txt',
   'thanks.txt', 'todo.txt', 'pgpkeys.asc');

my $TRACING = 0;

##################################################
# Run main() and Quit                            #
##################################################
my $config = {};

main();
exit;

sub exec_uname {
    # Only exec it if we think it might actually work
    if(-f '/bin/uname' || -f '/usr/bin/uname' || -f '/bin/sh') {
        my $uname = `uname -a`;
        if($uname) {
            chomp $uname;
            return $uname;
        }
    }

    return '';
}

sub deprecation_warning {
    warning("$0 is deprecated; migration to ./configure.py strongly recommended");
}

##################################################
# Main Driver                                    #
##################################################
sub main {
    my $base_dir = where_am_i();

    deprecation_warning();

    $$config{'uname'} = exec_uname();

    $$config{'base-dir'} = $base_dir;
    $$config{'src-dir'} = File::Spec->catdir($base_dir, 'src');
    $$config{'checks-dir'} = File::Spec->catdir($base_dir, 'checks');
    $$config{'doc_src_dir'} = File::Spec->catdir($base_dir, 'doc');

    $$config{'config-dir'} =
        File::Spec->catdir($$config{'src-dir'}, 'build-data');

    $$config{'command_line'} = $0 . ' ' . join(' ', @ARGV);
    $$config{'timestamp'} = gmtime;
    $$config{'user'} = getlogin || getpwuid($<) || '';
    $$config{'hostname'} = hostname;

    %CPU = read_info_files($config, 'arch', \&get_arch_info);
    %OPERATING_SYSTEM = read_info_files($config, 'os', \&get_os_info);
    %COMPILER = read_info_files($config, 'cc', \&get_cc_info);
    %MODULES = read_module_files($config);

    add_to($config, {
        'version_major' => $MAJOR_VERSION,
        'version_minor' => $MINOR_VERSION,
        'version_patch' => $PATCH_VERSION,
        'version'       => $VERSION_STRING,
        'so_version'    => $SO_VERSION_STRING,
        });

    get_options($config);

    my $default_value_is = sub {
        my ($var, $val) = @_;
        $$config{$var} = $val if not defined($$config{$var});
    };

    &$default_value_is('gcc_bug', 0);
    &$default_value_is('autoconfig', 1);
    &$default_value_is('debug', 0);
    &$default_value_is('shared', 'yes');
    &$default_value_is('local_config', '');

    # Goes into build-specific dirs (maybe)

    $$config{'build_dir'} = 'build';
    $$config{'botan_config'} = File::Spec->catfile(
        $$config{'build_dir'}, 'botan-config');

    $$config{'botan_pkgconfig'} = File::Spec->catfile(
        $$config{'build_dir'},
        'botan-' . $MAJOR_VERSION . '.' . $MINOR_VERSION . '.pc');

    $$config{'makefile'} = 'Makefile';
    $$config{'check_prefix'} = '';
    $$config{'lib_prefix'} = '';

    if(defined($$config{'with_build_dir'})) {
        for my $var ('build_dir',
                     'botan_config',
                     'botan_pkgconfig',
                     'makefile',
                     'check_prefix',
                     'lib_prefix')
        {
            $$config{$var} = File::Spec->catfile($$config{'with_build_dir'},
                                                 $$config{$var});
        }
    }
    else {
    }

    choose_target($config);

    my $os = $$config{'os'};
    my $cc = $$config{'compiler'};

    &$default_value_is('prefix', os_info_for($os, 'install_root'));
    &$default_value_is('libdir', os_info_for($os, 'lib_dir'));
    &$default_value_is('docdir', os_info_for($os, 'doc_dir'));
    &$default_value_is('make_style', $COMPILER{$cc}{'makefile_style'});

    scan_modules($config);

    print_enabled_modules($config);

    add_to($config, {
        'includedir'    => os_info_for($os, 'header_dir'),

        'build_lib'     => File::Spec->catdir($$config{'build_dir'}, 'lib'),
        'build_check'   => File::Spec->catdir($$config{'build_dir'}, 'checks'),
        'build_include' =>
            File::Spec->catdir($$config{'build_dir'}, 'include'),
        'build_include_botan' =>
            File::Spec->catdir($$config{'build_dir'}, 'include', 'botan'),

        'mp_bits'       => find_mp_bits($config),
        'mod_libs'      => [ using_libs($config) ],

        'sources'       => { },
        'includes'      => { },

        'check_src'     => {
            map_to($$config{'checks-dir'},
                   grep { $_ ne 'keys' and !m@\.(dat|h)$@ }
                      dir_list($$config{'checks-dir'}))
            }
        });

    load_modules($config);

    my @dirs = mkdirs($$config{'build_dir'},
                      $$config{'build_include'},
                      $$config{'build_include_botan'},
                      $$config{'build_lib'},
                      $$config{'build_check'});

    #autoconfig('Created ' . join(' ', @dirs)) if @dirs;

    write_pkg_config($config);

    determine_config($config);

    process_template(File::Spec->catfile($$config{'config-dir'}, 'buildh.in'),
                     File::Spec->catfile($$config{'build_dir'}, 'build.h'),
                     $config);

    process_template(File::Spec->catfile(
                         $$config{'config-dir'}, 'botan.doxy.in'),
                     File::Spec->catfile($$config{'doc_src_dir'}, 'botan.doxy'),
                     $config);

    $$config{'includes'}{'build.h'} = $$config{'build_dir'};

    generate_makefile($config);

    copy_include_files($config);

    deprecation_warning();
}

sub where_am_i {
    my ($volume,$dir,$file) = File::Spec->splitpath($0);
    my $src_dir = File::Spec->catpath($volume, $dir, '');
    return $src_dir if $src_dir;
    return File::Spec->curdir();
}

##################################################
# Diagnostics                                    #
##################################################
sub with_diagnostic {
    my ($type, @args) = @_;

    my $args = join('', @args);
    my $str = "($type): ";
    while(length($str) < 14) { $str = ' ' . $str; }

    $str .= $args . "\n";
    return $str;
}

sub croak {
    die with_diagnostic('error', @_);
}

sub warning {
    warn with_diagnostic('warning', @_);
}

sub autoconfig {
    print with_diagnostic('autoconfig', @_);
}

sub emit_help {
    print join('', @_);
    exit;
}

sub trace {
    return unless $TRACING;

    my (undef, undef, $line) = caller(0);
    my (undef, undef, undef, $func) = caller(1);

    $func =~ s/main:://;

    print with_diagnostic('trace', "at $func:$line - ", @_);
}

##################################################
# Display Help and Quit                          #
##################################################
sub display_help {
    sub module_sets {
        my %modsets;
        for my $name (sort keys %MODULES) {
            my %info = %{$MODULES{$name}};
            next unless (defined($info{'modset'}));

            for my $s (split(/,/, $info{'modset'})) {
                $modsets{$s} = undef;
            }
        }

        return sort keys %modsets;
    }

    my $sets = join(' ', module_sets());

    my $listing = sub {
        my (@list) = @_;

        return '' if (@list == 0);

        my ($output, $len) = ('', 0);

        my $append = sub {
            my ($to_append) = @_;
            $output .= $to_append;
            $len += length $to_append;
        };

        foreach my $name (sort @list) {
            next if $name eq 'defaults';
            if($len > 58) {
                $output .= "\n        ";
                $len = 8;
            }
            &$append($name . ' ');
        }
        chop $output;
        return $output;
    };

    #my $modules = &$listing(keys %MODULES);
    my $compilers = &$listing(keys %COMPILER);
    my $oses =  &$listing(keys %OPERATING_SYSTEM);
    my $cpus = &$listing(keys %CPU);

    my $helptxt = <<ENDOFHELP;
This is $0 from Botan $VERSION_STRING

To select the compiler, use

  --cc=[$compilers]

To select the OS and processor to target, use these options. By
default, autodetection will be attempted.

  --os=[generic $oses]
  --cpu=[generic $cpus]

  --with-endian=[little big none]
  --with-unaligned-mem=[yes no]

To change build options:

  --with-tr1={none,system,boost}  enable (or disable) using a TR1 implementation
  --with-build-dir=DIR            setup the build in DIR
  --with-local-config=FILE        include the contents of FILE into build.h

  --disable-debug      don't worry about debugging
  --enable-debug       set compiler flags for debugging

  --enable-shared      enable shared libraries
  --disable-shared     don't build shared libararies

To change where the library is installed:

  --prefix=PATH        set the base installation directory
  --libdir=PATH        install library files in \${prefix}/\${libdir}
  --docdir=PATH        install documentation in \${prefix}/\${docdir}

To change what modules to use:

  --enable-modules=[module,[module[,...]]]
  --disable-modules=[module,[module[,...]]]

To get diagnostic and debug output:

  --module-info             display more information about modules

  --show-arch-info=CPU      show more information about a particular CPU
       [$cpus]

  --help                    display this help
  --version                 display the version of Botan
  --quiet                   display only warnings and errors
  --trace                   enable runtime tracing of this program

See doc/building.pdf for more information about this program.

ENDOFHELP

    emit_help($helptxt);
}

##################################################
# Display Further Information about Modules      #
##################################################
sub module_info {

    my $info = '';
    foreach my $mod (sort keys %MODULES) {
        my $modinfo = $MODULES{$mod};
        my $fullname = $$modinfo{'realname'};

        while(length($mod) < 10) { $mod .= ' '; }
        $info .= "$mod - $fullname\n";
    }

    return $info;
}

##################################################
#
##################################################
sub choose_target {
    my ($config) = @_;

    my $cc = $$config{'compiler'};
    my $os = $$config{'os'};
    my $cpu = $$config{'cpu'};

    autoconfig("Setting up build for Botan $VERSION_STRING");

    $cpu = guess_cpu() if not defined($cpu);
    $cc = guess_compiler() if not defined($cc);
    $os = guess_os() if not defined($os);

    display_help()
        unless(defined($cc) and defined($os) and defined($cpu));

    croak("Compiler $cc isn't known (try --help)")
        unless defined($COMPILER{$cc});

    my %ccinfo = %{$COMPILER{$cc}};

    if(defined($ccinfo{'compiler_has_tr1'})) {
        unless(defined($$config{'tr1'})) {
            autoconfig('Assuming compiler ', $cc, ' has TR1 headers. ',
                       'Use --with-tr1=none to disable');
            $$config{'tr1'} = 'system';
        }
    }

    $os = os_alias($os);
    croak("OS $os isn't known (try --help)") unless
        ($os eq 'generic' or defined($OPERATING_SYSTEM{$os}));

    my ($arch, $submodel) = figure_out_arch($cpu);

    # hacks
    if($cc eq 'gcc') {
        $ccinfo{'binary_name'} = 'c++' if($os eq 'darwin');

        if($$config{'gcc_bug'} != 1) {
            my $binary = $ccinfo{'binary_name'};

            my $gcc_version = `$binary -v 2>&1`;

            $gcc_version = '' if not defined $gcc_version;

            my $has_ll_bug = 0;
            $has_ll_bug = 1 if($gcc_version =~ /4\.[01234]/);
            $has_ll_bug = 1 if($gcc_version =~ /3\.[34]/);
            $has_ll_bug = 1 if($gcc_version =~ /2\.95\.[0-4]/);
            $has_ll_bug = 1 if($gcc_version eq '');

            $has_ll_bug = 0 if($arch eq 'alpha' or $arch =~ /.*64$/);

            if($has_ll_bug)
            {
                warning('Enabling -fpermissive to work around ',
                        'possible GCC bug');

                $$config{'gcc_bug'} = 1;
            }

            warning('GCC 2.95.x issues many spurious warnings')
                if($gcc_version =~ /2\.95\.[0-4]/);
        }
    }

    trace("using $cc $os $arch $submodel");

    add_to($config, {
        'compiler'      => $cc,
        'os'            => $os,
        'arch'          => $arch,
        'submodel'      => $submodel,
    });
}

sub module_runs_on {
    my ($config, $modinfo, $mod, $noisy) = @_;

    my $cc = $$config{'compiler'};
    my $os = $$config{'os'};
    my $submodel = $$config{'submodel'};
    my $arch = $$config{'arch'};

    my %modinfo = %{$modinfo};

    my $realname = $modinfo{'realname'};

    my @arch_list = @{ $modinfo{'arch'} };
    if(scalar @arch_list > 0 && !in_array($arch, \@arch_list) &&
       !in_array($submodel, \@arch_list))
    {
        autoconfig("$mod ($realname): skipping, " .
                   "not compatible with " . realname($arch) .
                   "/" . $submodel) if $noisy;
        return 0;
    }

    my @os_list = @{ $modinfo{'os'} };
    if(scalar @os_list > 0 && !in_array($os, \@os_list))
    {
        autoconfig("$mod ($realname): " .
                   "skipping, not compatible with " . realname($os)) if $noisy;
        return 0;
    }

    my @cc_list = @{ $modinfo{'cc'} };
    if(scalar @cc_list > 0 && !in_array($cc, \@cc_list)) {
        autoconfig("$mod ($realname): " .
                   "skipping, not compatible with " . realname($cc)) if $noisy;
        return 0;
    }


    if($modinfo{'uses_tr1'} eq 'yes') {
        return 0 unless defined($$config{'tr1'});

        my $tr1 = $$config{'tr1'};
        return 0 unless($tr1 eq 'system' or $tr1 eq 'boost');
    }

    return 1;
}

sub scan_modules {
    my ($config) = @_;

    foreach my $mod (sort keys %MODULES) {
        my %modinfo = %{ $MODULES{$mod} };

        next if(defined($$config{'modules'}{$mod}) && $$config{'modules'}{$mod} < 0);

        next unless(module_runs_on($config, \%modinfo, $mod, 0));

        if($modinfo{'load_on'} eq 'auto' or
           $modinfo{'load_on'} eq 'always' or
            ($modinfo{'load_on'} eq 'asm_ok' and $$config{'asm_ok'})) {

            my %maybe_load = ();
            my $all_deps_found = 1;

            LINE: foreach (@{$modinfo{'requires'}}) {
                for my $req_mod (split(/\|/, $_)) {
                    next unless defined $MODULES{$req_mod};

                    next if(defined($$config{'modules'}{$req_mod}) && $$config{'modules'}{$req_mod} < 0);
                    next unless(module_runs_on($config, $MODULES{$req_mod}, $req_mod, 0));

                    $maybe_load{$req_mod} = 1;
                    next LINE;
                }
                $all_deps_found = 0;
            }

            if($all_deps_found) {
                foreach my $depmod (keys %maybe_load)
                   { $$config{'modules'}{$depmod} = 1; }
                $$config{'modules'}{$mod} = 1;
            }
        }
    }
}

sub print_enabled_modules {
    my ($config) = @_;

    return unless($$config{'verbose'});

    my %by_type;

    foreach my $mod (sort keys %MODULES) {
        my $type = $MODULES{$mod}{'type'};

        my $n = 0;
        $n = 1 if($$config{'modules'}{$mod} && $$config{'modules'}{$mod} > 0);

        $by_type{$type}{$mod} = $n;
    }

    for my $type (sort keys %by_type) {
        my %mods = %{$by_type{$type}};

        my @load_lines;

        if(keys %mods == 1) {
            my $on = $mods{$type};

            if($on > 0) {
                print with_diagnostic('loading', $type);
            }
            else {
                print with_diagnostic('loading', '[', $type , ']');
            }
        }
        else {
            my $s = $type . ': ';

            for my $mod (sort keys %mods) {
                my $on = $mods{$mod};

                if($s eq '') {
                    $s = ' ' x (length($type) + 16);
                }

                if($on > 0) {
                    $s .= $mod . ' ';
                }
                else {
                    $s .= '[' . $mod . '] ';
                }

                if(length($s) > 60) {
                    push @load_lines, $s;
                    $s = '';
                }
            }

            #print "Last1 '$s'\n";

            $s =~ s/\s*$//m; # strip trailing whitespace

            push @load_lines, $s if($s ne '');


            print with_diagnostic('loading', join("\n", @load_lines));
        }
    }
}

sub get_options {
    my ($config) = @_;

    my $save_option = sub {
        my ($opt, $val) = @_;
        $opt =~ s/-/_/g;
        $$config{$opt} = $val;
    };

    $$config{'verbose'} = 1;
    $$config{'asm_ok'} = 1;
    $$config{'tr1'} = undef; # not enabled by default
    $$config{'modules'} = {};

    sub arch_info {
        my $arg = $_[0];

        my $arch = find_arch($arg);

        unless(defined($arch) and defined($CPU{$arch})) {
            warning("Unknown arch '$arg' passed to --arch-info (try --help)");
            return '';
        }

        my %info = %{ $CPU{$arch} };

        my $out = "Information for $arg ($arch)\n--------\n";

        if(@{$info{'aliases'}}) {
            $out .= 'Aliases: ' . join(' ', @{$info{'aliases'}}) . "\n";
        }

        if(@{$info{'submodels'}}) {
            $out .= 'Submodels: ' . join(' ', @{$info{'submodels'}}) . "\n";
        }

        foreach my $k (keys %{$info{'submodel_aliases'}}) {
            $out .= "Alias '$k' -> '" . $info{'submodel_aliases'}{$k} . "'\n";
        }

        if(defined($info{'endian'})) {
            $out .= 'Default endian: ' . $info{'endian'} . "\n";
        }

        if(defined($info{'unaligned'})) {
            $out .= 'Unaligned memory access: ' . $info{'unaligned'} . "\n";
        }

        return $out;
    }

    sub add_modules {
        my ($config,$mods) = @_;

        foreach my $mod (split(/,/, $mods)) {
            # -1 means disabled by user, do not load
            $$config{'modules'}{$mod} = 1 unless(
                defined($$config{'modules'}{$mod}) &&
                $$config{'modules'}{$mod} == -1);
        }
    }

    sub disable_modules {
        my ($config,$mods) = @_;

        foreach my $mod (split(/,/, $mods)) {
            # -1 means disabled by user, do not load
            $$config{'modules'}{$mod} = -1;
        }
    }

    sub add_module_sets {
        my ($config,$sets) = @_;

        foreach my $set (split(/,/, $sets)) {
            for my $mod (sort keys %MODULES) {
                my %info = %{$MODULES{$mod}};

                next unless (defined($info{'modset'}));

                for my $s (split(/,/, $info{'modset'})) {
                    if($s eq $set) {
                        $$config{'modules'}{$mod} = 1
                            unless($$config{'modules'}{$mod} == -1);
                    }
                }
            }
        }
    }

    exit 1 unless GetOptions(
        'prefix=s' => sub { &$save_option(@_); },
        'exec-prefix=s' => sub { &$save_option(@_); },

        'bindir=s' => sub { &$save_option(@_); },
        'datadir' => sub { &$save_option(@_); },
        'datarootdir' => sub { &$save_option(@_); },
        'docdir=s' => sub { &$save_option(@_); },
        'dvidir' => sub { &$save_option(@_); },
        'htmldir' => sub { &$save_option(@_); },
        'includedir' => sub { &$save_option(@_); },
        'infodir' => sub { &$save_option(@_); },
        'libdir=s' => sub { &$save_option(@_); },
        'libexecdir' => sub { &$save_option(@_); },
        'localedir' => sub { &$save_option(@_); },
        'localstatedir' => sub { &$save_option(@_); },
        'mandir' => sub { &$save_option(@_); },
        'oldincludedir' => sub { &$save_option(@_); },
        'pdfdir' => sub { &$save_option(@_); },
        'psdir' => sub { &$save_option(@_); },
        'sbindir=s' => sub { &$save_option(@_); },
        'sharedstatedir' => sub { &$save_option(@_); },
        'sysconfdir' => sub { &$save_option(@_); },

        'cc=s' => sub { &$save_option('compiler', $_[1]) },
        'os=s' => sub { &$save_option(@_) },
        'cpu=s' => sub { &$save_option(@_) },

        'help' => sub { display_help(); },
        'module-info' => sub { emit_help(module_info()); },
        'version' => sub { emit_help("$VERSION_STRING\n") },
        'so-version' => sub { emit_help("$SO_VERSION_STRING\n") },

        'with-tr1-implementation=s' => sub { $$config{'tr1'} = $_[1]; },

        'quiet' => sub { $$config{'verbose'} = 0; },
        'trace' => sub { $TRACING = 1; },

        'enable-asm' => sub { $$config{'asm_ok'} = 1; },
        'disable-asm' => sub { $$config{'asm_ok'} = 0; },

        'enable-autoconfig' => sub { $$config{'autoconfig'} = 1; },
        'disable-autoconfig' => sub { $$config{'autoconfig'} = 0; },

        'enable-shared' => sub { $$config{'shared'} = 'yes'; },
        'disable-shared' => sub { $$config{'shared'} = 'no'; },

        'enable-debug' => sub { &$save_option('debug', 1); },
        'disable-debug' => sub { &$save_option('debug', 0); },

        'enable-modules:s' => sub { add_modules($config, $_[1]); },
        'disable-modules:s' => sub { disable_modules($config, $_[1]); },

        'with-openssl' => sub { add_modules($config, 'openssl'); },
        'without-openssl' => sub { disable_modules($config, 'openssl'); },
        'with-gnump' => sub { add_modules($config, 'gnump'); },
        'without-gnump' => sub { disable_modules($config, 'gnump'); },
        'with-bzip2' => sub { add_modules($config, 'bzip2'); },
        'without-bzip2' => sub { disable_modules($config, 'bzip2'); },
        'with-zlib' => sub { add_modules($config, 'zlib'); },
        'without-zlib' => sub { disable_modules($config, 'zlib'); },

        'use-module-set=s' => sub { add_module_sets($config, $_[1]); },

        'with-build-dir=s' => sub { &$save_option(@_); },
        'with-endian=s' => sub { &$save_option(@_); },
        'with-unaligned-mem=s' => sub { &$save_option(@_); },
        'with-local-config=s' =>
            sub { &$save_option('local_config', slurp_file($_[1])); },

        'modules=s' => sub { add_modules($config, $_[1]); },
        'show-arch-info=s' => sub { emit_help(arch_info($_[1])); },
        'make-style=s' => sub { &$save_option(@_); },
        'dumb-gcc|gcc295x' => sub { $$config{'gcc_bug'} = 1; }
        );

    # All arguments should now be consumed
    croak("Unknown option $ARGV[0] (try --help)") unless($#ARGV == -1);
}

##################################################
# Functions to search the info tables            #
##################################################
sub find_arch {
    my $name = $_[0];

    foreach my $arch (keys %CPU) {
        my %info = %{$CPU{$arch}};

        return $arch if($name eq $arch);

        foreach my $alias (@{$info{'aliases'}}) {
            return $arch if($name eq $alias);
        }

        foreach my $submodel (@{$info{'submodels'}}) {
            return $arch if($name eq $submodel);
        }

        foreach my $submodel (keys %{$info{'submodel_aliases'}}) {
            return $arch if($name eq $submodel);
        }
    }
    return undef;
};

sub figure_out_arch {
    my ($name) = @_;

    return ('generic', 'generic') if($name eq 'generic');

    my $submodel_alias = sub {
        my ($name,$info) = @_;

        my %info = %{$info};

        foreach my $submodel (@{$info{'submodels'}}) {
            return $submodel if($name eq $submodel);
        }

        return '' unless defined $info{'submodel_aliases'};
        my %sm_aliases = %{$info{'submodel_aliases'}};

        foreach my $alias (keys %sm_aliases) {
            my $official = $sm_aliases{$alias};
            return $official if($alias eq $name);
        }
        return '';
    };

    my $arch = find_arch($name);
    croak("Arch type $name isn't known (try --help)") unless defined $arch;
    trace("mapped name '$name' to arch '$arch'");

    my %archinfo = %{ $CPU{$arch} };

    my $submodel = &$submodel_alias($name, \%archinfo);

    if($submodel eq '') {
        $submodel = $archinfo{'default_submodel'};

        autoconfig("Using $submodel as default type for family ",
                   realname($arch)) if($submodel ne $arch);
    }

    trace("mapped name '$name' to submodel '$submodel'");

    croak("Couldn't figure out arch type of $name")
        unless defined($arch) and defined($submodel);

    return ($arch,$submodel);
}

sub os_alias {
    my $name = $_[0];

    foreach my $os (keys %OPERATING_SYSTEM) {
        foreach my $alias (@{$OPERATING_SYSTEM{$os}{'aliases'}}) {
            if($alias eq $name) {
                trace("os_alias($name) -> $os");
                return $os;
                }
        }
    }

    return $name;
}

sub os_info_for {
    my ($os,$what) = @_;

    die unless defined($os);

    croak('os_info_for called with an os of defaults (internal problem)')
        if($os eq 'defaults');

    my $result = '';

    if(defined($OPERATING_SYSTEM{$os})) {
        my %osinfo = %{$OPERATING_SYSTEM{$os}};
        $result = $osinfo{$what};
    }

    if(!defined($result) or $result eq '') {
        $result = $OPERATING_SYSTEM{'defaults'}{$what};
    }

    croak("os_info_for: No info for $what on $os") unless defined $result;

    return $result;
}

sub my_compiler {
    my ($config) = @_;
    my $cc = $$config{'compiler'};

    croak('my_compiler called, but no compiler set in config')
        unless defined $cc and $cc ne '';

    croak("unknown compiler $cc") unless defined $COMPILER{$cc};

    return %{$COMPILER{$cc}};
}

sub mach_opt {
    my ($config) = @_;

    my %ccinfo = my_compiler($config);

    # Nothing we can do in that case
    return '' unless $ccinfo{'mach_opt_flags'};

    my $submodel = $$config{'submodel'};
    my $arch = $$config{'arch'};
    if(defined($ccinfo{'mach_opt_flags'}{$submodel}))
    {
        return $ccinfo{'mach_opt_flags'}{$submodel};
    }
    elsif(defined($ccinfo{'mach_opt_flags'}{$arch})) {
        my $mach_opt_flags = $ccinfo{'mach_opt_flags'}{$arch};
        my $processed_modelname = $submodel;

        my $remove = '';
        if(defined($ccinfo{'mach_opt_re'}) and
           defined($ccinfo{'mach_opt_re'}{$arch})) {
            $remove = $ccinfo{'mach_opt_re'}{$arch};
        }

        $processed_modelname =~ s/$remove//;
        $mach_opt_flags =~ s/SUBMODEL/$processed_modelname/g;
        return $mach_opt_flags;
    }
    return '';
}

##################################################
#                                                #
##################################################
sub using_libs {
   my ($config) = @_;

   my $os = $$config{'os'};
   my %libs;

   foreach my $mod (sort keys %{$$config{'modules'}}) {
       next if ${$$config{'modules'}}{$mod} < 0;

      my %MOD_LIBS = %{ $MODULES{$mod}{'libs'} };

      foreach my $mod_os (keys %MOD_LIBS)
      {
          next if($mod_os =~ /^all!$os$/);
          next if($mod_os =~ /^all!$os,/);
          #next if($mod_os =~ /^all!.*,${os}$/);
          next if($mod_os =~ /^all!.*,$os,.*/);
          next unless($mod_os eq $os or ($mod_os =~ /^all.*/));
          my @liblist = split(/,/, $MOD_LIBS{$mod_os});
          foreach my $lib (@liblist) { $libs{$lib} = 1; }
      }
   }

   return sort keys %libs;
}

sub libs {
    my ($prefix,$suffix,@libs) = @_;
    my $output = '';
    foreach my $lib (@libs) {
        $output .= ' ' if($output ne '');
        $output .= $prefix . $lib . $suffix;
    }
    return $output;
}

##################################################
# Path and file manipulation utilities           #
##################################################
sub portable_symlink {
   my ($from, $to_dir, $to_fname) = @_;

   #trace("portable_symlink($from, $to_dir, $to_fname)");

   my $can_symlink = 0;
   my $can_link = 0;

   unless($^O eq 'MSWin32' or $^O eq 'dos' or $^O eq 'cygwin') {
       $can_symlink = eval { symlink("",""); 1 };
       $can_link = eval { link("",""); 1 };
   }

   chdir $to_dir or croak("Can't chdir to $to_dir ($!)");

   if($can_symlink) {
       symlink $from, $to_fname or
           croak("Can't symlink $from to $to_fname ($!)");
   }
   elsif($can_link) {
       link $from, $to_fname or
           croak("Can't link $from to $to_fname ($!)");
   }
   else {
       copy ($from, $to_fname) or
           croak("Can't copy $from to $to_fname ($!)");
   }

   my $go_up = File::Spec->splitdir($to_dir);
   for(my $j = 0; $j != $go_up; $j++) # return to where we were
   {
       chdir File::Spec->updir();
   }
}

sub copy_include_files {
    my ($config) = @_;

    my $include_dir = $$config{'build_include_botan'};

    trace('Copying to ', $include_dir);

    foreach my $file (dir_list($include_dir)) {
        my $path = File::Spec->catfile($include_dir, $file);
        unlink $path or croak("Could not unlink $path ($!)");
    }

   my $link_up = sub {
       my ($dir, $file) = @_;
       my $updir = File::Spec->updir();
       portable_symlink(File::Spec->catfile($updir, $updir, $updir,
                                            $dir, $file),
                        $include_dir, $file);
   };

    my $files = $$config{'includes'};

    foreach my $file (keys %$files) {
        &$link_up($$files{$file}, $file);
    }
}

sub dir_list {
    my ($dir) = @_;
    opendir(DIR, $dir) or croak("Couldn't read directory '$dir' ($!)");

    my @listing = grep { !/#/ and -f File::Spec->catfile($dir, $_) and
                         $_ ne File::Spec->curdir() and
                         $_ ne File::Spec->updir() } readdir DIR;

    closedir DIR;
    return @listing;
}

sub mkdirs {
    my (@dirs) = @_;

    my @created;
    foreach my $dir (@dirs) {
        next if( -e $dir and -d $dir ); # skip it if it's already there
        mkdir($dir, 0777) or
            croak("Could not create directory $dir ($!)");
        push @created, $dir;
    }
    return @created;
}

sub slurp_file {
    my $file = $_[0];

    return '' if(!defined($file) or $file eq '');

    croak("'$file': No such file") unless(-e $file);
    croak("'$file': Not a regular file") unless(-f $file);

    open FILE, "<$file" or croak("Couldn't read $file ($!)");

    my $output = '';
    while(<FILE>) { $output .= $_; }
    close FILE;

    return $output;
}

sub which
{
    my $file = $_[0];
    my @paths = split(/:/, $ENV{PATH});
    foreach my $path (@paths)
    {
        my $file_path = File::Spec->catfile($path, $file);
        return $file_path if(-e $file_path and -r $file_path);
    }
    return '';
}

# Return a hash mapping every var in a list to a constant value
sub map_to {
    my $var = shift;
    return map { $_ => $var } @_;
}

sub in_array {
    my($target, $array) = @_;
    return 0 unless defined($array);
    foreach (@$array) { return 1 if($_ eq $target); }
    return 0;
}

sub add_to {
    my ($to,$from) = @_;

    foreach my $key (keys %$from) {
        $$to{$key} = $$from{$key};
    }
}

##################################################
#                                                #
##################################################
sub find_mp_bits {
    my(@modules_list) = @_;
    my $mp_bits = 32; # default, good for most systems

    my $seen_mp_module = undef;

    foreach my $modname (sort keys %{$$config{'modules'}}) {
        croak("Unknown module $modname") unless defined $MODULES{$modname};

        next if $$config{'modules'}{$modname} < 0;

        my %modinfo = %{ $MODULES{$modname} };
        if($modinfo{'mp_bits'}) {
            if(defined($seen_mp_module) and $modinfo{'mp_bits'} != $mp_bits) {
                croak('Inconsistent mp_bits requests from modules ',
                      $seen_mp_module, ' and ', $modname);
            }

            $seen_mp_module = $modname;
            $mp_bits = $modinfo{'mp_bits'};
        }
    }
    return $mp_bits;
}

##################################################
#                                                #
##################################################
sub realname {
    my $arg = $_[0];

    return $COMPILER{$arg}{'realname'}
       if defined $COMPILER{$arg};

    return $OPERATING_SYSTEM{$arg}{'realname'}
       if defined $OPERATING_SYSTEM{$arg};

    return $CPU{$arg}{'realname'}
       if defined $CPU{$arg};

    return $arg;
}

##################################################
#                                                #
##################################################

sub load_module {
    my ($config, $modname) = @_;

    #trace("load_module($modname)");

    croak("Unknown module $modname") unless defined($MODULES{$modname});

    my %module = %{$MODULES{$modname}};

    my $works_on = sub {
        my ($what, $lst_ref) = @_;
        my @lst = @{$lst_ref};
        return 1 if not @lst; # empty list -> no restrictions
        return 1 if $what eq 'generic'; # trust the user
        return in_array($what, \@lst);
    };

    # Check to see if everything is OK WRT system requirements
    my $os = $$config{'os'};

    croak("Module '$modname' does not run on $os")
        unless(&$works_on($os, $module{'os'}));

    my $arch = $$config{'arch'};
    my $sub = $$config{'submodel'};

    croak("Module '$modname' does not run on $arch/$sub")
        unless(&$works_on($arch, $module{'arch'}) or
               &$works_on($sub, $module{'arch'}));

    my $cc = $$config{'compiler'};

    croak("Module '$modname' does not work with $cc")
        unless(&$works_on($cc, $module{'cc'}));

    my $handle_files = sub {
        my($lst, $func) = @_;
        return unless defined($lst);

        foreach (sort @$lst) {
            &$func($module{'moddirs'}, $config, $_);
        }
    };

    &$handle_files($module{'ignore'},  \&ignore_file);
    &$handle_files($module{'add'},     \&add_file);
    &$handle_files($module{'replace'},
                   sub { ignore_file(@_); add_file(@_); });

    warning($modname, ': ', $module{'note'})
        if(defined($module{'note'}));
}

sub load_modules {
    my ($config) = @_;

    my @mod_names;

    foreach my $mod (sort keys %{$$config{'modules'}}) {
        next unless($$config{'modules'}{$mod} > 0);

        load_module($config, $mod);

        push @mod_names, $mod;
    }

    $$config{'mod_list'} = join("\n", @mod_names);

    my $unaligned_ok = 0;

    my $target_os_defines = sub {
        my @macro_list;

        my $os = $$config{'os'};
        if($os ne 'generic') {
            push @macro_list, '#define BOTAN_TARGET_OS_IS_' . uc $os;

            my @features = @{$OPERATING_SYSTEM{$os}{'target_features'}};

            for my $feature (@features) {
                push @macro_list, '#define BOTAN_TARGET_OS_HAS_' . uc $feature;
            }

        }
        return join("\n", @macro_list);
    };

    $$config{'target_os_defines'} = &$target_os_defines();

    my $target_cpu_defines = sub {
        my @macro_list;

        my $arch = $$config{'arch'};
        if($arch ne 'generic') {
            my %cpu_info = %{$CPU{$arch}};
            my $endian = $cpu_info{'endian'};

            if(defined($$config{'with_endian'})) {
                $endian = $$config{'with_endian'};
                $endian = undef unless($endian eq 'little' ||
                                       $endian eq 'big');
            }
            elsif(defined($endian)) {
                autoconfig("Since arch is $arch, assuming $endian endian mode");
            }

            push @macro_list, "#define BOTAN_TARGET_ARCH_IS_" . (uc $arch);

            my $submodel = $$config{'submodel'};
            if($arch ne $submodel) {
                $submodel = uc $submodel;
                $submodel =~ tr/-/_/;
                $submodel =~ tr/.//;

                push @macro_list, "#define BOTAN_TARGET_CPU_IS_$submodel";
            }

            if(defined($endian)) {
                $endian = uc $endian;
                push @macro_list,
                   "#define BOTAN_TARGET_CPU_IS_${endian}_ENDIAN";

                # See if the user set --with-unaligned-mem
                if(defined($$config{'with_unaligned_mem'})) {
                    my $spec = $$config{'with_unaligned_mem'};

                    if($spec eq 'yes') {
                        $unaligned_ok = 1;
                    }
                    elsif($spec eq 'no') {
                        $unaligned_ok = 0;
                    }
                    else {
                        warning('Unknown arg to --with-unaligned-mem (' .
                                $spec . ') will ignore');
                        $unaligned_ok = 0;
                    }
                }
                # Otherwise, see if the CPU has a default setting
                elsif(defined($cpu_info{'unaligned'}) and
                      $cpu_info{'unaligned'} eq 'ok')
                {
                    autoconfig("Since arch is $arch, " .
                               'assuming unaligned memory access is OK');
                    $unaligned_ok = 1;
                }
            }
        }

        # variable is always set (one or zero)
        push @macro_list,
           "#define BOTAN_TARGET_UNALIGNED_LOADSTOR_OK $unaligned_ok";
        return join("\n", @macro_list);
    };

    $$config{'target_cpu_defines'} = &$target_cpu_defines();

    my $target_compiler_defines = sub {
        my @macro_list;

        if(defined($$config{'tr1'})) {
            my $tr1 = $$config{'tr1'};

            if($tr1 eq 'system') {
                push @macro_list, '#define BOTAN_USE_STD_TR1';
            }
            elsif($tr1 eq 'boost') {
                push @macro_list, '#define BOTAN_USE_BOOST_TR1';
            }
            elsif($tr1 ne 'none') {
                croak("Unknown --with-tr1= option value '$tr1' (try --help)");
            }
        }

        return join("\n", @macro_list);
    };

    $$config{'target_compiler_defines'} = &$target_compiler_defines();

    my $gen_defines = sub {
        my @macro_list;

        my %defines;

        foreach my $mod (sort keys %{$$config{'modules'}}) {
            next unless $$config{'modules'}{$mod} > 0;

            my $defs = $MODULES{$mod}{'define'};
            next unless $defs;

            push @{$defines{$MODULES{$mod}{'type'}}}, split(/,/, $defs);
        }

        foreach my $type (sort keys %defines) {
            push @macro_list, "\n/* $type */";

            for my $macro (@{$defines{$type}}) {
                die unless(defined $macro and $macro ne '');
                push @macro_list, "#define BOTAN_HAS_$macro";
            }
        }

        return join("\n", @macro_list);
    };

    $$config{'module_defines'} = &$gen_defines();
}

##################################################
#                                                #
##################################################
sub file_type {
    my ($file) = @_;

    return 'sources'
        if($file =~ /\.cpp$/ or $file =~ /\.c$/ or $file =~ /\.S$/);
    return 'includes' if($file =~ /\.h$/);

    croak('file_type() - don\'t know what sort of file ', $file, ' is');
}

sub add_file {
    my ($mod_dir, $config, $file) = @_;

    check_for_file($config, $file, $mod_dir, $mod_dir);

    my $do_add_file = sub {
        my ($type) = @_;

        croak("File $file already added from ", $$config{$type}{$file})
            if(defined($$config{$type}{$file}));

        if($file =~ /(.*):(.*)/) {
            my @dirs = File::Spec->splitdir($mod_dir);

            $dirs[$#dirs-1] = $1;

            $$config{$type}{$2} = File::Spec->catdir(@dirs);
        }
        else {
            $$config{$type}{$file} = $mod_dir;
        }
    };

    &$do_add_file(file_type($file));
}

sub ignore_file {
    my ($mod_dir, $config, $file) = @_;
    check_for_file($config, $file, undef, $mod_dir);

    my $do_ignore_file = sub {
        my ($type, $ok_if_from) = @_;

        if(defined ($$config{$type}{$file})) {

            croak("$mod_dir - File $file modified from ",
                  $$config{$type}{$file})
                if($$config{$type}{$file} ne $ok_if_from);

            delete $$config{$type}{$file};
        }
    };

    &$do_ignore_file(file_type($file));
}

sub check_for_file {
   my ($config, $file, $added_from, $mod_dir) = @_;

   #trace("check_for_file($file, $added_from, $mod_dir)");

   my $full_path = sub {
       my ($file,$mod_dir) = @_;

       if($file =~ /(.*):(.*)/) {
           return File::Spec->catfile($mod_dir, '..', $1, $2);
       } else {
           return File::Spec->catfile($mod_dir, $file) if(defined($mod_dir));

           my @typeinfo = file_type($config, $file);
           return File::Spec->catfile($typeinfo[1], $file);
       }
   };

   $file = &$full_path($file, $added_from);

   croak("Module $mod_dir requires that file $file exist. This error\n      ",
         'should never occur; please contact the maintainers with details.')
       unless(-e $file);
}

##################################################
#                                                #
##################################################
sub process_template {
    my ($in, $out, $config) = @_;

    trace("process_template: $in -> $out");

    my $contents = slurp_file($in);

    foreach my $name (keys %$config) {
        my $val = $$config{$name};

        unless(defined $val) {
            trace("Undefined variable $name in $in");
            next;
        }

        $contents =~ s/\%\{$name\}/$val/g;
    }

    if($contents =~ /\%\{([a-z_]*)\}/) {

        sub summarize {
            my ($n, $s) = @_;

            $s =~ s/\n/\\n/; # escape newlines

            return $s if(length($s) <= $n);

            return substr($s, 0, 57) . '...';
        }

        foreach my $key (sort keys %$config) {
            print with_diagnostic("debug",
                                  "In %config:", $key, " -> ",
                                  summarize(60, $$config{$key}));
        }

        croak("Unbound variable '$1' in $in");
    }

    open OUT, ">$out" or croak("Couldn't write $out ($!)");
    print OUT $contents;
    close OUT;
}

##################################################
#                                                #
##################################################
sub read_list {
    my ($line, $reader, $marker, $func) = @_;

    if($line =~ m@^<$marker>$@) {
        while(1) {
            $line = &$reader();

            die "EOF while searching for $marker" unless $line;
            last if($line =~ m@^</$marker>$@);
            &$func($line);
        }
    }
}

sub list_push {
    my ($listref) = @_;
    return sub { push @$listref, $_[0]; }
}

sub match_any_of {
    my ($line, $hash, $quoted, @any_of) = @_;

    $quoted = ($quoted eq 'quoted') ? 1 : 0;

    foreach my $what (@any_of) {
        $$hash{$what} = $1 if(not $quoted and $line =~ /^$what (.*)/);
        $$hash{$what} = $1 if($quoted and $line =~ /^$what \"(.*)\"/);
    }
}

##################################################
#                                                #
##################################################
sub make_reader {
    my $filename = $_[0];

    croak("make_reader(): Arg was undef") if not defined $filename;

    open FILE, "<$filename" or
        croak("Couldn't read $filename ($!)");

    return sub {
        my $line = '';
        while(1) {
            my $line = <FILE>;
            last unless defined($line);

            chomp($line);
            $line =~ s/#.*//;
            $line =~ s/^\s*//;
            $line =~ s/\s*$//;
            $line =~ s/\s\s*/ /;
            $line =~ s/\t/ /;
            return $line if $line ne '';
        }
        close FILE;
        return undef;
    }
}

##################################################
#                                                #
##################################################
sub read_info_files {
    my ($config, $dir, $func) = @_;

    $dir = File::Spec->catdir($$config{'config-dir'}, $dir);

    my %allinfo;
    foreach my $file (dir_list($dir)) {
        my $fullpath = File::Spec->catfile($dir, $file);

        $file =~ s/.txt//;

        trace("reading $fullpath");
        %{$allinfo{$file}} = &$func($file, $fullpath);
    }

    return %allinfo;
}

sub read_module_files {
    my ($config) = @_;

    my %allinfo;

    my @modinfos;

    File::Find::find(
        { wanted => sub
          { if(-f $_ && /^info\.txt\z/s) {
              my $name = $File::Find::name;
              push @modinfos, $name;
            }
          }
        },
        $$config{'src-dir'});

    foreach my $modfile (@modinfos) {
        trace("reading $modfile");

        my ($volume,$dirs,$file) = File::Spec->splitpath($modfile);

        my @dirs = File::Spec->splitdir($dirs);
        my $moddir = $dirs[$#dirs-1];

        trace("module $moddir in $dirs $modfile");

        %{$allinfo{$moddir}} = get_module_info($dirs, $moddir, $modfile);
    }

    return %allinfo;
}

##################################################
#                                                #
##################################################

sub get_module_info {
   my ($dirs, $name, $modfile) = @_;
   my $reader = make_reader($modfile);

   my %info;

   $info{'name'} = $name;
   $info{'modinfo'} = $modfile;
   $info{'moddirs'} = $dirs;

   # Default module settings
   $info{'load_on'} = 'request'; # default unless specified
   $info{'uses_tr1'} = 'no';
   $info{'libs'} = {};
   $info{'use'} = 'no';

   my @dir_arr = File::Spec->splitdir($dirs);
   $info{'type'} = $dir_arr[$#dir_arr-2]; # cipher, hash, ...
   if($info{'type'} eq 'src') { $info{'type'} = $dir_arr[$#dir_arr-1]; }

   while($_ = &$reader()) {
       match_any_of($_, \%info, 'quoted', 'realname', 'note', 'type');
       match_any_of($_, \%info, 'unquoted', 'define', 'mp_bits',
                                'modset', 'load_on', 'uses_tr1');

       read_list($_, $reader, 'arch', list_push(\@{$info{'arch'}}));
       read_list($_, $reader, 'cc', list_push(\@{$info{'cc'}}));
       read_list($_, $reader, 'os', list_push(\@{$info{'os'}}));
       read_list($_, $reader, 'add', list_push(\@{$info{'add'}}));
       read_list($_, $reader, 'replace', list_push(\@{$info{'replace'}}));
       read_list($_, $reader, 'ignore', list_push(\@{$info{'ignore'}}));
       read_list($_, $reader, 'requires', list_push(\@{$info{'requires'}}));

       read_list($_, $reader, 'libs',
                 sub {
                     my $line = $_[0];
                     $line =~ m/^([\w!,]*) -> ([\w.,-]*)$/;
                     $info{'libs'}{$1} = $2;
                 });

       if(/^require_version /) {
           if(/^require_version (\d+)\.(\d+)\.(\d+)$/) {
               my $version = "$1.$2.$3";
               my $needed_version = 100*$1 + 10*$2 + $3;

               my $have_version =
                   100*$MAJOR_VERSION + 10*$MINOR_VERSION + $PATCH_VERSION;

               if($needed_version > $have_version) {
                   warning("Module $name needs v$version; disabling");
                   return ();
               }
           }
           else {
               croak("In module $name, bad version requirement '$_'");
           }
       }
   }

   return %info;
}

##################################################
#                                                #
##################################################
sub get_arch_info {
    my ($name,$file) = @_;
    my $reader = make_reader($file);

    my %info;
    $info{'name'} = $name;

    while($_ = &$reader()) {
        match_any_of($_, \%info, 'quoted', 'realname');
        match_any_of($_, \%info, 'unquoted',
                     'default_submodel', 'endian', 'unaligned');

        read_list($_, $reader, 'aliases', list_push(\@{$info{'aliases'}}));
        read_list($_, $reader, 'submodels', list_push(\@{$info{'submodels'}}));

        read_list($_, $reader, 'submodel_aliases',
                  sub {
                      my $line = $_[0];
                      $line =~ m/^(\S*) -> (\S*)$/;
                      $info{'submodel_aliases'}{$1} = $2;
                  });
    }
    return %info;
}

##################################################
#                                                #
##################################################
sub get_os_info {
    my ($name,$file) = @_;
    my $reader = make_reader($file);

    my %info;
    $info{'name'} = $name;

    while($_ = &$reader()) {
        match_any_of($_, \%info,
                     'quoted', 'realname', 'ar_command',
                     'install_cmd_data', 'install_cmd_exec');

        match_any_of($_, \%info, 'unquoted',
                     'os_type',
                     'obj_suffix',
                     'so_suffix',
                     'static_suffix',
                     'install_root',
                     'header_dir',
                     'lib_dir', 'doc_dir',
                     'ar_needs_ranlib');

        read_list($_, $reader, 'aliases', list_push(\@{$info{'aliases'}}));

        read_list($_, $reader, 'target_features',
                  list_push(\@{$info{'target_features'}}));

        read_list($_, $reader, 'supports_shared',
                  list_push(\@{$info{'supports_shared'}}));
    }
    return %info;
}

##################################################
# Read a file from misc/config/cc and set the values from
# there into a hash for later reference
##################################################
sub get_cc_info {
    my ($name,$file) = @_;
    my $reader = make_reader($file);

    my %info;
    $info{'name'} = $name;

    while($_ = &$reader()) {
        match_any_of($_, \%info, 'quoted',
                     'realname',
                     'binary_name',
                     'compile_option',
                     'output_to_option',
                     'add_include_dir_option',
                     'add_lib_dir_option',
                     'add_lib_option',
                     'lib_opt_flags',
                     'check_opt_flags',
                     'dll_import_flags',
                     'dll_export_flags',
                     'lang_flags',
                     'warning_flags',
                     'shared_flags',
                     'ar_command',
                     'debug_flags',
                     'no_debug_flags');

        match_any_of($_, \%info, 'unquoted',
                     'makefile_style',
                     'compiler_has_tr1');

        sub quoted_mapping {
            my $hashref = $_[0];
            return sub {
                my $line = $_[0];
                $line =~ m/^(\S*) -> \"(.*)\"$/;
                $$hashref{$1} = $2;
            }
        }

        read_list($_, $reader, 'mach_abi_linking',
                  quoted_mapping(\%{$info{'mach_abi_linking'}}));
        read_list($_, $reader, 'so_link_flags',
                  quoted_mapping(\%{$info{'so_link_flags'}}));

        read_list($_, $reader, 'mach_opt',
                  sub {
                      my $line = $_[0];
                      $line =~ m/^(\S*) -> \"(.*)\" ?(.*)?$/;
                      $info{'mach_opt_flags'}{$1} = $2;
                      $info{'mach_opt_re'}{$1} = $3;
                  });

    }
    return %info;
}

##################################################
#                                                #
##################################################
sub write_pkg_config {
    my ($config) = @_;

    return if($$config{'os'} eq 'generic' or
              $$config{'os'} eq 'windows');

    $$config{'link_to'} = libs('-l', '', 'm', @{$$config{'mod_libs'}});

    my $botan_config = $$config{'botan_config'};

    process_template(
       File::Spec->catfile($$config{'config-dir'}, 'botan-config.in'),
                     $botan_config, $config);
    chmod 0755, $botan_config;

    process_template(
       File::Spec->catfile($$config{'config-dir'}, 'botan.pc.in'),
                           $$config{'botan_pkgconfig'}, $config);

    delete $$config{'link_to'};
}

##################################################
#                                                #
##################################################
sub file_list {
    my ($put_in, $from, $to, %files) = @_;

    my $list = '';

    my $spaces = 16;

    foreach (sort keys %files) {
        my $file = $_;

        $file =~ s/$from/$to/ if(defined($from) and defined($to));

        my $dir = $files{$_};
        $dir = $put_in if defined $put_in;

        if(defined($dir)) {
            $list .= File::Spec->catfile ($dir, $file);
        }
        else {
            $list .= $file;
        }

        $list .= " \\\n                ";
    }

    $list =~ s/\\\n +$//; # remove trailing escape

    return $list;
}

sub build_cmds {
    my ($config, $dir, $flags, $files) = @_;

    my $obj_suffix = $$config{'obj_suffix'};

    my %ccinfo = my_compiler($config);

    my $inc = $ccinfo{'add_include_dir_option'};
    my $from = $ccinfo{'compile_option'};
    my $to = $ccinfo{'output_to_option'};

    my $inc_dir = $$config{'build_include'};

    # Probably replace by defaults to -I -c -o
    croak('undef value found in build_cmds')
        unless defined($inc) and defined($from) and defined($to);

    my $bld_line = "\t\$(CXX) $inc$inc_dir $flags $from\$? $to\$@";

    my @output_lines;

    foreach (sort keys %$files) {
        my $src_file = File::Spec->catfile($$files{$_}, $_);
        my $obj_file = File::Spec->catfile($dir, $_);

        $obj_file =~ s/\.cpp$/.$obj_suffix/;
        $obj_file =~ s/\.c$/.$obj_suffix/;
        $obj_file =~ s/\.S$/.$obj_suffix/;

        push @output_lines, "$obj_file: $src_file\n$bld_line";
    }

    return join("\n\n", @output_lines);
}

sub determine_config {
   my ($config) = @_;

   sub os_ar_command {
       return os_info_for(shift, 'ar_command');
   }

   sub append_if {
       my($var,$addme,$cond) = @_;

       croak('append_if: reference was undef') unless defined $var;

       if($cond and $addme ne '') {
           $$var .= ' ' unless($$var eq '' or $$var =~ / $/);
           $$var .= $addme;
       }
   }

   sub append_ifdef {
       my($var,$addme) = @_;
       append_if($var, $addme, defined($addme));
   }

   my $empty_if_nil = sub {
       my $val = $_[0];
       return $val if defined($val);
       return '';
   };

   my %ccinfo = my_compiler($config);

   my $lang_flags = '';
   append_ifdef(\$lang_flags, $ccinfo{'lang_flags'});
   append_if(\$lang_flags, "-fpermissive", $$config{'gcc_bug'});

   my $debug = $$config{'debug'};

   my $lib_opt_flags = '';
   append_ifdef(\$lib_opt_flags, $ccinfo{'lib_opt_flags'});
   append_ifdef(\$lib_opt_flags, $ccinfo{'debug_flags'}) if($debug);
   append_ifdef(\$lib_opt_flags, $ccinfo{'no_debug_flags'}) if(!$debug);

   # This is a default that works on most Unix and Unix-like systems
   my $ar_command = 'ar crs';
   my $ranlib_command = 'true'; # almost no systems need it anymore

   # See if there are any over-riding methods. We presume if CC is creating
   # the static libs, it knows how to create the index itself.

   my $os = $$config{'os'};

   if($ccinfo{'ar_command'}) {
       $ar_command = $ccinfo{'ar_command'};
   }
   elsif(os_ar_command($os))
   {
       $ar_command = os_ar_command($os);
       $ranlib_command = 'ranlib'
           if(os_info_for($os, 'ar_needs_ranlib') eq 'yes');
   }

   my $arch = $$config{'arch'};

   my $abi_opts = '';
   append_ifdef(\$abi_opts, $ccinfo{'mach_abi_linking'}{$arch});
   append_ifdef(\$abi_opts, $ccinfo{'mach_abi_linking'}{$os});
   append_ifdef(\$abi_opts, $ccinfo{'mach_abi_linking'}{'all'});
   $abi_opts = ' ' . $abi_opts if($abi_opts ne '');

   if($$config{'shared'} eq 'yes' and
      (in_array('all', $OPERATING_SYSTEM{$os}{'supports_shared'}) or
       in_array($$config{'compiler'},
                $OPERATING_SYSTEM{$os}{'supports_shared'}))) {

       $$config{'shared_flags'} = &$empty_if_nil($ccinfo{'shared_flags'});
       $$config{'so_link'} = &$empty_if_nil($ccinfo{'so_link_flags'}{$os});

       if($$config{'so_link'} eq '') {
           $$config{'so_link'} =
               &$empty_if_nil($ccinfo{'so_link_flags'}{'default'})
       }

       if($$config{'shared_flags'} eq '' and $$config{'so_link'} eq '') {
           $$config{'shared'} = 'no';

           warning($$config{'compiler'}, ' has no shared object flags set ',
                   "for $os; disabling shared");
       }
   }
   else {
       autoconfig("No shared library generated with " .
                  $$config{'compiler'} . " on " . $$config{'os'});

       $$config{'shared'} = 'no';
       $$config{'shared_flags'} = '';
       $$config{'so_link'} = '';
   }

   add_to($config, {
       'cc'              => $ccinfo{'binary_name'} . $abi_opts,
       'lib_opt'         => $lib_opt_flags,
       'check_opt'       => &$empty_if_nil($ccinfo{'check_opt_flags'}),
       'mach_opt'        => mach_opt($config),
       'lang_flags'      => $lang_flags,
       'warn_flags'      => &$empty_if_nil($ccinfo{'warning_flags'}),

       'ar_command'      => $ar_command,
       'ranlib_command'  => $ranlib_command,
       'static_suffix'   => os_info_for($os, 'static_suffix'),
       'so_suffix'       => os_info_for($os, 'so_suffix'),
       'obj_suffix'      => os_info_for($os, 'obj_suffix'),

       'dll_export_flags' => $ccinfo{'dll_export_flags'},
       'dll_import_flags' => $ccinfo{'dll_import_flags'},

       'install_cmd_exec' => os_info_for($os, 'install_cmd_exec'),
       'install_cmd_data' => os_info_for($os, 'install_cmd_data'),
       });
}

sub generate_makefile {
   my ($config) = @_;

   my $is_in_doc_dir =
       sub { -e File::Spec->catfile($$config{'doc_src_dir'}, $_[0]) };

   my $docs = file_list(undef, undef, undef,
                        map_to($$config{'doc_src_dir'},
                               grep { &$is_in_doc_dir($_); } @DOCS));

   $docs .= File::Spec->catfile($$config{'base-dir'}, 'readme.txt');

   my $includes = file_list(undef, undef, undef,
                            map_to($$config{'build_include_botan'},
                                   keys %{$$config{'includes'}}));

   my $lib_objs = file_list($$config{'build_lib'}, '(\.cpp$|\.c$|\.S$)',
                            '.' . $$config{'obj_suffix'},
                            %{$$config{'sources'}});

   my $check_objs = file_list($$config{'build_check'}, '.cpp',
                              '.' . $$config{'obj_suffix'},
                              %{$$config{'check_src'}}),

   my $lib_build_cmds = build_cmds($config, $$config{'build_lib'},
                                   '$(LIB_FLAGS)', $$config{'sources'});

   my $check_build_cmds = build_cmds($config, $$config{'build_check'},
                                     '$(CHECK_FLAGS)', $$config{'check_src'});

   add_to($config, {
       'lib_objs' => $lib_objs,
       'check_objs' => $check_objs,
       'lib_build_cmds' => $lib_build_cmds,
       'check_build_cmds' => $check_build_cmds,

       'doc_files'       => $docs,
       'include_files'   => $includes
       });

   my $template_dir = File::Spec->catdir($$config{'config-dir'}, 'makefile');
   my $template = undef;

   my $make_style = $$config{'make_style'};

   if($make_style eq 'unix') {
       $template = File::Spec->catfile($template_dir, 'unix.in');

       $template = File::Spec->catfile($template_dir, 'unix_shr.in')
           if($$config{'shared'} eq 'yes');

       add_to($config, {
           'link_to' => libs('-l', '', 'm', @{$$config{'mod_libs'}}),
       });
   }
   elsif($make_style eq 'nmake') {
       $template = File::Spec->catfile($template_dir, 'nmake.in');

       add_to($config, {
           'shared' => 'no',
           'link_to' => libs('', '', '', @{$$config{'mod_libs'}}),
       });
   }

   croak("Don't know about makefile format '$make_style'")
       unless defined $template;

   trace("'$make_style' -> '$template'");

   process_template($template, $$config{'makefile'}, $config);

   autoconfig("Wrote ${make_style}-style makefile in $$config{'makefile'}");
}

##################################################
# Configuration Guessing                         #
##################################################
sub guess_cpu_from_this
{
    my $cpuinfo = lc $_[0];

    $cpuinfo =~ s/\(r\)//g;
    $cpuinfo =~ s/\(tm\)//g;
    $cpuinfo =~ s/ //g;

    trace("guess_cpu_from_this($cpuinfo)");

    # The 32-bit SPARC stuff is impossible to match to arch type easily, and
    # anyway the uname stuff will pick up that it's a SPARC so it doesn't
    # matter. If it's an Ultra, assume a 32-bit userspace, no 64-bit code
    # possible; that's the most common setup right now anyway
    return 'sparc32-v9' if($cpuinfo =~ /ultrasparc/);

    # Should probably do this once and cache it
    my @names;
    my %all_alias;

    foreach my $arch (keys %CPU) {
        my %info = %{$CPU{$arch}};

        foreach my $submodel (@{$info{'submodels'}}) {
            push @names, $submodel;
        }

        if(defined($info{'submodel_aliases'})) {
            my %submodel_aliases = %{$info{'submodel_aliases'}};
            foreach my $sm_alias (keys %submodel_aliases) {
                push @names, $sm_alias;
                $all_alias{$sm_alias} = $submodel_aliases{$sm_alias};
            }
        }
    }

    @names = sort { length($b) <=> length($a) } @names;

    foreach my $name (@names) {
        if($cpuinfo =~ $name) {
            trace("Matched '$cpuinfo' against '$name'");

            return $all_alias{$name} if defined($all_alias{$name});

            return $name;
        }
    }

    trace("Couldn't match $cpuinfo against any submodels");

    # No match? Try arch names. Reset @names
    @names = ();

    foreach my $arch (keys %CPU) {
        my %info = %{$CPU{$arch}};

        push @names, $info{'name'};

        foreach my $alias (@{$info{'aliases'}}) {
            push @names, $alias;
        }
    }

    @names = sort { length($b) <=> length($a) } @names;

    foreach my $name (@names) {
        if($cpuinfo =~ $name) {
            trace("Matched '$cpuinfo' against '$name'");
            return $name;
        }
    }

    return '';
}

# Do some WAGing and see if we can figure out what system we are. Think about
# this as a really moronic config.guess
sub guess_compiler
{
    my @CCS = ('gcc', 'msvc', 'icc', 'compaq', 'kai');

    # First try the CC enviornmental variable, if it's set
    if(defined($ENV{CC}))
    {
        my @new_CCS = ($ENV{CC});
        foreach my $cc (@CCS) { push @new_CCS, $cc; }
        @CCS = @new_CCS;
    }

    foreach (@CCS)
    {
        my $bin_name = $COMPILER{$_}{'binary_name'};
        if(which($bin_name) ne '') {
            autoconfig("Guessing to use $_ as the compiler " .
                       "(use --cc to set)");
            return $_;
        }
    }

    croak(
        "Can't find a usable C++ compiler, is PATH right?\n" .
        "You might need to run with the --cc option (try $0 --help)\n");
}

sub guess_os
{
     sub recognize_os
     {
         my $os = os_alias($_[0]);
         if(defined($OPERATING_SYSTEM{$os})) {
             autoconfig("Guessing operating system is $os (use --os to set)");
             return $os;
         }
         return undef;
     }

    my $guess = recognize_os($^O);
    return $guess if $guess;

    trace("Can't guess os from $^O");

    my $uname = $$config{'uname'};

    if($uname ne '') {
        $guess = recognize_os($uname);
        return $guess if $guess;
        trace("Can't guess os from $uname");
    }

    warning("Unknown OS ('$^O', '$uname'), falling back to generic code");
    return 'generic';
}

sub guess_cpu
{
    # If we have /proc/cpuinfo, try to get nice specific information about
    # what kind of CPU we're running on.
    my $cpuinfo = '/proc/cpuinfo';

    if(defined($ENV{'CPUINFO'})) {
        my $cpuinfo_env = $ENV{'CPUINFO'};

        if(-e $cpuinfo_env and -r $cpuinfo_env) {
            autoconfig("Will use $cpuinfo_env as /proc/cpuinfo");
            $cpuinfo = $cpuinfo_env;
        } else {
            warn("Could not read from ENV /proc/cpuinfo ($cpuinfo_env)");
        }
    }

    if(-e $cpuinfo and -r $cpuinfo)
    {
        open CPUINFO, $cpuinfo or die "Could not read $cpuinfo\n";

        while(<CPUINFO>) {

            chomp;
            $_ =~ s/\t/ /g;
            $_ =~ s/ +/ /g;

            if($_ =~ /^cpu +: (.*)/ or
               $_ =~ /^model name +: (.*)/)
            {
                my $cpu = guess_cpu_from_this($1);
                if($cpu ne '') {
                    autoconfig("Guessing CPU using $cpuinfo line '$_'");
                    autoconfig("Guessing CPU is a $cpu (use --cpu to set)");
                    return $cpu;
                }
            }
        }

        autoconfig("*** Could not figure out CPU based on $cpuinfo");
        autoconfig("*** Please mail contents to lloyd\@randombit.net");
    }

    sub known_arch {
        my ($name) = @_;

        foreach my $arch (keys %CPU) {
            my %info = %{$CPU{$arch}};

            return 1 if $name eq $info{'name'};
            foreach my $submodel (@{$info{'submodels'}}) {
                return 1 if $name eq $submodel;
            }

            foreach my $alias (@{$info{'aliases'}}) {
                return 1 if $name eq $alias;
            }

            if(defined($info{'submodel_aliases'})) {
                my %submodel_aliases = %{$info{'submodel_aliases'}};
                foreach my $sm_alias (keys %submodel_aliases) {
                    return 1 if $name eq $sm_alias;
                }
            }
        }

        my $guess = guess_cpu_from_this($name);

        return 0 if($guess eq $name or $guess eq '');

        return known_arch($guess);
    }

    my $uname = $$config{'uname'};
    if($uname ne '') {
        my $cpu = guess_cpu_from_this($uname);

        if($cpu ne '')
        {
            autoconfig("Guessing CPU using uname output '$uname'");
            autoconfig("Guessing CPU is a $cpu (use --cpu to set)");

            return $cpu if known_arch($cpu);
        }
    }

    my $config_archname = $Config{'archname'};
    my $cpu = guess_cpu_from_this($config_archname);

    if($cpu ne '')
    {
        autoconfig("Guessing CPU using Config{archname} '$config_archname'");
        autoconfig("Guessing CPU is a $cpu (use --cpu to set)");

        return $cpu if known_arch($cpu);
    }

    warning("Could not determine CPU type (try --cpu option)");
    return 'generic';
}
