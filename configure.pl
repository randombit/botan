#!/usr/bin/perl -w

require 5.006;

use strict;
use Getopt::Long;
use File::Spec;
use File::Copy;

my $MAJOR_VERSION = 1;
my $MINOR_VERSION = 5;
my $PATCH_VERSION = 11;

##################################################
# Data                                           #
##################################################
my (%CPU, %OPERATING_SYSTEM, %COMPILER, %MODULES);

my @DOCS = (
   'api.pdf', 'tutorial.pdf', 'fips140.pdf',
   'api.tex', 'tutorial.tex', 'fips140.tex',
   'credits.txt', 'info.txt', 'license.txt', 'log.txt',
   'thanks.txt', 'todo.txt', 'botan.rc', 'pgpkeys.asc');

##################################################
# Run main() and Quit                            #
##################################################
main();
exit;

##################################################
# Main Driver                                    #
##################################################
sub main {
    my $ARCH_DIR = File::Spec->catdir('misc', 'config', 'arch');
    my $OS_DIR = File::Spec->catdir('misc', 'config', 'os');
    my $CC_DIR = File::Spec->catdir('misc', 'config', 'cc');

    %CPU = read_info_files($ARCH_DIR, \&get_arch_info);
    %OPERATING_SYSTEM = read_info_files($OS_DIR, \&get_os_info);
    %COMPILER = read_info_files($CC_DIR, \&get_cc_info);
    %MODULES = read_module_files('modules');

    my $config = {};

    add_to($config, {
        'version_major' => $MAJOR_VERSION,
        'version_minor' => $MINOR_VERSION,
        'version_patch' => $PATCH_VERSION,
        'version'       => "$MAJOR_VERSION.$MINOR_VERSION.$PATCH_VERSION"
        });

    my ($prefix, $doc_dir, $lib_dir) = ('', '', '');
    my $shared = 'yes';
    my ($debug, $dumb_gcc) = (0, 0);
    my $build_dir = 'build';
    my ($make_style, $module_set, $local_config) = ('', '', '');

    my $autoconfig = 1;
    my @using_mods;

    GetOptions('debug' => sub { $debug = 1; },
               'disable-shared' => sub { $shared = 'no'; },
               'noauto' => sub { $autoconfig = 0 },
               'dumb-gcc|gcc295x' => sub { $dumb_gcc = 1; },
               'make-style=s' => \$make_style,
               'modules=s' => \@using_mods,
               'module-set=s' => \$module_set,
               'prefix=s' => \$prefix,
               'docdir=s' => \$doc_dir,
               'libdir=s' => \$lib_dir,
               'build-dir=s' => \$build_dir,
               'local-config=s' => \$local_config,
               'help' => sub { help(); }
               );

    add_to($config, {
        'debug'         => $debug,
        'shared'        => $shared,
        'build'         => $build_dir,
        'local_config'  => slurp_file($local_config),
        });

    my $cc_os_cpu_set = '';
    if($#ARGV == 0) { $cc_os_cpu_set = $ARGV[0]; }
    elsif($autoconfig) {
        $cc_os_cpu_set = guess_triple();
        print "(autoconfig): Guessing your system config is $cc_os_cpu_set\n";
    }
    else { help(); }

    my ($cc,$os,$submodel) = split(/-/,$cc_os_cpu_set,3);
    if(!defined($cc) or !defined($os) or !defined($submodel)) { help(); }

    # hacks
    if($cc eq 'gcc' && $dumb_gcc != 1)
    {
        my $gcc_version = '';

        # Stupid Apple. At least they fixed it after 10.2
        if($os eq 'darwin') { $gcc_version = `c++ -v 2>&1`; }
        else { $gcc_version = `g++ -v 2>&1`; }

        $gcc_version = '' if not defined $gcc_version;

        # GCC 2.95.x and 3.[34] are busted in handling long long in
        # C++. The third check is because on Cygwin (at least for me)
        # $gcc_version doesn't get the output from g++, not sure
        # what's up with that. If it's Cygwin and we didn't get
        # output, assume it's a buggy GCC. There is no reduction in
        # code quality, etc, so even if we're wrong it's no big deal.

        if(($gcc_version =~ /4\.[01]/) ||
           ($gcc_version =~ /3\.[34]/) ||
           ($gcc_version =~ /2\.95\.[0-4]/) ||
           ($gcc_version eq '' && $^O eq 'cygwin'))
        {
            warning("Enabling -fpermissive to work around possible GCC bug");
            $dumb_gcc = 1;
        }
        if($gcc_version =~ /2\.95\.[0-4]/)
        {
            warning("GCC 2.95.x issues many spurious warnings during build");
        }
    }

    error("Compiler $cc isn't known") unless defined($COMPILER{$cc});

    $os = os_alias($os);
    error("OS $os isn't known") unless
        ($os eq 'generic' or defined($OPERATING_SYSTEM{$os}));

    my $arch = undef;
    ($arch, $submodel) = figure_out_arch($submodel);

    error(realname($os), " doesn't run on $arch ($submodel)")
        unless($arch eq 'generic' or $os eq 'generic' or
               in_array($arch, $OPERATING_SYSTEM{$os}{'arch'}));

    error(realname($cc), " doesn't run on $arch ($submodel)")
        unless($arch eq 'generic' or
               (in_array($arch, $COMPILER{$cc}{'arch'})));

    error(realname($cc), " doesn't run on ", realname($os))
        unless($os eq 'generic' or (in_array($os, $COMPILER{$cc}{'os'})));

    my %MODULE_SETS =
        (
         'unix' => [ 'alloc_mmap', 'es_egd', 'es_ftw', 'es_unix', 'fd_unix',
                     'tm_unix' ],
         'beos' => [ 'es_beos', 'es_unix', 'fd_unix', 'tm_unix' ],
         'win32' => ['es_capi', 'es_win32', 'mux_win32', 'tm_win32' ],
         );

    error("Module set $module_set isn't known")
        if($module_set && !defined($MODULE_SETS{$module_set}));

    if($module_set) {
        foreach (@{ $MODULE_SETS{$module_set} }) { push @using_mods,$_; }
    }

    @using_mods = grep {/./} split(/,/,join(',',@using_mods));

    if($autoconfig)
    {
        foreach my $mod (guess_mods($cc,$os,$arch,$submodel))
        {
            print "  (autoconfig): Enabling module $mod\n"
                unless(in_array($mod, \@using_mods));

            push @using_mods, $mod;
        }
    }

    # Uniqify @using_mods
    my %uniqed_mods = map { $_ => undef } @using_mods;
    @using_mods = sort keys %uniqed_mods;

    foreach (@using_mods) {
        error("Module $_ isn't known (try --help)")
            unless(exists($MODULES{$_}));
    }

    my $list_checks = sub {
        my @list = dir_list('checks');
        @list = grep { !/\.dat$/ } grep { !/^keys$/ } grep { !/\.h$/ } @list;
        return map { $_ => 'checks' } @list;
    };

    $make_style = $COMPILER{$cc}{'makefile_style'} unless($make_style);

    add_to($config, {
        'compiler'      => $cc,
        'os'            => $os,
        'arch'          => $arch,
        'submodel'      => $submodel,

        'make_style'    => $make_style,
        'gcc_bug'       => $dumb_gcc,

        'prefix'        => os_install_info($os, 'install_root'),
        'libdir'        => os_install_info($os, 'lib_dir'),
        'docdir'        => os_install_info($os, 'doc_dir'),

        'includedir'    => os_install_info($os, 'header_dir'),

        'build_lib'     => File::Spec->catdir($$config{'build'}, 'lib'),
        'build_check'   => File::Spec->catdir($$config{'build'}, 'checks'),
        'build_include' => File::Spec->catdir($$config{'build'}, 'include'),

        'modules'       => [ @using_mods ],
        'mp_bits'       => find_mp_bits(@using_mods),
        'mod_libs'      => [ using_libs($os, @using_mods) ],

        'sources'       => { map { $_ => 'src' } dir_list('src') },
        'includes'      => { map { $_ => 'include' } dir_list('include') },
        'check_src'     => { &$list_checks() }
        });

    $$config{'prefix'} = $prefix if($prefix ne '');
    $$config{'libdir'} = $lib_dir if($lib_dir ne '');
    $$config{'docdir'} = $doc_dir if($doc_dir ne '');

    foreach my $mod (@using_mods) {
        load_module($MODULES{$mod}, $config);
    }

    add_to($config, {
        'defines' => defines($config),

        'build_include_botan' =>
            File::Spec->catdir($$config{'build_include'}, 'botan')
        });

    mkdirs($$config{'build'},
           $$config{'build_include'}, $$config{'build_include_botan'},
           $$config{'build_lib'}, $$config{'build_check'});

    print_pkg_config($config);

    process_template(File::Spec->catfile('misc', 'config', 'buildh.in'),
                     File::Spec->catfile($$config{'build'}, 'build.h'),
                     $config);
    $$config{'includes'}{'build.h'} = $$config{'build'};

    clean_out_dir($$config{'build_include_botan'});
    copy_files($$config{'build_include_botan'}, $$config{'includes'});

    generate_makefile($config);
}

##################################################
# Diagnostics                                    #
##################################################
sub error {
    my $str = '(error): ';
    foreach(@_) { $str .= $_; }
    $str .= "\n";
    die $str;
}

sub warning {
    my $str = '(note): ';
    foreach(@_) { $str .= $_; }
    $str .= "\n";
    warn $str;
}

sub trace {
    my $tracing = 1;
    return unless $tracing;

    my (undef, undef, $line1) = caller(0);
    my (undef, undef, $line2, $func1) = caller(1);
    my (undef, undef, undef, $func2) = caller(2);

    my ($sec,$min) = localtime;

    my $str = "(trace func1:$line1 | $func2:$line2): $min:$sec";
    foreach(@_) { $str .= $_; }
    $str .= "\n";
    warn $str;
}

##################################################
# Display Help                                   #
##################################################
sub help {
   print <<ENDOFHELP;
Usage: $0 [options] CC-OS-CPU

See doc/building.pdf for more information about this program.

Options:
  --prefix=PATH:       set the base installation directory
  --libdir=PATH:       install library files in \${prefix}/\${libdir}
  --docdir=PATH:       install documentation in \${prefix}/\${docdir}
  --build-dir=DIR:     setup the build in DIR
  --local-config=FILE: include the contents of FILE into build.h

  --modules=MODS:      add module(s) MODS to the library.
  --module-set=SET:    add a pre-specified set of modules (unix|win32|beos)

  --debug:             set compiler flags for debugging
  --disable-shared:    disable building shared libararies
  --noauto:            disable autoconfiguration
  --make-style=STYLE:  override the guess as to what type of makefile to use

You may use 'generic' for OS or CPU (useful if your OS or CPU isn't listed).

CPU can be a generic family name or a specific model name. Common aliases are
supported but not listed. Choosing a specific submodel will usually result in
code that will not run on earlier versions of that architecture.

ENDOFHELP

   my $print_listing = sub {
       my ($header, $hash) = @_;
       print "$header: ";
       my $len = length "$header: ";

       foreach my $name (sort keys %$hash) {
           if($len > 71) {
               print "\n   ";
               $len = 3;
           }
           print "$name ";
           $len += length "$name ";
       }

       print "\n";
   };

   &$print_listing('CC', \%COMPILER);
   &$print_listing('OS', \%OPERATING_SYSTEM);
   &$print_listing('CPU', \%CPU);
   &$print_listing('Modules', \%MODULES) if(%MODULES);
   exit;
   }

##################################################
# Functions to search the info tables            #
##################################################
sub figure_out_arch {
    my ($name) = @_;
    return ('generic', 'generic') if($name eq 'generic');

    my $submodel_alias = sub {
        my ($name,$info) = @_;

        my %info = %{$info};

        foreach my $submodel (@{$info{'submodels'}}) {
            return $submodel if ($name eq $submodel);
        }

        return '' unless defined $info{'submodel_aliases'};
        my %sm_aliases = %{$info{'submodel_aliases'}};

        foreach my $alias (keys %sm_aliases) {
            my $official = $sm_aliases{$alias};
            return $official if($alias eq $name);
        }
        return '';
    };

    my $find_arch = sub {
        my $name = $_[0];

        foreach my $arch (keys %CPU) {
            my %info = %{$CPU{$arch}};

            return $arch if ($name eq $arch);

            foreach my $alias (@{$info{'aliases'}}) {
                return $arch if ($name eq $alias);
            }

            foreach my $submodel (@{$info{'submodels'}}) {
                return $arch if ($name eq $submodel);
            }

            foreach my $submodel (keys %{$info{'submodel_aliases'}}) {
                return $arch if ($name eq $submodel);
            }
        }
        return undef;
    };

    my $arch = &$find_arch($name);
    error("Arch type $name isn't known") unless defined $arch;

    my %archinfo = %{ $CPU{$arch} };

    my $submodel = &$submodel_alias($name, \%archinfo);

    if($submodel eq '') {
        $submodel = $archinfo{'default_submodel'};

        warning("Using $submodel as default type for family ", realname($arch))
           if($submodel ne $arch);
    }

    error("Couldn't figure out arch type of $name")
        unless defined($arch) and defined($submodel);

    return ($arch,$submodel);
}

sub os_alias {
    my $name = $_[0];

    foreach my $os (keys %OPERATING_SYSTEM) {
        foreach my $alias (@{$OPERATING_SYSTEM{$os}{'aliases'}}) {
            return $os if($alias eq $name);
        }
    }

    return $name;
}

sub os_info_for {
    my ($os,$what) = @_;

    die "Internal error: os_info_for called with an os of defaults\n"
        if($os eq 'defaults');

    my $result = '';

    if(defined($OPERATING_SYSTEM{$os})) {
        my %osinfo = %{$OPERATING_SYSTEM{$os}};
        $result = $osinfo{$what};
    }

    if(!defined($result) or $result eq '') {
        $result = $OPERATING_SYSTEM{'defaults'}{$what};
    }

    return $result;
}

sub os_install_info {
    my ($os,$what) = @_;

    my $result = $OPERATING_SYSTEM{$os}{$what};

    if(defined($result) and $result ne '') {
        return $result;
    }

    return $OPERATING_SYSTEM{'defaults'}{$what};
}

sub mach_opt {
    my ($config) = @_;

    my %ccinfo = %{$COMPILER{$$config{'compiler'}}};

    # Nothing we can do in that case
    return '' unless defined($ccinfo{'mach_opt_flags'});

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
   my ($os,@using) = @_;
   my %libs;

   foreach my $mod (@using) {
      my %MOD_LIBS = %{ $MODULES{$mod}{'libs'} };
      foreach my $mod_os (keys %MOD_LIBS) {
          next if($mod_os =~ /^all!$os$/);
          next if($mod_os =~ /^all!$os,/);
          next if($mod_os =~ /^all!.*,${os}$/);
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
sub copy_files {
   my ($include_dir, $files) = @_;

   my $link_up = sub {
       my ($dir, $file) = @_;
       my $updir = File::Spec->updir();
       portable_symlink(File::Spec->catfile($updir, $updir, $updir,
                                            $dir, $file),
                        $include_dir, $file);
   };

   foreach my $file (keys %$files) {
       &$link_up($$files{$file}, $file);
   }
}

sub dir_list {
    my ($dir) = @_;
    opendir(DIR, $dir) or die "Couldn't read directory $dir ($!)\n";

    my @listing = grep { $_ ne File::Spec->curdir() and
                         $_ ne File::Spec->updir() } readdir DIR;

    closedir DIR;
    return @listing;
}

sub clean_out_dir {
    my $dir = $_[0];

    foreach my $file (dir_list($dir)) {
        my $path = File::Spec->catfile($dir, $file);
        unlink $path or die "Could not unlink $path ($!)\n";
    }
}

sub mkdirs {
    my (@dirs) = @_;
    foreach my $dir (@dirs) {
        next if( -e $dir and -d $dir ); # skip it if it's already there
        mkdir($dir, 0777) or
            error("Could not create directory $dir ($!)");
    }
}

sub portable_symlink {
   my ($from, $to_dir, $to_fname) = @_;

   my $can_symlink = 0;
   my $can_link = 0;

   unless($^O eq 'MSWin32' or $^O eq 'dos' or $^O eq 'cygwin') {
       $can_symlink = eval { symlink("",""); 1 };
       $can_link = eval { link("",""); 1 };
   }

   chdir $to_dir or die "Can't chdir to $to_dir ($!)\n";

   if($can_symlink) {
       symlink $from, $to_fname or die "Can't symlink $from to $to_fname ($!)";
   }
   elsif($can_link) {
       link $from, $to_fname    or die "Can't link $from to $to_fname ($!)";
   }
   else {
       copy ($from, $to_fname)  or die "Can't copy $from to $to_fname ($!)";
   }

   my $go_up = File::Spec->splitdir($to_dir);
   for(my $j = 0; $j != $go_up; $j++) # return to where we were
   {
       chdir File::Spec->updir();
   }
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

    foreach my $modname (@modules_list) {
        my %modinfo = %{ $MODULES{$modname} };
        if($modinfo{'mp_bits'}) {
            if(defined($seen_mp_module) and $modinfo{'mp_bits'} != $mp_bits) {
                error("Inconsistent mp_bits requests from modules ",
                      $seen_mp_module, " and ", $modname);
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

    return $COMPILER{$arg}{'realname'} if defined $COMPILER{$arg};
    return $OPERATING_SYSTEM{$arg}{'realname'}
       if defined $OPERATING_SYSTEM{$arg};
    return $CPU{$arg}{'realname'} if defined $CPU{$arg};

    return $arg;
}

##################################################
#                                                #
##################################################
sub load_module {
    my ($module_ref, $config) = @_;

    my %module = %{$module_ref};
    my $modname = $module{'name'};

    my $works_on = sub {
        my ($what, @lst) = @_;
        return 1 if not @lst; # empty list -> no restrictions
        return in_array($what, \@lst);
    };

    # Check to see if everything is OK WRT system requirements
    my $os = $$config{'os'};
    if($os ne 'generic') {
        unless(&$works_on($os, @{$module{'os'}})) {
            error("Module '$modname' does not run on ", realname($os));
        }
    }

    my $arch = $$config{'arch'};
    if($arch ne 'generic') {
        my $sub = $$config{'submodel'};
        unless(&$works_on($arch, @{$module{'arch'}}) or
               &$works_on($sub, @{$module{'arch'}})) {

            error("Module '$modname' does not run on $arch/$sub");
        }
    }

    my $cc = $$config{'compiler'};
    unless(&$works_on($cc, @{$module{'cc'}})) {
        error("Module '$modname' does not work with ", realname($cc));
    }

    sub handle_files {
        my($modname, $config, $lst, $func) = @_;
        return unless defined($lst);
        foreach (sort @$lst) {
            &$func($modname, $config, $_);
        }
    }

    handle_files($modname, $config, $module{'replace'}, \&replace_file);
    handle_files($modname, $config, $module{'ignore'},  \&ignore_file);
    handle_files($modname, $config, $module{'add'},     \&add_file);

    if(defined($module{'note'})) {
        my $realname = $module{'realname'};
        my $note = $module{'note'};
        warning("$modname (\"$realname\"): $note\n");
    }
}

##################################################
#                                                #
##################################################
sub add_file {
    my ($modname, $config, $file) = @_;
    check_for_file($file, $modname, $modname);

    my $mod_dir = File::Spec->catdir('modules', $modname);

    if($file =~ /\.cpp$/ or $file =~ /\.S$/) {
        error("File $file already added from ", $$config{'sources'}{$file})
            if(defined($$config{'sources'}{$file}));

        $$config{'sources'}{$file} = $mod_dir;
    }
    elsif($file =~ /\.h$/) {
        error("File $file already added from ", $$config{'includes'}{$file})
            if(defined($$config{'includes'}{$file}));

        $$config{'includes'}{$file} = $mod_dir;
    }
    else {
        error("Not sure where to put $file");
    }
}

sub ignore_file {
    my ($modname, $config, $file) = @_;
    check_for_file($file, undef, $modname);

    if($file =~ /\.cpp$/ or $file =~ /\.S$/) {
        if(defined ($$config{'sources'}{$file})) {
            error("$modname - File $file modified from ",
                  $$config{'sources'}{$file})
                if($$config{'sources'}{$file} ne 'src');

            delete $$config{'sources'}{$file};
        }
    }
    elsif($file =~ /\.h$/) {
        if(defined ($$config{'includes'}{$file})) {
            error("$modname - File $file modified from ",
                  $$config{'includes'}{$file})
                if($$config{'includes'}{$file} ne 'include');

            delete $$config{'includes'}{$file};
        }
    }
    else { error("Not sure where to put $file"); }
}

# This works because ignore file always runs on files in the main source tree,
# and add always works on the file in the modules directory.
sub replace_file {
   my ($modname, $config, $file) = @_;
   ignore_file($modname, $config, $file);
   add_file($modname, $config, $file);
}

sub check_for_file {
   my ($file, $added_from, $modname) = @_;

   my $full_path = sub {
       my ($file,$modname) = @_;

       return File::Spec->catfile('modules', $modname, $file)
           if(defined($modname));

       return File::Spec->catfile('include', $file)
           if($file =~ /\.h$/);

       return File::Spec->catfile('src', $file)
           if($file =~ /\.cpp$/ or $file =~ /\.S$/);

       error("Not sure where to put $file");
   };

   $file = &$full_path($file, $added_from);

   error("Module $modname requires that file $file exist. This error\n      ",
       "should never occur; please contact the maintainers with details.")
       unless(-e $file);
}

##################################################
#                                                #
##################################################
sub process_template {
    my ($in, $out, $config) = @_;

    my $contents = slurp_file($in);

    foreach my $name (keys %$config) {
        my $val = $$config{$name};
        die unless defined $val;

        $contents =~ s/@\{var:$name\}/$val/g;

        unless($val eq 'no' or $val eq 'false') {
            $contents =~ s/\@\{if:$name (.*)\}/$1/g;
            $contents =~ s/\@\{if:$name (.*) (.*)\}/$1/g;
        } else {
            $contents =~ s/\@\{if:$name (.*)\}//g;
            $contents =~ s/\@\{if:$name (.*) (.*)\}/$2/g;
        }
    }

    if($contents =~ /@\{var:(.*)\}/ or
       $contents =~ /@\{if:(.*) /) {
        error("Unbound variable '$1' in $in");
    }

    open OUT, ">$out" or error("Couldn't write $out ($!)");
    print OUT $contents;
}

##################################################
#                                                #
##################################################
sub append_if {
    my($var,$addme,$cond) = @_;
    die unless defined $var;

    if($cond and $addme ne '') {
        $$var .= ' ' unless($$var eq '' or $$var =~ / $/);
        $$var .= $addme;
    }
}

sub append_ifdef {
    my($var,$addme) = @_;
    append_if($var, $addme, defined($addme));
}

sub read_hash {
    my ($line, $reader, $marker, $func) = @_;

    if($line =~ m@^<$marker>$@) {
        while(1) {
            $line = &$reader();
            last if($line =~ m@^</$marker>$@);
            &$func($line);
        }
    }
}

sub list_push {
    my ($listref) = @_;
    return sub { push @$listref, $_[0]; }
}

sub set_if {
    my ($line, $what, $var) = @_;
    $$var = $1 if($line =~ /^$what (.*)/);
}

sub set_if_quoted {
    my ($line, $what, $var) = @_;
    $$var = $1 if($line =~ /^$what \"(.*)\"/);
}

sub set_if_any {
    my ($func, $line, $hash, $any_of) = @_;
    foreach my $found (split(/:/, $any_of)) {
        &$func($line, $found, \$hash->{$found});
    }
}

##################################################
#                                                #
##################################################
sub make_reader {
    my $filename = $_[0];

    error("make_reader(): Arg was undef") if not defined $filename;

    open FILE, "<$filename" or
        error("Couldn't read $filename ($!)");

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
    my ($dir,$func) = @_;

    my %allinfo;
    foreach my $file (dir_list($dir)) {
        %{$allinfo{$file}} =
            &$func($file, File::Spec->catfile($dir, $file));
    }

    return %allinfo;
}

sub read_module_files {
    my ($moddir) = @_;

    my %allinfo;
    foreach my $dir (dir_list($moddir)) {
        my $modfile = File::Spec->catfile($moddir, $dir, 'modinfo.txt');
        %{$allinfo{$dir}} = get_module_info($dir, $modfile);
    }

    return %allinfo;
}

##################################################
#                                                #
##################################################
sub get_module_info {
   my ($name, $file) = @_;
   my $reader = make_reader($file);

   my %info;
   $info{'name'} = $name;
   $info{'external_libs'} = 0;
   $info{'libs'} = {};

   while($_ = &$reader()) {
       set_if_any(\&set_if_quoted, $_, \%info, 'realname:note');

       set_if_any(\&set_if, $_, \%info, 'define:mp_bits');

       $info{'external_libs'} = 1 if(/^uses_external_libs/);

       read_hash($_, $reader, 'arch', list_push(\@{$info{'arch'}}));
       read_hash($_, $reader, 'cc', list_push(\@{$info{'cc'}}));
       read_hash($_, $reader, 'os', list_push(\@{$info{'os'}}));
       read_hash($_, $reader, 'add', list_push(\@{$info{'add'}}));
       read_hash($_, $reader, 'replace', list_push(\@{$info{'replace'}}));
       read_hash($_, $reader, 'ignore', list_push(\@{$info{'ignore'}}));

       read_hash($_, $reader, 'libs',
                 sub {
                     my $line = $_[0];
                     $line =~ m/^([\w!,]*) -> ([\w,-]*)$/;
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
               error("In module $name, bad version requirement '$_'");
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
        set_if_any(\&set_if_quoted, $_, \%info, 'realname');
        set_if_any(\&set_if, $_, \%info, 'default_submodel');

        read_hash($_, $reader, 'aliases', list_push(\@{$info{'aliases'}}));
        read_hash($_, $reader, 'submodels', list_push(\@{$info{'submodels'}}));

        read_hash($_, $reader, 'submodel_aliases',
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
        set_if_any(\&set_if_quoted, $_, \%info, 'realname:ar_command');

        set_if_any(\&set_if, $_, \%info,
                   'os_type:obj_suffix:so_suffix:static_suffix:' .
                   'install_root:header_dir:lib_dir:doc_dir:' .
                   'install_user:install_group:install_cmd:ar_needs_ranlib');

        read_hash($_, $reader, 'aliases', list_push(\@{$info{'aliases'}}));
        read_hash($_, $reader, 'arch', list_push(\@{$info{'arch'}}));

        read_hash($_, $reader, 'supports_shared',
                  list_push(\@{$info{'supports_shared'}}));
    }
    return %info;
}

##################################################
#                                                #
##################################################
sub get_cc_info {
    my ($name,$file) = @_;
    my $reader = make_reader($file);

    my %info;
    $info{'name'} = $name;

    while($_ = &$reader()) {
        set_if_any(\&set_if_quoted, $_, \%info,
                   'realname:binary_name:' .
                   'compile_option:output_to_option:add_include_dir_option:' .
                   'add_lib_dir_option:add_lib_option:' .
                   'lib_opt_flags:check_opt_flags:' .
                   'lang_flags:warning_flags:so_obj_flags:ar_command:' .
                   'debug_flags:no_debug_flags');

        set_if_any(\&set_if, $_, \%info, 'makefile_style');

        read_hash($_, $reader, 'os', list_push(\@{$info{'os'}}));
        read_hash($_, $reader, 'arch', list_push(\@{$info{'arch'}}));

        sub quoted_mapping {
            my $hashref = $_[0];
            return sub {
                my $line = $_[0];
                $line =~ m/^(\S*) -> \"(.*)\"$/;
                $$hashref{$1} = $2;
            }
        }

        read_hash($_, $reader, 'mach_abi_linking',
                  quoted_mapping(\%{$info{'mach_abi_linking'}}));
        read_hash($_, $reader, 'so_link_flags',
                  quoted_mapping(\%{$info{'so_link_flags'}}));

        read_hash($_, $reader, 'mach_opt',
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
sub guess_cpu_from_this
{
    my $cpuinfo = lc $_[0];
    my $cpu = '';

    $cpu = 'amd64' if($cpuinfo =~ /athlon64/);
    $cpu = 'amd64' if($cpuinfo =~ /opteron/);

    $cpu = 'athlon' if($cpuinfo =~ /athlon/);
    $cpu = 'pentium4' if($cpuinfo =~ /pentium 4/);
    $cpu = 'pentium4' if($cpuinfo =~ /pentium\(r\) 4/);
    $cpu = 'pentium3' if($cpuinfo =~ /pentium iii/);
    $cpu = 'pentium2' if($cpuinfo =~ /pentium ii/);
    $cpu = 'pentium3' if($cpuinfo =~ /pentium 3/);
    $cpu = 'pentium2' if($cpuinfo =~ /pentium 2/);

    # The 32-bit SPARC stuff is impossible to match to arch type easily, and
    # anyway the uname stuff will pick up that it's a SPARC so it doesn't
    # matter. If it's an Ultra, assume a 32-bit userspace, no 64-bit code
    # possible; that's the most common setup right now anyway
    $cpu = 'sparc32-v9' if($cpuinfo =~ /ultrasparc/);

    # 64-bit PowerPC
    $cpu = 'rs64a' if($cpuinfo =~ /rs64-/);
    $cpu = 'power3' if($cpuinfo =~ /power3/);
    $cpu = 'power4' if($cpuinfo =~ /power4/);
    $cpu = 'power5' if($cpuinfo =~ /power5/);
    $cpu = 'ppc970' if($cpuinfo =~ /ppc970/);

    # Ooh, an Alpha. Try to figure out what kind
    if($cpuinfo =~ /alpha/)
    {
        $cpu = 'alpha-ev4' if($cpuinfo =~ /ev4/);
        $cpu = 'alpha-ev5' if($cpuinfo =~ /ev5/);
        $cpu = 'alpha-ev56' if($cpuinfo =~ /ev56/);
        $cpu = 'alpha-pca56' if($cpuinfo =~ /pca56/);
        $cpu = 'alpha-ev6' if($cpuinfo =~ /ev6/);
        $cpu = 'alpha-ev67' if($cpuinfo =~ /ev67/);
        $cpu = 'alpha-ev68' if($cpuinfo =~ /ev68/);
        $cpu = 'alpha-ev7' if($cpuinfo =~ /ev7/);
    }

    return $cpu;
}

# Do some WAGing and see if we can figure out what system we are. Think about
# this as a really moronic config.guess
sub guess_triple
{
    # /bin/sh, good bet we're on something Unix-y (at least it'll have uname)
    if(-f '/bin/sh')
    {
        my $os = lc `uname -s 2>/dev/null`; chomp $os;

        # Let the crappy hacks commence!

        # Cygwin's uname -s is cygwin_<windows version>
        $os = 'cygwin' if($os =~ /^cygwin/);
        $os = os_alias($os);

        if(!defined $OPERATING_SYSTEM{$os})
        {
            warning("Unknown uname -s output: $os, falling back to 'generic'");
            $os = 'generic';
        }

        my $cpu = '';

        # If we have /proc/cpuinfo, try to get nice specific information about
        # what kind of CPU we're running on.
        if(-e '/proc/cpuinfo' and -r '/proc/cpuinfo')
        {
            open CPUINFO, '/proc/cpuinfo' or
                die "Couldn't read /proc/cpuinfo ($!)\n";

            my $cpuinfo = join('', <CPUINFO>);
            close CPUINFO;

            $cpu = guess_cpu_from_this($cpuinfo);
        }

        # `umame -p` is sometimes something stupid like unknown, but in some
        # cases it can be more specific (useful) than `uname -m`
        if($cpu eq '') # no guess so far
        {
            my $uname_p = `uname -p 2>/dev/null`;
            chomp $uname_p;
            $cpu = guess_cpu_from_this($uname_p);

            # If guess_cpu_from_this didn't figure it out, try it plain
            if($cpu eq '') { $cpu = lc $uname_p; }

            my (%SUBMODEL_ALIAS, %ARCH_ALIAS, %ARCH);

            foreach my $arch (keys %CPU) {
                my %info = %{$CPU{$arch}};

                $ARCH{$arch} = $info{'name'};
                foreach my $submodel (@{$info{'submodels'}}) {
                    $ARCH{$submodel} = $info{'name'};
                }

                foreach my $alias (@{$info{'aliases'}}) {
                    $ARCH_ALIAS{$alias} = $arch;
                }

                if(defined($info{'submodel_aliases'})) {
                    my %submodel_aliases = %{$info{'submodel_aliases'}};
                    foreach my $sm_alias (keys %submodel_aliases) {
                        $SUBMODEL_ALIAS{$sm_alias} =
                            $submodel_aliases{$sm_alias};
                    }
                }
            }

            if(!defined $ARCH{$cpu} && !defined $SUBMODEL_ALIAS{$cpu} &&
               !defined $ARCH_ALIAS{$cpu})
            {
                # Nope, couldn't figure out uname -p
                $cpu = lc `uname -m 2>/dev/null`;
                chomp $cpu;

                if(!defined $ARCH{$cpu} && !defined $SUBMODEL_ALIAS{$cpu} &&
                   !defined $ARCH_ALIAS{$cpu})
                {
                    $cpu = 'generic';
                }
            }
        }

        my @CCS = ('gcc', 'icc', 'compaq', 'kai'); # Skips several, oh well...

        # First try the CC enviornmental variable, if it's set
        if(defined($ENV{CC}))
        {
            my @new_CCS = ($ENV{CC});
            foreach my $cc (@CCS) { push @new_CCS, $cc; }
            @CCS = @new_CCS;
        }

        my $cc = '';
        foreach (@CCS)
        {
            my $bin_name = $COMPILER{$_}{'binary_name'};
            $cc = $_ if(which($bin_name) ne '');
            last if($cc ne '');
        }

        if($cc eq '') {
            my $msg =
               "Can't find a usable C++ compiler, is your PATH right?\n" .
               "You might need to run with explicit compiler/system flags;\n" .
               "   run '$0 --help' for more information\n";
            error($msg);
        }

        return "$cc-$os-$cpu";
    }
    elsif($^O eq 'MSWin32' or $^O eq 'dos')
    {
        my $os = 'windows'; # obviously

        # Suggestions on this? The Win32 'shell' env is not so hot. We could
        # try using cpuinfo, except that will crash hard on NT/Alpha (like what
        # we're doing now won't!). In my defense of choosing i686:
        #   a) There are maybe a few hundred Alpha/MIPS boxes running NT4 today
        #   b) Anyone running Windows on < Pentium Pro deserves to lose.
        my $cpu = 'i686';

        # No /bin/sh, so not cygwin. Assume VC++; again, this could be much
        # smarter
        my $cc = 'msvc';
        return "$cc-$os-$cpu";
    }
    else
    {
        error("Autoconfiguration failed (try --help)");
    }
}

sub guess_mods {
    my ($cc, $os, $arch, $submodel) = @_;

    my @usable_modules;

    foreach my $mod (sort keys %MODULES) {
        my %modinfo = %{ $MODULES{$mod} };

        # If it uses external libs, the user has to request it specifically
        next if($modinfo{'external_libs'});

        my @cc_list = @{ $modinfo{'cc'} };
        next if(scalar @cc_list > 0 && !in_array($cc, \@cc_list));

        my @os_list = @{ $modinfo{'os'} };
        next if(scalar @os_list > 0 && !in_array($os, \@os_list));

        my @arch_list = @{ $modinfo{'arch'} };
        next if(scalar @arch_list > 0 &&
                !in_array($arch, \@arch_list) &&
                !in_array($submodel, \@arch_list));

        push @usable_modules, $mod;
    }
    return @usable_modules;
}

sub defines {
    my ($config) = @_;

    my $defines = '';

    my $arch = $$config{'arch'};
    if($arch ne 'generic') {
        $arch = uc $arch;
        $defines .= "#define BOTAN_TARGET_ARCH_IS_$arch\n";

        my $submodel = $$config{'submodel'};
        if($arch ne $submodel) {
            $submodel = uc $submodel;
            $submodel =~ s/-/_/g;
            $defines .= "#define BOTAN_TARGET_CPU_IS_$submodel\n";
        }
    }

    my @defarray;
    foreach my $mod (@{$$config{'modules'}}) {
        my $defs = $MODULES{$mod}{'define'};
        next unless $defs;

        push @defarray, split(/,/, $defs);
    }
    foreach (sort @defarray) {
        next if not defined $_ or not $_;
        $defines .= "#define BOTAN_EXT_$_\n";
    }
    chomp($defines);
    return $defines;
}

sub slurp_file {
    my $file = $_[0];
    return '' if(!defined($file) or $file eq '');

    error("'$file': No such file") unless(-e $file);
    error("'$file': Not a regular file") unless(-f $file);

    open FILE, "<$file" or error("Couldn't read $file ($!)");

    my $output = '';
    while(<FILE>) { $output .= $_; }
    close FILE;

    return $output;
}

##################################################
#                                                #
##################################################
sub print_pkg_config {
    my ($config) = @_;

    return if($$config{'os'} eq 'generic' or
              $$config{'os'} eq 'windows');

    $$config{'link_to'} = libs('-l', '', 'm', @{$$config{'extra_libs'}});

    process_template(File::Spec->catfile('misc', 'config', 'botan-config.in'),
                     'botan-config', $config);

    delete $$config{'link_to'};

    chmod 0755, 'botan-config';
}

##################################################
#                                                #
##################################################
sub generate_makefile {
   my ($config) = @_;

   my $debug = $$config{'debug'};

   sub os_ar_command {
       return os_info_for(shift, 'ar_command');
   }

   sub os_ar_needs_ranlib {
       return (os_info_for(shift, 'ar_needs_ranlib') eq 'yes');
   }

   my $cc = $$config{'compiler'};
   my %ccinfo = %{$COMPILER{$cc}};

   my $lang_flags = '';
   append_ifdef(\$lang_flags, $ccinfo{'lang_flags'});
   append_if(\$lang_flags, "-fpermissive", $$config{'gcc_bug'});

   my $warnings = '';
   append_ifdef(\$warnings, $ccinfo{'warning_flags'});

   my $lib_opt_flags = '';
   append_ifdef(\$lib_opt_flags, $ccinfo{'lib_opt_flags'});
   append_ifdef(\$lib_opt_flags, $ccinfo{'debug_flags'}) if($debug);
   append_ifdef(\$lib_opt_flags, $ccinfo{'no_debug_flags'}) if(!$debug);

   my $mach_opt_flags = mach_opt($config);

   # This is a default that works on most Unix and Unix-like systems
   my $ar_command = "ar crs";
   my $ar_needs_ranlib = 0; # almost no systems need it anymore

   # See if there are any over-riding methods. We presume if CC is creating
   # the static libs, it knows how to create the index itself.

   my $os = $$config{'os'};

   if($ccinfo{'ar_command'}) {
       $ar_command = $ccinfo{'ar_command'};
   }
   elsif(os_ar_command($os))
   {
       $ar_command = os_ar_command($os);
       $ar_needs_ranlib = 1 if(os_ar_needs_ranlib($os));
   }

   my $so_obj_flags = '';
   append_ifdef(\$so_obj_flags, $ccinfo{'so_obj_flags'});

   my $so_link_flags = '';
   append_ifdef(\$so_link_flags, $ccinfo{'so_link_flags'}{$os});
   append_ifdef(\$so_link_flags, $ccinfo{'so_link_flags'}{'default'})
       if($so_link_flags eq '');

   my $supports_shared = 0;
   my $arch = $$config{'arch'};
   if(in_array('all', $OPERATING_SYSTEM{$os}{'supports_shared'}) or
      in_array($arch, $OPERATING_SYSTEM{$os}{'supports_shared'})) {
       $supports_shared = 1;
   }

   if($$config{'shared'} eq 'no' or !$supports_shared)
      { $so_obj_flags = $so_link_flags = ''; }

   my $make_shared = 0;
   $make_shared = 1
    if(($so_obj_flags or $so_link_flags) and $supports_shared);

   my $check_opt_flags = '';
   append_ifdef(\$check_opt_flags, $ccinfo{'check_opt_flags'});

   my $ccopts = '';
   append_ifdef(\$ccopts, $ccinfo{'mach_abi_linking'}{$arch});
   append_ifdef(\$ccopts, $ccinfo{'mach_abi_linking'}{$os});
   append_ifdef(\$ccopts, $ccinfo{'mach_abi_linking'}{'all'});
   $ccopts = ' ' . $ccopts if($ccopts ne '');

   my $cc_bin = $ccinfo{'binary_name'};

   # Hack for 10.1, 10.2+ is fixed. Don't have a 10.0.x machine anymore
   $cc_bin = "c++" if($os eq "darwin" and $cc eq "gcc");

   my $docs = file_list(undef, undef, undef, map { $_ => 'doc' } @DOCS);
   $docs .= 'readme.txt';

   my $includes = file_list(undef, undef, undef,
                            map { $_ => $$config{'build_include_botan'} }
                               keys %{$$config{'includes'}});

   add_to($config, {
       'shared'          => ($make_shared ? 'yes' : 'no'),

       'cc'              => $cc_bin . $ccopts,
       'lib_opt'         => $lib_opt_flags,
       'check_opt'       => $check_opt_flags,
       'mach_opt'        => $mach_opt_flags,
       'lang_flags'      => $lang_flags,
       'warn_flags'      => $warnings,
       'so_obj_flags'    => $so_obj_flags,
       'so_link'         => $so_link_flags,

       'ar_command'      => $ar_command,
       'ranlib_command'  => ($ar_needs_ranlib ? 'ranlib' : 'true'),
       'static_suffix'   => os_info_for($os, 'static_suffix'),
       'so_suffix'       => os_info_for($os, 'so_suffix'),
       'obj_suffix'      => os_info_for($os, 'obj_suffix'),

       'doc_files'       => $docs,
       'include_files'   => $includes
       });

   my $lib_objs = file_list($$config{'build_lib'}, '(\.cpp$|\.S$)',
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
       'check_build_cmds' => $check_build_cmds
       });

   my $template_dir = File::Spec->catdir('misc', 'config', 'makefile');

   my $make_style = $$config{'make_style'};
   if($make_style eq 'unix') {
       $$config{'makefile'} = File::Spec->catfile($template_dir, 'unix.in');

       $$config{'makefile'} = File::Spec->catfile($template_dir, 'unix_shr.in')
           if($make_shared);

       print_unix_makefile($config);
   }
   elsif($make_style eq 'nmake') {
       $$config{'makefile'} = File::Spec->catfile($template_dir, 'nmake.in');
       print_nmake_makefile($config);
   }
   else {
      error("This configure script does not know how to make ",
            "a makefile for makefile style \"$make_style\"");
   }
}

##################################################
#                                                #
##################################################
sub file_list {
    my ($put_in, $from, $to, %files) = @_;
    my $spaces = 16;

    my $list = '';

    my $len = $spaces;
    foreach (sort keys %files) {
        my $file = $_;

        if($len > 60) {
            $list .= "\\\n" . ' 'x$spaces;
            $len = $spaces;
        }

        $file =~ s/$from/$to/ if(defined($from) and defined($to));

        my $dir = $files{$_};
        $dir = $put_in if defined $put_in;

        if(defined($dir)) {
            $list .= File::Spec->catfile ($dir, $file) . ' ';
            $len += length($file) + length($dir);
        }
        else {
            $list .= $file . ' ';
            $len += length($file);
        }
    }

    return $list;
}

sub build_cmds {
    my ($config, $dir, $flags, $files) = @_;

    die unless $dir;
    die unless $flags;

    my $output = '';

    my $cc = $$config{'compiler'};
    my $obj_suffix = $$config{'obj_suffix'};

    die unless $obj_suffix;

    my $inc = $COMPILER{$cc}{'add_include_dir_option'};
    my $from = $COMPILER{$cc}{'compile_option'};
    my $to = $COMPILER{$cc}{'output_to_option'};

    my $inc_dir = $$config{'build_include'};

    # Probably replace by defaults to -I -c -o
    die unless defined($inc) and defined($from) and defined($to);

    my $bld_line =
        "\t\$(CXX) $inc$inc_dir $flags $from \$? $to \$@";

    foreach (sort keys %$files) {
        my $src_file = File::Spec->catfile($$files{$_}, $_);
        my $obj_file = File::Spec->catfile($dir, $_);

        $obj_file =~ s/\.cpp$/.$obj_suffix/;
        $obj_file =~ s/\.S$/.$obj_suffix/;

        $output .= "$obj_file: $src_file\n$bld_line\n\n";
    }
    chomp($output);
    chomp($output);
    return $output;
}

##################################################
# Print a Unix style makefile                    #
##################################################
sub print_unix_makefile {
   my ($config) = @_;

   my $os = $$config{'os'};
   my $install_cmd_exec = os_install_info($os, 'install_cmd');
   $install_cmd_exec =~ s/OWNER/\$(OWNER)/;
   $install_cmd_exec =~ s/GROUP/\$(GROUP)/;
   $install_cmd_exec =~ s/MODE/\$(EXEC_MODE)/;

   my $install_cmd_data = os_install_info($os, 'install_cmd');
   $install_cmd_data =~ s/OWNER/\$(OWNER)/;
   $install_cmd_data =~ s/GROUP/\$(GROUP)/;
   $install_cmd_data =~ s/MODE/\$(DATA_MODE)/;

   unshift @{$$config{'mod_libs'}}, "m";

   add_to($config, {
       'link_to' => libs('-l', '', @{$$config{'mod_libs'}}),
       'install_user' => os_install_info($os, 'install_user'),
       'install_group' => os_install_info($os, 'install_group'),
       'install_cmd_exec' => $install_cmd_exec,
       'install_cmd_data' => $install_cmd_data,
       });

   process_template($$config{'makefile'}, 'Makefile', $config);
}

##################################################
# Print a NMAKE-style makefile                   #
##################################################
sub print_nmake_makefile {
   my ($config) = @_;

   my $static_lib_suffix = $$config{'static_suffix'};
   add_to($config, {
       'shared' => 'no',
       'link_to' => libs('', ".$static_lib_suffix", @{$$config{'mod_libs'}}),
       'install_user' => '',
       'install_group' => '',
       'install_cmd_exec' => '',
       'install_cmd_data' => '',
       });

   process_template($$config{'makefile'}, 'Makefile', $config);
}
