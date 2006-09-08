#!/usr/bin/perl -w

require 5.006;

use strict;
use Getopt::Long;
use File::Spec;
use File::Copy;

my $MAJOR_VERSION = 1;
my $MINOR_VERSION = 5;
my $PATCH_VERSION = 11;

# If 1, then we always copy include files, without attempting to make symlinks
# or hardlinks. It seems that link("","") will succeed on Windows, but the
# actual operation will fail (FAT32 doesn't support any kind of links).
# This is automatically forced if $^O is 'dos', 'MSWin32', or 'cygwin'
my $FORCE_COPY = 0;

my $INCLUDE_DIR = 'include';
my $SRC_DIR = 'src';
my $MOD_DIR = 'modules';
my $CHECK_DIR = 'checks';
my $DOC_DIR = 'doc';
my $BUILD_DIR = 'build';
my $BUILD_DIR_LIB = 'lib';
my $BUILD_DIR_CHECKS = 'checks';
my $MAKE_FILE = 'Makefile';
my $BUILD_INCLUDE_DIR = 'build/include';

my $ARCH_DIR = 'misc/config/arch';
my $OS_DIR = 'misc/config/os';
my $CC_DIR = 'misc/config/cc';

my $CONFIG_HEADER = 'build.h';

my $CPP_INCLUDE_DIR_DIRNAME = 'botan';

my %MODULE_SETS = (
   'unix' => [ 'alloc_mmap', 'es_egd', 'es_ftw', 'es_unix', 'fd_unix',
               'tm_unix' ],
   'beos' => [ 'es_beos', 'es_unix', 'fd_unix', 'tm_unix' ],
   'win32' => ['es_capi', 'es_win32', 'mux_win32', 'tm_win32' ],
);

my %DOCS = (
   'readme.txt' => undef, # undef = file is in top level directory

   'pgpkeys.asc' => $DOC_DIR,

   'api.pdf' => $DOC_DIR,
   'tutorial.pdf' => $DOC_DIR,
   'fips140.pdf' => $DOC_DIR,

   'api.tex' => $DOC_DIR,
   'tutorial.tex' => $DOC_DIR,
   'fips140.tex' => $DOC_DIR,

   'botan.rc' => $DOC_DIR,

   'credits.txt' => $DOC_DIR,
   'info.txt' => $DOC_DIR,
   'license.txt' => $DOC_DIR,
   'log.txt' => $DOC_DIR,
   'thanks.txt' => $DOC_DIR,
   'todo.txt' => $DOC_DIR
   );

my (%CPU, %OPERATING_SYSTEM, %COMPILER, %MODULES);

# This is build configuration stuff, should all go into %BUILD
my ($CPP_INCLUDE_DIR, $BUILD_LIB_DIR, $BUILD_CHECK_DIR);
my ($user_set_root, $doc_dir, $lib_dir) = ('', '', '');
my (%ignored_src, %ignored_include, %added_src, %added_include,
    %lib_src, %check_src, %include);

# Run stuff, quit
main();
exit;

sub main {
    %CPU = read_info_files($ARCH_DIR, \&get_arch_info);
    %OPERATING_SYSTEM = read_info_files($OS_DIR, \&get_os_info);
    %COMPILER = read_info_files($CC_DIR, \&get_cc_info);
    %MODULES = read_module_files($MOD_DIR);

    my ($debug, $dumb_gcc, $no_shared) = (0, 0, 0);
    my ($make_style, $build_dir, $module_set, $local_config) =
        ('', '', '', '');

    my $autoconfig = 1;
    my @using_mods;

    GetOptions('debug' => sub { $debug = 1; },
               'disable-shared' => sub { $no_shared = 1; },
               'noauto' => sub { $autoconfig = 0 },
               'gcc295x' => sub { $dumb_gcc = 1; },
               'dumb-gcc' => sub { $dumb_gcc = 1; },
               'make-style=s' => \$make_style,
               'modules=s' => \@using_mods,
               'module-set=s' => \$module_set,
               'prefix=s' => \$user_set_root,
               'docdir=s' => \$doc_dir,
               'libdir=s' => \$lib_dir,
               'build-dir=s' => \$build_dir,
               'local-config=s' => \$local_config,
               'help' => sub { help(); }
               );

    if($^O eq 'MSWin32' or $^O eq 'dos' or $^O eq 'cygwin') {
        print "Disabling use of symlink()/link() due to Win FS limitations\n";
        $FORCE_COPY = 1;
    }

    my $cc_os_cpu_set = '';
    if($#ARGV == 0) { $cc_os_cpu_set = $ARGV[0]; }
    elsif($autoconfig) {
        $cc_os_cpu_set = guess_triple();
        print "(autoconfig): Guessing your system config is $cc_os_cpu_set\n";
    }
    else { help(); }

    my ($cc,$os,$submodel) = split(/-/,$cc_os_cpu_set,3);
    if(!defined($cc) or !defined($os) or !defined($submodel)) { help(); }

    if($build_dir ne '')
    {
        $BUILD_DIR = $build_dir;
        $BUILD_INCLUDE_DIR = $build_dir . '/include';
    }

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
            print "(note): GCC 2.95.x issues a lot of warnings for \n" .
                "    Botan; either ignore the warnings or upgrade to 3.x\n";
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

    $make_style = $COMPILER{$cc}{'makefile_style'} unless($make_style);

    error("Module set $module_set isn't known")
        if($module_set && !defined($MODULE_SETS{$module_set}));

    if($module_set) {
        foreach (@{ $MODULE_SETS{$module_set} }) { push @using_mods,$_; }
    }

    @using_mods = grep {/./} split(/,/,join(',',@using_mods));

    if($autoconfig)
    {
        foreach (guess_mods($cc,$os,$arch,$submodel))
        {
            # Print a notice, unless it was enabled explicitly (or in a set)
            my $picked_by_user = 0;
            foreach my $x (@using_mods) { $picked_by_user = 1 if($_ eq $x); }

            print "  (autoconfig): Enabling module $_\n" if(!$picked_by_user);
            push @using_mods, $_;
        }
    }

    # Uniqify @using_mods
    my %uniqed_mods;
    foreach my $mod (@using_mods) { $uniqed_mods{$mod} = 0; }
    @using_mods = sort keys %uniqed_mods;

    foreach (@using_mods) {
        error("Module $_ isn't known (try --help)")
            unless(exists($MODULES{$_}));
    }

    check_for_conflicts(@using_mods);
    foreach my $mod (@using_mods) {
        load_module($mod, $cc, $os, $arch, $submodel);
    }

    print_pkg_config($os, $MAJOR_VERSION, $MINOR_VERSION, $PATCH_VERSION,
                     using_libs($os, @using_mods));

    $CPP_INCLUDE_DIR =
        File::Spec->catdir($BUILD_INCLUDE_DIR, $CPP_INCLUDE_DIR_DIRNAME);
    $BUILD_LIB_DIR = File::Spec->catdir($BUILD_DIR, $BUILD_DIR_LIB);
    $BUILD_CHECK_DIR = File::Spec->catdir($BUILD_DIR, $BUILD_DIR_CHECKS);

    %lib_src = list_dir($SRC_DIR, \%ignored_src);
    %check_src = list_dir($CHECK_DIR, undef);

    %include = list_dir($INCLUDE_DIR, \%ignored_include);

    mkdirs($BUILD_DIR,
            $BUILD_INCLUDE_DIR, $CPP_INCLUDE_DIR,
            $BUILD_LIB_DIR, $BUILD_CHECK_DIR);
    clean_out_dirs($CPP_INCLUDE_DIR);

    my $config_h = File::Spec->catfile($BUILD_DIR, $CONFIG_HEADER);

    print_config_h($MAJOR_VERSION, $MINOR_VERSION, $PATCH_VERSION,
                   $config_h, $local_config, $os, $arch, $submodel,
                   find_mp_bits(@using_mods), defines(@using_mods));

    $added_include{$CONFIG_HEADER} = $BUILD_DIR;

    copy_files($CPP_INCLUDE_DIR, \%include, \%added_include);

    my %all_includes = list_dir($CPP_INCLUDE_DIR);

    generate_makefile($make_style,
                      $cc, $os, $submodel, $arch,
                      $debug, $no_shared, $dumb_gcc,
                      \%lib_src, \%check_src, \%all_includes,
                      \%added_src, using_libs($os, @using_mods));
}

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

sub figure_out_arch {
    my ($name) = @_;
    return ('generic', 'generic') if($name eq 'generic');

    sub submodel_alias {
        my ($name) = @_;

        foreach my $arch (keys %CPU) {
            next unless defined $CPU{$arch}{'submodel_aliases'};
            my %sm_aliases = %{$CPU{$arch}{'submodel_aliases'}};

            foreach my $alias (keys %sm_aliases) {
                my $official = $sm_aliases{$alias};
                return $official if($alias eq $name);
            }
        }
        return $name;
    }

    sub arch_alias {
        my $name = $_[0];

        foreach my $arch (keys %CPU) {
            foreach my $alias (@{$CPU{$arch}{'aliases'}}) {
                return $arch if($alias eq $name);
            }
        }
        return undef;
    }

    sub find_arch {
        my $name = $_[0];

        foreach my $arch (keys %CPU) {
            my %info = %{$CPU{$arch}};

            return $arch if ($name eq $arch);

            foreach my $submodel (@{$info{'submodels'}}) {
                return $arch if ($name eq $submodel);
            }
        }
    }

    my $submodel = submodel_alias($name);
    my $arch = arch_alias($name);

    if(not defined($arch) and $submodel ne '') {
        $arch = find_arch($submodel);
    }

    error("Arch $name isn't known") unless defined $arch;

    if($submodel eq $arch) {
        $submodel = $CPU{$arch}{'default_submodel'};

        warning("Using $submodel as default type for family ", realname($arch))
           if($submodel ne $arch);
    }

    die unless defined($arch) and defined($submodel);

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

sub check_for_file {
   my ($file,$mod) = @_;

   error("Module $mod requires that file $file exist. This error\n",
       "should never occur; please contact the maintainers with details.")
       unless(-e $file);
}

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

sub defines {
   my @defarray;
   foreach my $mod (@_) {
       my $defs = $MODULES{$mod}{'define'};
       next unless $defs;

       push @defarray, split(/,/, $defs);
   }
   return \@defarray;
}

# Any other alternatives here?
sub portable_symlink {
   my ($from, $to_dir, $to_fname) = @_;

   my $can_symlink = eval { symlink("",""); 1 };
   my $can_link = eval { link("",""); 1 };

   if($FORCE_COPY) { $can_symlink = 0; $can_link = 0; }

   chdir $to_dir or die "Can't chdir to $to_dir ($!)\n";

   if($can_symlink) {
     symlink $from, $to_fname or die "Can't symlink $from to $to_fname ($!)"; }
   elsif($can_link) {
     link $from, $to_fname    or die "Can't link $from to $to_fname ($!)"; }
   else {
     copy ($from, $to_fname)  or die "Can't copy $from to $to_fname ($!)"; }

   my $go_up = File::Spec->splitdir($to_dir);
   for(my $j = 0; $j != $go_up; $j++)
   {
       chdir File::Spec->updir();
   }
}

sub copy_files {
   my ($include_dir, $mainline, $modules) = @_;

   my $link_up = sub {
       my ($dir, $file) = @_;
       my $updir = File::Spec->updir();
       portable_symlink(File::Spec->catfile($updir, $updir, $updir,
                                            $dir, $file),
                        $include_dir, $file);
   };

   foreach (keys %$mainline) { &$link_up('include', $_); }
   foreach (keys %$modules) { &$link_up($$modules{$_}, $_); }
}

sub list_dir {
    my ($dir, $ignore) = @_;

    my @list = dir_list($dir);

    if($dir eq $CHECK_DIR) {
        @list = grep { !/\.dat$/ } grep { !/^keys$/ } grep { !/\.h$/ } @list;
    }

    # If $ignore is set, pull everything in @list that's in $ignore out of it
    if(defined($ignore)) {
        @list = grep { !exists($$ignore{$_}) } @list;
    }
    my %list = map { $_ => $dir } @list;
    return %list;
}

sub clean_out_dirs {
   my (@dirs) = @_;
   foreach my $dir (@dirs) {
      my %files = list_dir($dir);
      foreach my $file (keys %files) {
         my $path = File::Spec->catfile($dir, $file);
         unlink $path or die "Could not unlink $path ($!)\n";
      }
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

sub in_array {
    my($target, $array) = @_;
    return 0 unless defined($array);
    foreach (@$array) { return 1 if($_ eq $target); }
    return 0;
}

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

sub check_for_conflicts {

    sub conflicts {
        my ($mod, $item, $do_what, $hashref) = @_;
        return if(!defined($item));

        if(defined($$hashref{$item})) {
            my $other_mod = $$hashref{$item};
            error("Both $mod and $other_mod $do_what $item");
        }
        return $item;
    }

    my @mods = @_;
    my (%ignored, %added, %replaced, %defines);

    foreach my $mod (@mods) {
        sub check_hash {
            my ($mod, $do_what, $hashref) = @_;
            foreach (@{ $MODULES{$mod}{$do_what} }) {
                $$hashref{conflicts($mod, $_, $do_what, $hashref)} = $mod;
            }
        }

        check_hash($mod, 'replace', \%replaced);
        check_hash($mod, 'add', \%added);
        check_hash($mod, 'ignore', \%ignored);
    }
}

sub dir_list {
    my ($dir) = @_;
    opendir(DIR, $dir) or die "Couldn't read directory $dir ($!)\n";
    my @listing = grep { $_ ne '.' and $_ ne '..' } readdir DIR;
    closedir DIR;
    return @listing;
}

sub realname {
    my $arg = $_[0];

    return $COMPILER{$arg}{'realname'} if defined $COMPILER{$arg};
    return $OPERATING_SYSTEM{$arg}{'realname'}
       if defined $OPERATING_SYSTEM{$arg};
    return $CPU{$arg}{'realname'} if defined $CPU{$arg};

    return $arg;
}

sub load_module {
   my ($modname,$cc,$os,$arch,$sub) = @_;
   my %module = %{$MODULES{$modname}};
   $modname = $module{'name'};

   sub works_on {
       my ($what, @lst) = @_;
       return 1 if not @lst; # empty list -> no restrictions
       return in_array($what, \@lst);
   }

   # Check to see if everything is OK WRT system requirements
   if($os ne 'generic') {
       unless(works_on($os, @{$module{'os'}})) {
           error("Module '$modname' does not run on ", realname($os));
       }
   }

   if($arch ne 'generic') {
       unless(works_on($arch, @{$module{'arch'}}) or
              works_on($sub, @{$module{'arch'}})) {

           error("Module '$modname' does not run on $arch/$sub");
       }
   }

   unless(works_on($cc, @{$module{'cc'}})) {
       error("Module '$modname' does not work with ", realname($cc));
   }

   sub handle_files {
       my($modname, $lst, $func) = @_;
       return unless defined($lst);
       foreach (sort @$lst) {
           &$func($modname, $_);
       }
   }

   handle_files($modname, $module{'replace'}, \&replace_file);
   handle_files($modname, $module{'ignore'},  \&ignore_file);
   handle_files($modname, $module{'add'},     \&add_file);

   if(defined($module{'note'})) {
       my $realname = $module{'realname'};
       my $note = $module{'note'};
       print STDERR "(note): $modname (\"$realname\"): $note\n";
   }
}

sub full_path {
   my ($file,$modname) = @_;

   if(defined($modname)) {
       return File::Spec->catfile ($MOD_DIR, $modname, $file);
   }
   else {
       if($file =~ /\.h$/) {
           return File::Spec->catfile ($INCLUDE_DIR, $file);
       }
       elsif($file =~ /\.cpp$/ or $file =~ /\.s$/ or $file =~ /\.S$/) {
           return File::Spec->catfile ($SRC_DIR, $file);
       }
       else {
           error("Not sure where to put $file");
       }
   }
}

sub add_file {
    my ($modname,$file) = @_;
    check_for_file(full_path($file, $modname), $modname);

    if($file =~ /\.cpp$/ or $file =~ /\.s$/ or $file =~ /\.S$/) {
        $added_src{$file} = File::Spec->catdir($MOD_DIR, $modname);
    }
    elsif($file =~ /\.h$/) {
        $added_include{$file} = File::Spec->catdir($MOD_DIR, $modname);
    }
    else { error("Not sure where to put $file"); }
}

sub ignore_file {
    my ($modname,$file) = @_;
    check_for_file(full_path($file), $modname);

    if($file =~ /\.cpp$/ or $file =~ /\.s$/ or $file =~ /\.S$/) {
        $ignored_src{$file} = 1;
    }
    elsif($file =~ /\.h$/) {
        $ignored_include{$file} = 1;
    }
    else { error("Not sure where to put $file"); }
}

# This works because ignore file always runs on files in the main source tree,
# and add always works on the file in the modules directory.
sub replace_file {
   my ($modname,$file) = @_;
   ignore_file($modname, $file);
   add_file($modname, $file);
}

sub help {
    my $sets = join("|", sort keys %MODULE_SETS);

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
  --module-set=SET:    add a pre-specified set of modules ($sets)

  --debug:             set compiler flags for debugging
  --disable-shared:    disable building shared libararies
  --noauto:            disable autoconfiguration
  --make-style=STYLE:  override the guess as to what type of makefile to use

You may use 'generic' for OS or CPU (useful if your OS or CPU isn't listed).

CPU can be a generic family name or a specific model name. Common aliases are
supported but not listed. Choosing a specific submodel will usually result in
code that will not run on earlier versions of that architecture.

ENDOFHELP

   sub print_listing {
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
   }

   print_listing('CC', \%COMPILER);
   print_listing('OS', \%OPERATING_SYSTEM);
   print_listing('CPU', \%CPU);
   print_listing('Modules', \%MODULES) if(%MODULES);
   exit;
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

sub os_info_for {
    my ($os,$what) = @_;

    die "Internal error: os_info_for called with an os of defaults\n"
        if($os eq 'defaults');

    my %osinfo = %{$OPERATING_SYSTEM{$os}};

    my $result = $osinfo{$what};
    if(!defined($result) or $result eq '') {
        #print "Using defaults for $what\n";
        $result = $OPERATING_SYSTEM{'defaults'}{$what};
    }
    
    #print "$os $what -> $result\n";
    return $result;
}

sub os_install_info {
    my ($os,$what) = @_;

    return $doc_dir if($what eq 'doc_dir' && $doc_dir);
    return $lib_dir if($what eq 'lib_dir' && $lib_dir);
    return $user_set_root if($what eq 'install_root' && $user_set_root);

    my $result = $OPERATING_SYSTEM{$os}{$what};

    if(defined($result) and $result ne '') {
        return $result;
    }

    return $OPERATING_SYSTEM{'defaults'}{$what};
}

sub mach_opt {
    my ($cc, $arch, $submodel) = @_;

    my %ccinfo = %{$COMPILER{$cc}};

    # Nothing we can do in that case
    return '' unless defined($ccinfo{'mach_opt_flags'});

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

sub get_cc_info {
    my ($name,$file) = @_;
    my $reader = make_reader($file);

    my %info;
    $info{'name'} = $name;

    while($_ = &$reader()) {
        set_if_any(\&set_if_quoted, $_, \%info,
                   'realname:binary_name:lib_opt_flags:check_opt_flags:' .
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

sub guess_cpu_from_this
{
    my $cpuinfo = lc $_[0];
    my $cpu = '';

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
            print "Unknown uname -s output: $os, falling back to 'generic'\n";
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

            my $uname_p = `uname -p 2>/dev/null`;
            chomp $uname_p;
            $cpu = guess_cpu_from_this($uname_p);

            # If guess_cpu_from_this didn't figure it out, try it plain
            if($cpu eq '') { $cpu = lc $uname_p; }

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
        print "Sorry, you don't seem to be on Unix or Windows;\n" .
            "   autoconfig failed (try running me with --help)\n";
        exit 1;
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

sub print_config_h {
    my ($major, $minor, $patch, $config_h, $local_config, $os, $arch, $cpu,
        $mp_bits, $defines_ext) = @_;

    open CONFIG_H, ">$config_h" or
        error("Couldn't write $config_h ($!)");

    print CONFIG_H <<END_OF_CONFIG_H;
/*************************************************
* Build Config Header File                       *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_BUILD_CONFIG_H__
#define BOTAN_BUILD_CONFIG_H__

#define BOTAN_VERSION_MAJOR $major
#define BOTAN_VERSION_MINOR $minor
#define BOTAN_VERSION_PATCH $patch

#define BOTAN_MP_WORD_BITS $mp_bits
#define BOTAN_DEFAULT_BUFFER_SIZE 4096

#define BOTAN_KARAT_MUL_THRESHOLD 12
#define BOTAN_KARAT_SQR_THRESHOLD 12
END_OF_CONFIG_H

    if($arch ne 'generic') {
        $arch = uc $arch;
        print CONFIG_H "\n#define BOTAN_TARGET_ARCH_IS_$arch\n";

        if($arch ne $cpu) {
            $cpu = uc $cpu;
            $cpu =~ s/-/_/g;
            print CONFIG_H "#define BOTAN_TARGET_CPU_IS_$cpu\n";
        }
    }

    my $defines = '';

    foreach (sort @$defines_ext) {
        next if not defined $_ or not $_;
        $defines .= "#define BOTAN_EXT_$_\n";
    }

    print CONFIG_H "\n", $defines if($defines);

    if($local_config ne '') {
        open LOCAL_CONFIG, "<$local_config" or die
            "Couldn't read $local_config ($!)\n";
        print CONFIG_H "\n";
        while(<LOCAL_CONFIG>) { print CONFIG_H; }
    }

    print CONFIG_H "\n#endif\n";

    close CONFIG_H;
}

sub process_template {
    my ($in, $out, $vars) = @_;

    open IN, "<$in" or die "Couldn't read $in ($!)\n";
    open OUT, ">$out" or die "Couldn't write $out ($!)\n";

    my $lineno = 0;
    while(my $line = <IN>) {
        $lineno++;

        foreach my $name (keys %$vars)
        {
            my $val = $$vars{$name};
            $line =~ s/@\{var:$name\}/$val/g;

            unless($val eq 'no' or $val eq 'false') {
                $line =~ s/\@\{if:$name (.*)\}/$1/g;
                $line =~ s/\@\{if:$name (.*) (.*)\}/$1/g;
            } else {
                $line =~ s/\@\{if:$name (.*)\}//g;
                $line =~ s/\@\{if:$name (.*) (.*)\}/$2/g;
            }
        }

        if($line =~ /@\{var:(.*)\}/) {
            die "Unbound variable '$1' at $in:$lineno\n";
        }

        print OUT $line;
    }
    close IN;
    close OUT;
}

sub print_pkg_config
{
    my ($os, $major,$minor,$patch,@libs) = @_;

    return if($os eq 'generic' or $os eq 'windows');

    unshift @libs, "m";
    my $link_to = "-l" . join(" -l", @libs);

    process_template('misc/config/botan-config.in', 'botan-config',
                     { 'version' => "${major}.${minor}.${patch}",
                       'prefix' => os_install_info($os, 'install_root'),
                       'includedir' => os_install_info($os, 'header_dir'),
                       'libdir' =>  os_install_info($os, 'lib_dir'),
                       'libs' => $link_to });

    chmod 0755, 'botan-config';
}

sub generate_makefile {
   my($make_style, $cc, $os, $submodel, $arch,
      $debug, $no_shared, $dumb_gcc,
      $lib_src, $check_src, $all_includes,
      $added_src, @libs_used) = @_;

   sub os_static_suffix {
       return os_info_for(shift, 'static_suffix');
   }

   sub os_shared_suffix {
       return os_info_for(shift, 'so_suffix');
   }

   sub os_obj_suffix {
       return os_info_for(shift, 'obj_suffix');
   }

   sub os_ar_command {
       return os_info_for(shift, 'ar_command');
   }

   sub os_ar_needs_ranlib {
       return (os_info_for(shift, 'ar_needs_ranlib') eq 'yes');
   }

   my %all_lib_srcs = (%{ $lib_src }, %{ $added_src });

   my %ccinfo = %{$COMPILER{$cc}};

   my $lang_flags = '';
   append_ifdef(\$lang_flags, $ccinfo{'lang_flags'});
   append_if(\$lang_flags, "-fpermissive", $dumb_gcc);

   my $warnings = '';
   append_ifdef(\$warnings, $ccinfo{'warning_flags'});

   my $lib_opt_flags = '';
   append_ifdef(\$lib_opt_flags, $ccinfo{'lib_opt_flags'});
   append_ifdef(\$lib_opt_flags, $ccinfo{'debug_flags'}) if($debug);
   append_ifdef(\$lib_opt_flags, $ccinfo{'no_debug_flags'}) if(!$debug);

   my $mach_opt_flags = mach_opt($cc, $arch, $submodel);

   # This is a default that works on most Unix and Unix-like systems
   my $ar_command = "ar crs";
   my $ar_needs_ranlib = 0; # almost no systems need it anymore

   # See if there are any over-riding methods. We presume if CC is creating
   # the static libs, it knows how to create the index itself.
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
   if(in_array('all', $OPERATING_SYSTEM{$os}{'supports_shared'}) or
      in_array($arch, $OPERATING_SYSTEM{$os}{'supports_shared'})) {
       $supports_shared = 1;
   }

   if($no_shared or !$supports_shared)
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

   my $install_root = os_install_info($os, 'install_root');

   open MAKEFILE, ">$MAKE_FILE"
      or die "Couldn't write $MAKE_FILE ($!)\n";

   ##################################################
   # Ready, set, print!                             #
   ##################################################
   my $cc_bin = $ccinfo{'binary_name'};

   # Hack for 10.1, 10.2+ is fixed. Don't have a 10.0.x machine anymore
   if($os eq "darwin" and $cc eq "gcc") { $cc_bin = "c++"; }

   my $obj_suffix = os_obj_suffix($os);
   my $static_suffix = os_static_suffix($os);

   my @arguments = (\*MAKEFILE,
                    $os,
                    $cc_bin . $ccopts,
                    $lib_opt_flags,
                    $check_opt_flags,
                    $mach_opt_flags,
                    $lang_flags,
                    $warnings,
                    $make_shared,
                    $so_obj_flags,
                    $so_link_flags,
                    $obj_suffix,
                    os_shared_suffix($os),
                    $static_suffix,
                    $ar_command,
                    $ar_needs_ranlib,
                    \%all_lib_srcs,
                    $check_src,
                    $all_includes,
                    \%DOCS,
                    $install_root,
                    os_install_info($os, 'header_dir'),
                    os_install_info($os, 'lib_dir'),
                    os_install_info($os, 'doc_dir'),
                    \@libs_used);

   if($make_style eq 'unix') { print_unix_makefile(@arguments); }
   elsif($make_style eq 'nmake') { print_nmake_makefile(@arguments); }
   else {
      error("This configure script does not know how to make ",
            "a makefile for makefile style \"$make_style\"");
   }

   close MAKEFILE;
}

##################################################
# Print a Unix style makefile                    #
##################################################
sub print_unix_makefile {
   my ($makefile, $os, $cc, $lib_opt, $check_opt, $mach_opt,
       $lang_flags, $warn_flags, $make_shared, $so_obj, $so_link,
       $obj_suffix, $so_suffix, $static_lib_suffix,
       $ar_command, $use_ranlib,
       $src, $check, $include_r, $docs,
       $install_root, $header_dir, $lib_dir, $doc_dir,
       $lib_list) = @_;

   my $link_to = "-lm";
   foreach my $lib (@$lib_list) { $link_to .= " -l" . $lib; }

   my $install_user = os_install_info($os, 'install_user');
   my $install_group = os_install_info($os, 'install_group');

   my $install_cmd_exec = os_install_info($os, 'install_cmd');
   my $install_cmd_data = os_install_info($os, 'install_cmd');

   $install_cmd_exec =~ s/OWNER/\$(OWNER)/;
   $install_cmd_data =~ s/OWNER/\$(OWNER)/;

   $install_cmd_exec =~ s/GROUP/\$(GROUP)/;
   $install_cmd_data =~ s/GROUP/\$(GROUP)/;

   $install_cmd_exec =~ s/MODE/\$(EXEC_MODE)/;
   $install_cmd_data =~ s/MODE/\$(DATA_MODE)/;

   $warn_flags = '' unless defined($warn_flags);
   $so_obj = '' unless defined($so_obj);

##################### COMMON CODE (PARTIALLY) ######################
   sub file_list {
      my ($spaces, $put_in, $from, $to, %files) = @_;
      my $len = $spaces;
      my $list;
      foreach (sort keys %files) {
         my $file = $_;
         my $dir = $put_in;
         if(!defined($dir)) { $dir = $files{$_}; }
         if($len > 60)
            { $list .= "\\\n" . ' 'x$spaces; $len = $spaces; }
         if(defined($from) and defined($to)) { $file =~ s/$from/$to/; }
         if(defined($dir))
            { $list .= File::Spec->catfile ($dir, $file) . ' ';
              $len += length($file) + length($dir); }
         else
            { $list .= $file . ' ';
              $len += length($file); }
      }
      return $list;
   }

   my $includes = file_list(16, undef, undef, undef, %$include_r);

   my $lib_obj = file_list(16, $BUILD_LIB_DIR, '(\.cpp$|\.s$|\.S$)',
                           '.'.$obj_suffix, %$src, %added_src);
   my $check_obj = file_list(16, $BUILD_CHECK_DIR, '.cpp', '.'.$obj_suffix,
                             %$check);

   my $doc_list = file_list(16, undef, undef, undef, %$docs);

   $lang_flags = '' if not defined($lang_flags);
   $warn_flags = '' if not defined($warn_flags);

##################### / COMMON CODE (PARTIALLY) ######################

   sub build_cmds {
      my ($dir, $flags, $obj_suffix, %files) = @_;
      my $output = '';

      foreach (sort keys %files) {
         my $src_file = File::Spec->catfile ($files{$_}, $_);
         my $obj_file = File::Spec->catfile ($dir, $_);
         $obj_file =~ s/\.cpp$/.$obj_suffix/;
         $obj_file =~ s/\.s$/.$obj_suffix/;
         $obj_file =~ s/\.S$/.$obj_suffix/;
         $output .= "$obj_file: $src_file\n" .
            "\t\$(CXX) -I$BUILD_INCLUDE_DIR $flags -c \$? -o \$@\n\n";
      }
      return $output;
   }

   my $lib_build_cmds = build_cmds($BUILD_LIB_DIR, '$(LIB_FLAGS)',
                                   $obj_suffix, %$src, %added_src);
   my $check_build_cmds = build_cmds($BUILD_CHECK_DIR, '$(CHECK_FLAGS)',
                                     $obj_suffix, %$check);

   chomp($lib_build_cmds);
   chomp($check_build_cmds);

   my $template = 'misc/config/makefile/unix.in';
   $template = 'misc/config/makefile/unix_shr.in' if($make_shared);

   process_template($template, 'Makefile',
                    { 'cc' => $cc,
                      'lib_opt' => $lib_opt,
                      'check_opt' => $check_opt,
                      'mach_opt' => $mach_opt,
                      'lang_flags' => $lang_flags,
                      'warn_flags' => $warn_flags,
                      'so_obj_flags' => $so_obj,
                      'so_link' => $so_link,
                      'link_to' => $link_to,
                      'shared' => ($make_shared ? 'yes' : 'no'),
                      'version_major' => $MAJOR_VERSION,
                      'version_minor' => $MINOR_VERSION,
                      'version_patch' => $PATCH_VERSION,
                      'prefix' => $install_root,
                      'libdir' => $lib_dir,
                      'includedir' => $header_dir,
                      'docdir' => $doc_dir,
                      'install_user' => $install_user,
                      'install_group' => $install_group,
                      'ar_command' => $ar_command,
                      'install_cmd_exec' => $install_cmd_exec,
                      'install_cmd_data' => $install_cmd_data,
                      'doc_files' => $doc_list,
                      'include_files' => $includes,
                      'lib_objs' => $lib_obj,
                      'check_objs' => $check_obj,
                      'lib_build_cmds' => $lib_build_cmds,
                      'check_build_cmds' => $check_build_cmds,
                      'so_suffix' => $so_suffix,
                      'build' => $BUILD_DIR });
}

##################################################
# Print a NMAKE-style makefile                   #
##################################################
sub print_nmake_makefile {
   my ($makefile, $os, $cc,
       $lib_opt, $check_opt, $mach_opt,
       $lang_flags, $warn_flags,
       undef, # $make_shared
       undef, # $so_obj
       undef, # $so_link
       $obj_suffix, $so_suffix,
       $static_lib_suffix,
       $ar_command, undef, # $use_ranlib
       $src, $check, $include_r, $docs,
       $install_root, $header_dir, $lib_dir, $doc_dir,
       $lib_list) = @_;

   my $link_to = '';
   foreach my $lib (@$lib_list)
   {
       my $lib_full = $lib . "." . $static_lib_suffix;
       if($link_to eq '') { $link_to .= $lib_full; }
       else               { $link_to .= ' ' . $lib_full; }
   }

##################### COMMON CODE (PARTIALLY) ######################

   my $includes = file_list(16, undef, undef, undef, %$include_r);

   my $lib_obj = file_list(16, $BUILD_LIB_DIR, '.cpp', '.'.$obj_suffix,
                           %$src, %added_src);
   my $check_obj = file_list(16, $BUILD_CHECK_DIR, '.cpp', '.'.$obj_suffix,
                             %$check);

   my $doc_list = file_list(16, undef, undef, undef, %$docs);

##################### / COMMON CODE (PARTIALLY) ######################

   sub build_cmds_nmake {
      my ($dir, $flags, $obj_suffix, %files) = @_;

      my $output = '';
      foreach (sort keys %files) {
         my $src_file = File::Spec->catfile ($files{$_}, $_);
         my $obj_file = File::Spec->catfile ($dir, $_);
         $obj_file =~ s/.cpp/.$obj_suffix/;
         $output .= "$obj_file: $src_file\n" .
            "\t\$(CXX) /I$BUILD_INCLUDE_DIR $flags /c \$? /Fo\$@\n\n";
      }
      return $output;
   }

   $warn_flags = '' unless defined($warn_flags);
   $lang_flags = '' unless defined($lang_flags);
   my $so_obj = '';
   my $so_link = '';
   my $make_shared = 0;
   my $install_user = '';
   my $install_group = '';
   my $install_cmd_exec = '';
   my $install_cmd_data = '';

   my $lib_build_cmds = build_cmds_nmake($BUILD_LIB_DIR, '$(LIB_FLAGS)',
                                         $obj_suffix, %$src, %added_src);

   my $check_build_cmds = build_cmds_nmake($BUILD_CHECK_DIR, '$(CHECK_FLAGS)',
                                           $obj_suffix, %$check);

   my $template = 'misc/config/makefile/nmake.in';

   process_template($template, 'Makefile.test',
                    { 'cc' => $cc,
                      'lib_opt' => $lib_opt,
                      'check_opt' => $check_opt,
                      'mach_opt' => $mach_opt,
                      'lang_flags' => $lang_flags,
                      'warn_flags' => $warn_flags,
                      'so_obj_flags' => $so_obj,
                      'so_link' => $so_link,
                      'link_to' => $link_to,
                      'shared' => ($make_shared ? 'yes' : 'no'),
                      'version_major' => $MAJOR_VERSION,
                      'version_minor' => $MINOR_VERSION,
                      'version_patch' => $PATCH_VERSION,
                      'prefix' => $install_root,
                      'libdir' => $lib_dir,
                      'includedir' => $header_dir,
                      'docdir' => $doc_dir,
                      'install_user' => $install_user,
                      'install_group' => $install_group,
                      'ar_command' => $ar_command,
                      'install_cmd_exec' => $install_cmd_exec,
                      'install_cmd_data' => $install_cmd_data,
                      'doc_files' => $doc_list,
                      'include_files' => $includes,
                      'lib_objs' => $lib_obj,
                      'check_objs' => $check_obj,
                      'lib_build_cmds' => $lib_build_cmds,
                      'check_build_cmds' => $check_build_cmds,
                      'static_suffix' => $static_lib_suffix,
                      'so_suffix' => $so_suffix,
                      'build' => $BUILD_DIR });
}

