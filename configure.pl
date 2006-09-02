#!/usr/bin/perl -w

require 5.006;

use strict;
use DirHandle;
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

# A whole buncha filenames
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

# Available module sets
my %MODULE_SETS = (
   'unix' => [ 'alloc_mmap', 'es_egd', 'es_ftw', 'es_unix', 'fd_unix',
               'tm_unix' ],
   'beos' => [ 'es_beos', 'es_unix', 'fd_unix', 'tm_unix' ],
   'win32' => ['es_capi', 'es_win32', 'mux_win32', 'tm_win32' ],
);

# Documentation list
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

my %REALNAME = ();

my(%SUBMODEL_ALIAS,%DEFAULT_SUBMODEL,%ARCH,%ARCH_ALIAS);

my(%OS_SUPPORTS_ARCH, %OS_SUPPORTS_SHARED, %OS_TYPE,
   %INSTALL_INFO, %OS_OBJ_SUFFIX, %OS_SHARED_SUFFIX,
   %OS_STATIC_SUFFIX, %OS_AR_COMMAND, %OS_AR_NEEDS_RANLIB,
   %OS_ALIAS);

my(%CC_BINARY_NAME,
   %CC_LIB_OPT_FLAGS,
   %CC_CHECK_OPT_FLAGS,
   %CC_WARN_FLAGS,
   %CC_LANG_FLAGS,
   %CC_SO_OBJ_FLAGS,
   %CC_SO_LINK_FLAGS,
   %CC_DEBUG_FLAGS,
   %CC_NO_DEBUG_FLAGS,
   %CC_MACHINE_OPT_FLAGS,
   %CC_MACHINE_OPT_FLAGS_RE,
   %CC_ABI_FLAGS,
   %CC_SUPPORTS_OS,
   %CC_SUPPORTS_ARCH,
   %CC_AR_COMMAND,
   %MAKEFILE_STYLE);

my %MODULES;

my $debug = 0;
my $no_shared = 0;
my $make_style = '';
my $module_set = '';
my $dumb_gcc = 0;
my $autoconfig = 1;
my $user_set_root = '';
my $build_dir = '';
my $local_config = '';
my @using_mods;
my ($doc_dir, $lib_dir);
my (%ignored_src, %ignored_include, %added_src, %added_include);
my ($CPP_INCLUDE_DIR, $BUILD_LIB_DIR, $BUILD_CHECK_DIR);
my (%lib_src, %check_src, %include);

sub main() {
    %MODULES = get_modules_list($MOD_DIR);

    set_arch_defines($ARCH_DIR);
    set_os_defines($OS_DIR);
    set_cc_defines($CC_DIR);

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
            warn "(note): Enabling -fpermissive to work around " .
                 "possible GCC issues\n";
            $dumb_gcc = 1;
        }
        if($gcc_version =~ /2\.95\.[0-4]/)
        {
            print "(note): GCC 2.95.x issues a lot of warnings for \n" .
                "    Botan; either ignore the warnings or upgrade to 3.x\n";
        }
    }

    $os = $OS_ALIAS{$os} if(defined $OS_ALIAS{$os});

    die "(error): Compiler $cc isn't known\n"
        unless defined($CC_BINARY_NAME{$cc});

    die "(error): OS $os isn't known\n" unless
        (defined($OS_SUPPORTS_ARCH{$os}) or $os eq 'generic');

    # Get the canonical submodel name (like r8k -> r8000)
    $submodel = $SUBMODEL_ALIAS{$submodel}
       if(defined($SUBMODEL_ALIAS{$submodel}));

    my $arch = undef;
    # Convert an arch alias to it's real name (like axp -> alpha)
    if(defined($ARCH_ALIAS{$submodel})) {
        $arch = $ARCH_ALIAS{$submodel};
        $submodel = $arch;
    }
    # If it's a regular submodel type, figure out what arch it is
    elsif(defined($ARCH{$submodel})) {
        $arch = $ARCH{$submodel};
    }
    elsif($submodel eq 'generic') { $arch = 'generic'; }
    else { die "(error): Arch $submodel isn't known\n"; }

    # If we got a generic family name as the model type
    if($submodel eq $arch and $submodel ne 'generic') {
        $submodel = $DEFAULT_SUBMODEL{$arch};

        warn "(note): Using $submodel as default type for family ",
        $REALNAME{$arch},"\n" if($submodel ne $arch);
    }

    $make_style = $MAKEFILE_STYLE{$cc} unless($make_style);

    die "(error): Module set $module_set isn't known\n"
        if($module_set && !defined($MODULE_SETS{$module_set}));

    if($module_set) {
        foreach (@{ $MODULE_SETS{$module_set} }) { push @using_mods,$_; }
    }

    @using_mods = grep {/./} split(/,/,join(',',@using_mods));

    if($autoconfig)
    {
        foreach (guess_mods($cc,$os,$arch,$submodel))
        {
            # Print a notice, unless it was enabled explicitly or
            # via module set
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
        die "(error): Module $_ isn't known (try --help)\n"
            unless(exists($MODULES{$_}));
    }

    die "(error): $REALNAME{$os} doesn't run on $arch ($submodel)\n"
        unless($arch eq 'generic' or $os eq 'generic' or
               in_array($OS_SUPPORTS_ARCH{$os}, $arch));

    die "(error): $REALNAME{$cc} doesn't run on $arch ($submodel)\n"
        unless($arch eq 'generic' or
               (in_array($CC_SUPPORTS_ARCH{$cc}, $arch)));

    die "(error): $REALNAME{$cc} doesn't run on $REALNAME{$os}\n"
        unless($os eq 'generic' or (in_array($CC_SUPPORTS_OS{$cc}, $os)));

    check_for_conflicts(@using_mods);
    foreach (@using_mods) {
        load_module($_, $cc, $os, $arch, $submodel, %{ $MODULES{$_} });
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

    mkdirs(($BUILD_DIR,
            $BUILD_INCLUDE_DIR, $CPP_INCLUDE_DIR,
            $BUILD_LIB_DIR, $BUILD_CHECK_DIR));
    clean_out_dirs(($CPP_INCLUDE_DIR));

    my $config_h = File::Spec->catfile($BUILD_DIR, $CONFIG_HEADER);

    print_config_h($MAJOR_VERSION, $MINOR_VERSION, $PATCH_VERSION,
                   $config_h, $local_config, $os, $arch, $submodel,
                   find_mp_bits(@using_mods), defines(@using_mods),
                   defines_base(@using_mods));

    $added_include{$CONFIG_HEADER} = $BUILD_DIR;

    copy_files($CPP_INCLUDE_DIR, \%include, \%added_include);

    my %all_includes = list_dir($CPP_INCLUDE_DIR);

    generate_makefile($make_style,
                      $cc, $os, $submodel, $arch,
                      $debug, $no_shared, $dumb_gcc,
                      \%lib_src, \%check_src, \%all_includes,
                      \%added_src, using_libs($os, @using_mods));
}

# Run stuff, quit
main();
exit;

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

sub check_for_file {
   my ($file,$mod) = @_;

   unless( -e $file ) { die
     "(error): Module $mod requires that file $file exist. This error\n",
     "should never occur; please contact the maintainers with details.\n";
   }
}

sub using_libs {
   my ($os,@using) = @_;
   my %libs;
   foreach my $mod (@using) {
      my %MOD_LIBS = %{ $MODULES{$mod}{'libs'} };
      foreach my $mod_os (keys %MOD_LIBS)
         {
             next if($mod_os =~ /^all!$os$/);
             next if($mod_os =~ /^all!$os,/);
             next if($mod_os =~ /^all!.*,${os}$/);
             next if($mod_os =~ /^all!.*,$os,.*/);
             next unless($mod_os eq $os or ($mod_os =~ /^all.*/));
             my @liblist = split(/,/, $MOD_LIBS{$mod_os});
             foreach my $lib (@liblist) { $libs{$lib} = 1; }
         }
   }

   my @libarray;
   foreach (sort keys %libs) { push @libarray , $_; }
   return @libarray;
   }

sub defines {
   my @using = @_;
   my @defarray;
   foreach (@using) {
       foreach my $define (sort keys %{ $MODULES{$_}{'define'} }) {
           push @defarray , $define;
       }
   }
   return \@defarray;
   }

sub defines_base {
   my @using = @_;
   my @defarray;
   foreach (@using) {
       foreach my $define (sort keys %{ $MODULES{$_}{'define_base'} }) {
           push @defarray , $define;
       }
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

   my $updir = File::Spec->updir();

   foreach (keys %{ $mainline }) {
       my $include = File::Spec->catfile($updir, $updir, $updir,
                                         'include', $_);

      portable_symlink($include, $include_dir, $_);
   }
   foreach (keys %{ $modules }) {
      my $include = File::Spec->catfile($updir, $updir, $updir,
                                        $$modules{$_}, $_);
      portable_symlink($include, $include_dir, $_);
   }
}

sub list_dir {
  my ($dir, $ignore) = @_;
  opendir DIR, $dir or die "Couldn't open directory $dir ($!)\n";
  my @list = grep { !/^\./ } readdir DIR;

  if($dir eq $CHECK_DIR) {
      @list = grep { !/\.dat$/ } grep { !/^keys$/ } grep { !/\.h$/ } @list;
  }

  # If $ignore is set, pull everything in @list that's in $ignore out of it
  if(defined($ignore)) {
     @list = grep { !exists($$ignore{$_}) } @list;
  }
  close DIR;
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
         die "(error): Could not create directory $dir ($!)\n";
   }
}

sub in_array {
   my($array_ref, $target) = @_;
   if(!defined($array_ref)) { return 0; }
   my @array = @{ $array_ref };
   foreach (@array) { if($_ eq $target) { return 1; } }
   return 0;
}

sub find_mp_bits
{
    my(@modules_list) = @_;
    my $mp_bits = 32; # default, good for most systems
    my $seen_mp_module = 0;

    foreach my $modname (@modules_list)
    {
        my %modinfo = %{ $MODULES{$modname} };
        if($modinfo{'mp_bits'})
        {
            die "(error): Inconsistent mp_bits requests from modules\n"
                if($seen_mp_module && $modinfo{'mp_bits'} != $mp_bits);

            $seen_mp_module = 1;
            $mp_bits = $modinfo{'mp_bits'};
        }
    }
    return $mp_bits;
}
sub print_config_h
   {
   my ($major, $minor, $patch, $config_h, $local_config, $os, $arch, $cpu,
       $mp_bits, $defines_ref, $defines_base_ref) = @_;

   my @defines = @{ $defines_ref };
   my @defines_base = @{ $defines_base_ref };

   chomp($patch);

   my $defines = '';
   foreach (sort @defines_base) {
       next if not defined $_ or not $_;
       $defines .= "#define BOTAN_$_\n";
   }
   if(scalar @defines_base) { $defines .= "\n"; }

   foreach (sort @defines) {
       next if not defined $_ or not $_;
       $defines .= "#define BOTAN_EXT_$_\n";
   }

   chomp($defines);

   if($defines) { $defines = "\n" . $defines . "\n"; }

   open CONFIG_H, ">$config_h" or
      die "Couldn't write $config_h ($!)\n";

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

   if($arch ne 'generic')
   {
       $arch = uc $arch;
       print CONFIG_H "\n#define BOTAN_TARGET_ARCH_IS_$arch\n";

       if($arch ne $cpu)
       {
           $cpu = uc $cpu;
           $cpu =~ s/-/_/g;
           print CONFIG_H "#define BOTAN_TARGET_CPU_IS_$cpu\n";
       }
   }

   print CONFIG_H $defines;

   if($local_config ne '')
   {
       open LOCAL_CONFIG, "<$local_config" or die
           "Couldn't read $local_config ($!)\n";
       print CONFIG_H "\n";
       while(<LOCAL_CONFIG>) { print CONFIG_H; }
   }

   print CONFIG_H "\n#endif\n";

   close CONFIG_H;
   }
sub check_for_conflicts {
   my @mods = @_;
   my (%ignored, %added, %replaced, %defines);
   foreach my $mod (@mods) {

       sub check_hash {
           my ($mod, $do_what, $hashref) = @_;
           foreach (keys %{ $MODULES{$mod}{$do_what} }) {
               ${$hashref}{conflicts($mod, $_, $do_what, $hashref)} = $mod;
           }
       }

      check_hash($mod, 'define', \%defines);
      check_hash($mod, 'replace', \%replaced);
      check_hash($mod, 'add', \%added);
      check_hash($mod, 'ignore', \%ignored);
   }
}

sub conflicts {
    my ($mod, $item, $do_what, $hashref) = @_;
    return if(!defined($item));

    if(defined($$hashref{$item})) {
       my $other_mod = $$hashref{$item};
       die "(error): Both $mod and $other_mod $do_what $item\n";
       }
    return $item;
}
sub get_modules_list
   {
   my $MOD_DIR = $_[0];
   my $dir = new DirHandle $MOD_DIR;
   if(!defined $dir) { return (); }

   my %MODULES;

   while(defined($_ = $dir->read))
      {
      next if($_ eq '.' or $_ eq '..');
      my $MODULE = $_;
      my %modinfo = get_module_info($MODULE, $MOD_DIR);
      foreach (keys %modinfo) { $MODULES{$MODULE}{$_} = $modinfo{$_}; }
      }
   return %MODULES;
   }

sub get_module_info
   {
   my ($MODULE, $MOD_DIR) = @_;
   my %HASH;
   my $mod_dirname = File::Spec->catfile($MOD_DIR,$MODULE);
   my $mod_dir = new DirHandle $mod_dirname;
   if(!defined $mod_dir)
      { die "(error): Couldn't open dir $mod_dirname ($!)\n"; }

   my $mod_info_name = 'modinfo.txt';

   my %MODFILES;
   my $have_config_file = 0;
   while(defined($_ = $mod_dir->read))
      {
      if($_ eq $mod_info_name) { $have_config_file = 1; }
      else { $MODFILES{$_} = undef; }
      }
   die "(error): Module $MODULE does not seem to have a description file\n"
      unless $have_config_file;

   my $desc_file = File::Spec->catfile($MOD_DIR,$MODULE,$mod_info_name);
   open MODFILE, "<$desc_file" or die
      "(error): Couldn't open file $desc_file, ($!)\n";

   $HASH{'libs'} = {};

   $HASH{'add'} = {};
   $HASH{'local_only'} = {};
   $HASH{'replace'} = {};
   $HASH{'ignore'} = {};

   $HASH{'define'} = {};
   $HASH{'define_base'} = {};

   $HASH{'external_libs'} = 0;

   while(<MODFILE>)
   {
       $HASH{'name'} = $1 if(/^realname \"(.*)\"/);
       $HASH{'notes'} = $1 if(/^note \"(.*)\"/);
       $HASH{'add'}{$1} = undef if(/^add_file ([\.\w]*)/);
       $HASH{'local_only'}{$1} = undef if(/^local_only ([\.\w]*)/);
       $HASH{'replace'}{$1} = undef if(/^replace_file ([\.\w]*)/);
       $HASH{'ignore'}{$1} = undef if(/^ignore_file ([\.\w]*)/);

       $HASH{'define'}{$1} = undef if(/^define (\w*)/);
       $HASH{'define_base'}{$1} = undef if(/^define_base (\w*)/);
       $HASH{'mp_bits'} = $1 if(/^mp_bits ([0-9]*)/);

       $HASH{'external_libs'} = 1 if(/^uses_external_libs/);

       if(/^require_version /)
       {
           if(/^require_version (\d)\.(\d)\.(\d)$/)
           {
               my $version = "$1.$2.$3";
               my $needed_version = 100*$1 + 10*$2 + $3;

               my $have_version =
                   100*$MAJOR_VERSION + 10*$MINOR_VERSION + $PATCH_VERSION;

               if($needed_version > $have_version) {
                   warn "Module $MODULE requires Botan version $version\n";
                   %HASH = ();
                   close MODFILE;
                   return %HASH;
               }
           }
           else
           {
               warn "In module $MODULE, bad version code in require_version\n";
           }
       }

       # Read in a list of supported CPU types (archs and/or submodels)
       if(/^<arch>$/) {
           while(1) {
               $_ = process($_ = <MODFILE>);
               next unless $_;
               last if (m@^</arch>$@);
               $HASH{'arch'}{$_} = undef;
           }
       }

       # Read in a list of supported OSes
       if(/^<os>$/) {
           while(1) {
               $_ = process($_ = <MODFILE>);
               next unless $_;
               last if (m@^</os>$@);
               $HASH{'os'}{$_} = undef;
           }
       }

      # Read in a set of os->extra library mappings
      if(/^<libs>$/) {
          while(1) {
              $_ = process($_ = <MODFILE>);
              next unless $_;
              last if (m@^</libs>$@);
              m/^([\w!,]*) -> ([\w,-]*)$/;
              $HASH{'libs'}{$1} = $2;
          }
      }

       # Read in a list of supported compilers
       if(/^<cc>$/) {
           while(1) {
               $_ = process($_ = <MODFILE>);
               next unless $_;
               last if (m@^</cc>$@);
               $HASH{'cc'}{$_} = undef;
           }
       }
   }

   close MODFILE;
   return %HASH;
   }

sub load_module {
   my ($modname,$cc,$os,$arch,$sub,%module) = @_;

   # Check to see if everything is OK WRT system requirements
   if(defined($module{'os'}) and !exists($module{'os'}{$os}) and
         $os ne 'generic')
       { die "(error): Module '$modname' does not run on $REALNAME{$os}\n"; }

   if(defined($module{'arch'}) and $arch ne 'generic' and
      !exists($module{'arch'}{$arch}) and !exists($module{'arch'}{$sub}))
       { die "(error): Module '$modname' does not run on ".
              "$REALNAME{$arch}/$sub\n"; }

   if(defined($module{'cc'}) and !exists($module{'cc'}{$cc}))
       {
       die "(error): Module '$modname' does not work with $REALNAME{$cc}\n";
       }

   handle_files($modname, $module{'replace'}, \&replace_file);
   handle_files($modname, $module{'ignore'},  \&ignore_file);
   handle_files($modname, $module{'add'},     \&add_file);

   if(defined($module{'notes'}))
   {
       my $realname = $module{'name'};
       my $note = $module{'notes'};
       print STDERR "(note): $modname (\"$realname\"): $note\n";
   }
}

sub handle_files {
   my($modname, $hash_scalar, $func) = @_;
   return unless defined($hash_scalar);
   my %hash = %{ $hash_scalar };
   foreach (sort keys %hash) {
      if(defined($hash{$_})) { &$func($modname, $_, $hash{$_}); }
      else                   { &$func($modname, $_); }
    }
}

sub full_path {
   my ($file,$modname) = @_;
   if(defined($modname))
      { return File::Spec->catfile ($MOD_DIR, $modname, $file); }
   else {
      if($file =~ /\.h$/)
         { return File::Spec->catfile ($INCLUDE_DIR, $file); }
      elsif($file =~ /\.cpp$/ or $file =~ /\.s$/ or $file =~ /\.S$/)
         { return File::Spec->catfile ($SRC_DIR, $file); }
      else { die "(internal error): Not sure where to put $file\n"; }
   }
}

sub add_file {
    my ($modname,$file) = @_;
    check_for_file(full_path($file, $modname), $modname);
    if($file =~ /\.cpp$/ or $file =~ /\.s$/ or $file =~ /\.S$/)
    { $added_src{$file} = File::Spec->catdir($MOD_DIR, $modname); }
    elsif($file =~ /\.h$/)
    { $added_include{$file} = File::Spec->catdir($MOD_DIR, $modname); }
    else { die "Not sure where to put $file\n"; }
}

sub ignore_file {
   my ($modname,$file) = @_;
   check_for_file(full_path($file), $modname);
   if($file =~ /\.cpp$/ or $file =~ /\.s$/ or $file =~ /\.S$/)
      { $ignored_src{$file} = 1; }
   elsif($file =~ /\.h$/) { $ignored_include{$file} = 1; }
   else { die "Not sure where to put $file\n"; }
}

# This works because ignore file always runs on files in the main source tree,
# and add always works on the file in the modules directory.
sub replace_file {
   my ($modname,$file) = @_;
   ignore_file($modname, $file);
   add_file($modname, $file);
}
sub help
   {
   print <<ENDOFHELP;
Usage: $0 [options] CC-OS-CPU

See doc/building.pdf for more information about this program.

Options:
  --prefix=/path: Set the installation path
  --libdir=/path: Install library files in \${prefix}/\${libdir}
  --docdir=/path: Install documentation in \${prefix}/\${docdir}

  --debug: tune compiler flags for debugging; inferior code can result
  --disable-shared: disable building shared libararies
  --noauto: Disable autoconfiguration
  --make-style=STYLE: override the guess as to what type of makefile to use
  --modules=MODS: add module(s) MODS to the library.
  --module-set=SET: add a pre-specified set of modules (unix|win32|beos)

You may use 'generic' for OS or CPU (useful if your OS or CPU isn't listed).

CPU can be a generic family name or a specific model name. Common aliases are
supported but not listed. Choosing a specific submodel will usually result in
code that will not run on earlier versions of that architecture.

ENDOFHELP
   print_listing('CC', %CC_BINARY_NAME);
   print_listing('OS', %OS_SUPPORTS_ARCH);
   print_listing('CPU', %DEFAULT_SUBMODEL);
   if(%MODULES) { print_listing('MODULES', %MODULES); }
   exit;
   }

sub print_listing
   {
   my ($header, %hash) = @_;
   print "$header: ";
   my $len = length "$header: ";
   foreach(sort(keys %hash)) {
       if($len > 71) { print "\n   "; $len = 3; }
       print "$_ ";
       $len += length "$_ ";
   }
   print "\n";
   }

sub which
{
    my $file = $_[0];
    my @paths = split(/:/, $ENV{PATH});
    foreach my $path (@paths)
    {
        my $file_path = File::Spec->catfile($path, $file);
        return $file_path if(guess_check_for_file($file_path));
    }
    return '';
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

        if(!defined $OS_TYPE{$os} && !defined $OS_ALIAS{$os})
        {
            print "Unknown uname -s output: $os, falling back to 'generic'\n";
            $os = 'generic';
        }

        $os = $OS_ALIAS{$os} if(defined($OS_ALIAS{$os}));
        my $cpu = '';

        # If we have /proc/cpuinfo, try to get nice specific information about
        # what kind of CPU we're running on.
        if(guess_check_for_file('/proc/cpuinfo'))
        {
            open CPUINFO, '/proc/cpuinfo' or die
                "Hey, guess_check_for_file said /proc/cpuinfo was readable!\n";
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
            my $bin_name = $CC_BINARY_NAME{$_};
            $cc = $_ if(which($bin_name) ne '');
            last if($cc ne '');
        }

        if($cc eq '') {
           warn "Can't find a usable C++ compiler, is your PATH right?\n";
           warn "You might need to run with explicit compiler/system flags;\n";
           warn "   run '$0 --help' for more information\n";
           exit 1;
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

sub guess_check_for_file
{
    my $file = $_[0];
    return 1 if(-f $file and -r $file);
    return 0;
}

sub guess_mods
{
    my ($cc, $os, $arch, $submodel) = @_;

    my @usable_modules;

    foreach my $mod (sort keys %MODULES)
    {
        next if($mod eq 'minimal'); # Never enabled by default

        my %modinfo = %{ $MODULES{$mod} };

        # If it uses external libs, the user has to request it specifically
        next if($modinfo{'external_libs'});

        my @cc_list = ();
        if($modinfo{'cc'}) { @cc_list = keys %{ $modinfo{'cc'} }; }
        my @os_list = ();
        if($modinfo{'os'}) { @os_list = keys %{ $modinfo{'os'} }; }
        my @arch_list = ();
        if($modinfo{'arch'}) { @arch_list = keys %{ $modinfo{'arch'} }; }

        next if(scalar @cc_list > 0 && !in_array(\@cc_list, $cc));
        next if(scalar @os_list > 0 && !in_array(\@os_list, $os));

        next if(scalar @arch_list > 0 &&
                !in_array(\@arch_list, $arch) &&
                !in_array(\@arch_list, $submodel));

        push @usable_modules, $mod;
    }
    return @usable_modules;
}

sub os_info_for {
    my ($os,$hashref) = @_;

    my %hash = %{ $hashref };

    die "Internal error: os_info_for called with undef hash\n"
        unless %hash;

    die "Internal error: os_info_for called with an os of defaults\n"
        if($os eq 'defaults');

    return $hash{$os} if(defined($hash{$os}) && $hash{$os} ne '');
    return $hash{'defaults'};
}

sub os_static_suffix {
    my $os = $_[0];
    return os_info_for($os, \%OS_STATIC_SUFFIX);
}

sub os_shared_suffix {
    my $os = $_[0];
    return os_info_for($os, \%OS_SHARED_SUFFIX);
}

sub os_obj_suffix {
    my $os = $_[0];
    return os_info_for($os, \%OS_OBJ_SUFFIX);
}

sub os_ar_command {
    my $os = $_[0];
    return os_info_for($os, \%OS_AR_COMMAND);
}

sub os_ar_needs_ranlib {
    my $os = $_[0];
    return os_info_for($os, \%OS_AR_NEEDS_RANLIB);
}

sub os_install_info {
    my ($os,$what) = @_;

    return $doc_dir if($what eq 'docs' && $doc_dir);
    return $lib_dir if($what eq 'libs' && $lib_dir);

    return $INSTALL_INFO{$os}{$what}
       if(defined($INSTALL_INFO{$os}) &&
          defined($INSTALL_INFO{$os}{$what}));

    return $INSTALL_INFO{'defaults'}{$what};
}
##################################################
# Generate compiler options and print makefile   #
##################################################
sub generate_makefile {
   my($make_style, $cc, $os, $submodel, $arch,
      $debug, $no_shared, $dumb_gcc,
      $lib_src, $check_src, $all_includes,
      $added_src, @libs_used) = @_;

   my %all_lib_srcs = (%{ $lib_src }, %{ $added_src });

   ##################################################
   # Set language options                           #
   ##################################################
   my $lang_flags = $CC_LANG_FLAGS{$cc};
   $lang_flags = "$lang_flags -fpermissive" if($dumb_gcc);

   ##################################################
   # Set basic optimization options                 #
   ##################################################
   my $lib_opt_flags = $CC_LIB_OPT_FLAGS{$cc};
   if(!$debug and ($CC_NO_DEBUG_FLAGS{$cc}))
      { $lib_opt_flags .= ' '.$CC_NO_DEBUG_FLAGS{$cc}; }
   if($debug and ($CC_DEBUG_FLAGS{$cc}))
      { $lib_opt_flags .= ' '.$CC_DEBUG_FLAGS{$cc}; }

   ##################################################
   # Set machine dependent optimization options     #
   ##################################################
   my $mach_opt_flags = '';
   if(defined($CC_MACHINE_OPT_FLAGS{$cc}{$submodel}))
      { $mach_opt_flags = $CC_MACHINE_OPT_FLAGS{$cc}{$submodel}; }
   elsif(defined($CC_MACHINE_OPT_FLAGS{$cc}{$arch})) {
      $mach_opt_flags = $CC_MACHINE_OPT_FLAGS{$cc}{$arch};
      my $processed_modelname = $submodel;
      if(defined($CC_MACHINE_OPT_FLAGS_RE{$cc}{$arch}))
         { $processed_modelname =~
              s/$CC_MACHINE_OPT_FLAGS_RE{$cc}{$arch}//; }
      $mach_opt_flags =~ s/SUBMODEL/$processed_modelname/g;
   }

   ##################################################
   # Figure out static library creation method      #
   ##################################################
   # This is a default that works on most Unix and Unix-like systems
   my $ar_command = "ar crs";
   my $ar_needs_ranlib = 0; # almost no systems need it anymore

   # See if there are any over-riding methods. We presume if CC is creating
   # the static libs, it knows how to create the index itself.
   if($CC_AR_COMMAND{$cc}) { $ar_command = $CC_AR_COMMAND{$cc}; }
   elsif(os_ar_command($os))
   {
       $ar_command = os_ar_command($os);
       $ar_needs_ranlib = 1 if(os_ar_needs_ranlib($os));
   }

   ##################################################
   # Set shared object options                      #
   ##################################################
   my $so_link_flags = '';
   my $so_obj_flags = $CC_SO_OBJ_FLAGS{$cc};

   if($no_shared or (!in_array($OS_SUPPORTS_SHARED{$os}, 'all') and
                     !in_array($OS_SUPPORTS_SHARED{$os}, $arch)))
      { $so_obj_flags = ''; }

  elsif(defined($CC_SO_LINK_FLAGS{$cc}{$os}))
      { $so_link_flags = $CC_SO_LINK_FLAGS{$cc}{$os}; }
   elsif(defined($CC_SO_LINK_FLAGS{$cc}{'default'}))
      { $so_link_flags = $CC_SO_LINK_FLAGS{$cc}{'default'}; }

   my $make_shared = 0;
   $make_shared = 1
       if(($so_obj_flags or $so_link_flags) and $OS_SUPPORTS_SHARED{$os});

   ##################################################
   # Set check code compilation flags               #
   ##################################################
   my $check_opt_flags = $CC_CHECK_OPT_FLAGS{$cc};

   ##################################################
   # Set misc ABI options                           #
   ##################################################
   my $ccopts = '';

   $ccopts .= ' '.$CC_ABI_FLAGS{$cc}{$arch}
      if(defined($CC_ABI_FLAGS{$cc}{$arch}));

   $ccopts .= ' '.$CC_ABI_FLAGS{$cc}{$os} if(defined($CC_ABI_FLAGS{$cc}{$os}));

   $ccopts .= ' '.$CC_ABI_FLAGS{$cc}{'all'}
      if(defined($CC_ABI_FLAGS{$cc}{'all'}));

   ##################################################
   # Where to install?                              #
   ##################################################
   my $install_root = os_install_info($os, 'root');
   my $header_dir   = os_install_info($os, 'headers');
   my $lib_dir      = os_install_info($os, 'libs');
   my $doc_dir      = os_install_info($os, 'docs');

   if($user_set_root ne '') { $install_root = $user_set_root; }

   ##################################################
   # Open the makefile                              #
   ##################################################
   open MAKEFILE, ">$MAKE_FILE"
      or die "Couldn't write $MAKE_FILE ($!)\n";

   ##################################################
   # Ready, set, print!                             #
   ##################################################
   my $cc_bin = $CC_BINARY_NAME{$cc};

   # Hack for 10.1, 10.2+ is fixed. Don't have a 10.0.x machine anymore
   if($os eq "darwin" and $cc eq "gcc") { $cc_bin = "c++"; }

   my $obj_suffix = os_obj_suffix($os);
   my $static_suffix = os_static_suffix($os);

   # Man that's a lot of arguments. :)
   my @arguments = (\*MAKEFILE,
                    $os,
                    $cc_bin . $ccopts,
                    $lib_opt_flags,
                    $check_opt_flags,
                    $mach_opt_flags,
                    $lang_flags,
                    $CC_WARN_FLAGS{$cc},
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
                    $header_dir,
                    $lib_dir,
                    $doc_dir,
                    \@libs_used);

   if($make_style eq 'unix') { print_unix_makefile(@arguments); }
   elsif($make_style eq 'nmake') { print_nmake_makefile(@arguments); }
   else {
      die "(error): This configure script does not know how to make ",
          "a makefile for makefile style \"$make_style\"\n";
   }

   close MAKEFILE;
}

##################################################
# Print a header for a makefile                  #
##################################################
sub print_header {
    my ($fh, $comment, $string) = @_;
    print $fh $comment x 50, "\n",
             "$comment $string", ' 'x(47-length($string)), "$comment\n",
              $comment x 50, "\n";
}
##################################################
# Print a Unix style makefile                    #
##################################################
sub print_unix_makefile {
   my ($makefile, $os, $cc,
       $lib_opt, $check_opt, $mach_opt,
       $lang_flags, $warn_flags,
       $make_shared, $so_obj, $so_link,
       $obj_suffix, $so_suffix, $static_lib_suffix,
       $ar_command, $use_ranlib,
       $src_hash, $check_hash, $include_hash, $docs,
       $install_root, $header_dir, $lib_dir, $doc_dir,
       $lib_list) = @_;

   ##################################################
   # Some constants                                 #
   ##################################################
   my $__TAB__ = "\t";
   my $COMMENT_CHAR = '#';

   ##################################################
   # Convert the references to hashes               #
   ##################################################
   my %src = %{ $src_hash };
   my %includes = %{ $include_hash };

   my %check = %{ $check_hash };

   my %docs = %{ $docs };

   ##################################################
   # Make the library linking list                  #
   ##################################################
   my $link_to = "-lm";
   foreach my $lib (@{ $lib_list })
   {
       $link_to .= " -l" . $lib;
   }

   ##################################################
   # Generate a few variables                       #
   ##################################################
   my $lib_flags   = '$(LIB_OPT) $(MACH_OPT) $(LANG_FLAGS) $(WARN_FLAGS)';

   my $libs = '$(STATIC_LIB)';
   if($make_shared) { $lib_flags .= ' $(SO_OBJ_FLAGS)';
                      $libs .= ' $(SHARED_LIB)'; }

   my $install_user = os_install_info($os, 'user');
   my $install_group = os_install_info($os, 'group');

   my $install_cmd_exec = os_install_info($os, 'command');
   my $install_cmd_data = os_install_info($os, 'command');

   $install_cmd_exec =~ s/OWNER/\$(OWNER)/;
   $install_cmd_data =~ s/OWNER/\$(OWNER)/;

   $install_cmd_exec =~ s/GROUP/\$(GROUP)/;
   $install_cmd_data =~ s/GROUP/\$(GROUP)/;

   $install_cmd_exec =~ s/MODE/\$(EXEC_MODE)/;
   $install_cmd_data =~ s/MODE/\$(DATA_MODE)/;

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

   my $includes = file_list(16, undef, undef, undef, %includes);

   my $lib_obj = file_list(16, $BUILD_LIB_DIR, '(\.cpp$|\.s$|\.S$)',
                           '.'.$obj_suffix, %src, %added_src);
   my $check_obj = file_list(16, $BUILD_CHECK_DIR, '.cpp', '.'.$obj_suffix,
                             %check);

   my $doc_list = file_list(16, undef, undef, undef, %docs);

##################### / COMMON CODE (PARTIALLY) ######################

   print_header($makefile, $COMMENT_CHAR, 'Compiler Options');
   print $makefile <<END_OF_MAKEFILE_HEADER;
CXX           = $cc
LIB_OPT       = $lib_opt
CHECK_OPT     = $check_opt
MACH_OPT      = $mach_opt
LANG_FLAGS    = $lang_flags
WARN_FLAGS    = $warn_flags
SO_OBJ_FLAGS  = $so_obj
SO_LINK_CMD   = $so_link
LINK_TO       = $link_to

END_OF_MAKEFILE_HEADER

   print_header($makefile, $COMMENT_CHAR, 'Version Numbers');
   print $makefile <<END_OF_VERSIONS;
MAJOR         = $MAJOR_VERSION
MINOR         = $MINOR_VERSION
PATCH         = $PATCH_VERSION

VERSION       = \$(MAJOR).\$(MINOR).\$(PATCH)

END_OF_VERSIONS

   print_header($makefile, $COMMENT_CHAR, 'Installation Settings');
   print $makefile <<END_OF_INSTALL_SETTINGS;
INSTALLROOT   = $install_root

BINDIR        = \$(INSTALLROOT)/bin
LIBDIR        = \$(INSTALLROOT)/$lib_dir
HEADERDIR     = \$(INSTALLROOT)/$header_dir/botan
DOCDIR        = \$(INSTALLROOT)/$doc_dir/Botan-\$(VERSION)

OWNER         = $install_user
GROUP         = $install_group
DATA_MODE     = 644
EXEC_MODE     = 755

CONFIG_SCRIPT = botan-config

END_OF_INSTALL_SETTINGS

   print_header($makefile, $COMMENT_CHAR, 'Aliases for Common Programs');
   print $makefile <<END_OF_COMMAND_ALIASES;
AR               = $ar_command
CD               = \@cd
ECHO             = \@echo
INSTALL_CMD_EXEC = $install_cmd_exec
INSTALL_CMD_DATA = $install_cmd_data
LN               = ln -fs
MKDIR            = \@mkdir
MKDIR_INSTALL    = \@umask 022; mkdir -p -m \$(EXEC_MODE)
RANLIB           = \@ranlib
RM               = \@rm -f
RM_R             = \@rm -rf

END_OF_COMMAND_ALIASES

   print_header($makefile, $COMMENT_CHAR, 'File Lists');
   print $makefile <<END_OF_FILE_LISTS;
CHECK         = check

DOCS          = $doc_list

HEADERS       = $includes

LIBOBJS       = $lib_obj

CHECKOBJS     = $check_obj

LIB_FLAGS     = $lib_flags
CHECK_FLAGS   = \$(CHECK_OPT) \$(LANG_FLAGS) \$(WARN_FLAGS)

LIBRARIES     = $libs

LIBNAME       = libbotan
STATIC_LIB    = \$(LIBNAME).$static_lib_suffix

END_OF_FILE_LISTS

   if($make_shared) {
       print $makefile <<END_OF_SHARED_LIB_DECL;
SHARED_LIB    = \$(LIBNAME)-\$(MAJOR).\$(MINOR).\$(PATCH).$so_suffix
SONAME        = \$(LIBNAME)-\$(MAJOR).\$(MINOR).\$(PATCH).$so_suffix

SYMLINK       = \$(LIBNAME).$so_suffix

END_OF_SHARED_LIB_DECL
   }

   print $makefile "all: \$(LIBRARIES)\n\n";
   print_header($makefile, $COMMENT_CHAR, 'Build Commands');

   sub print_build_cmds {
      my ($fh, $dir, $flags, $obj_suffix, %files) = @_;
      foreach (sort keys %files) {
         my $src_file = File::Spec->catfile ($files{$_}, $_);
         my $obj_file = File::Spec->catfile ($dir, $_);
         $obj_file =~ s/\.cpp$/.$obj_suffix/;
         $obj_file =~ s/\.s$/.$obj_suffix/;
         $obj_file =~ s/\.S$/.$obj_suffix/;
         print $fh "$obj_file: $src_file\n",
            "\t\$(CXX) -I$BUILD_INCLUDE_DIR $flags -c \$? -o \$@\n\n";
      }
   }

   print_build_cmds($makefile, $BUILD_LIB_DIR,
                    '$(LIB_FLAGS)', $obj_suffix, %src, %added_src);

   print_build_cmds($makefile, $BUILD_CHECK_DIR,
                    '$(CHECK_FLAGS)', $obj_suffix, %check);

   print_header($makefile, $COMMENT_CHAR, 'Link Commands');

   print $makefile <<END_OF_LINK_COMMANDS;
\$(CHECK): \$(LIBRARIES) \$(CHECKOBJS)
$__TAB__\$(CXX) \$(CHECKOBJS) -L. -lbotan \$(LINK_TO) -o \$(CHECK)

\$(STATIC_LIB): \$(LIBOBJS)
$__TAB__\$(RM) \$(STATIC_LIB)
$__TAB__\$(AR) \$(STATIC_LIB) \$(LIBOBJS)
END_OF_LINK_COMMANDS

   if($use_ranlib) { print $makefile "$__TAB__\$(RANLIB) \$(STATIC_LIB)\n\n"; }
   else { print $makefile "\n"; }

   if($make_shared) {
      print $makefile <<END_OF_SO_LINK_COMMAND;
\$(SHARED_LIB): \$(LIBOBJS)
$__TAB__\$(SO_LINK_CMD) \$(LINK_TO) \$(LIBOBJS) -o \$(SHARED_LIB)
$__TAB__\$(LN) \$(SHARED_LIB) \$(SYMLINK)

END_OF_SO_LINK_COMMAND
    }


   print_header($makefile, $COMMENT_CHAR, 'Fake Targets');

   print $makefile ".PHONY = clean distclean install static";
   if($make_shared) { print $makefile " shared"; }
   print $makefile "\n\n";

   print $makefile "static: \$(STATIC_LIB)\n\n";
   if($make_shared) { print $makefile "shared: \$(SHARED_LIB)\n\n"; }

   print $makefile <<END_OF_FAKE_TARGETS;
clean:
$__TAB__\$(RM_R) $BUILD_LIB_DIR/* $BUILD_CHECK_DIR/*
$__TAB__\$(RM) \$(LIBRARIES) \$(SYMLINK) \$(CHECK)

distclean: clean
$__TAB__\$(RM_R) $BUILD_DIR
$__TAB__\$(RM) $MAKE_FILE \$(CONFIG_SCRIPT)

END_OF_FAKE_TARGETS

   print $makefile <<END_OF_INSTALL_SCRIPTS;
install: \$(LIBRARIES)
$__TAB__\$(ECHO) "Installing Botan into \$(INSTALLROOT)... "
$__TAB__\$(MKDIR_INSTALL) \$(DOCDIR)
$__TAB__\$(MKDIR_INSTALL) \$(HEADERDIR)
$__TAB__\$(MKDIR_INSTALL) \$(LIBDIR)
$__TAB__\$(MKDIR_INSTALL) \$(BINDIR)
$__TAB__\@for i in \$(DOCS); do \\
$__TAB__   \$(INSTALL_CMD_DATA) \$\$i \$(DOCDIR); \\
$__TAB__ done
$__TAB__\@for i in \$(HEADERS); do \\
$__TAB__   \$(INSTALL_CMD_DATA) \$\$i \$(HEADERDIR); \\
$__TAB__ done
$__TAB__\@\$(INSTALL_CMD_DATA) \$(STATIC_LIB) \$(LIBDIR)
$__TAB__\@\$(INSTALL_CMD_EXEC) \$(CONFIG_SCRIPT) \$(BINDIR)
END_OF_INSTALL_SCRIPTS

   if($make_shared) {
      print $makefile <<END_OF_SYMLINKS;
$__TAB__\@\$(INSTALL_CMD_EXEC) \$(SHARED_LIB) \$(LIBDIR)
$__TAB__\$(CD) \$(LIBDIR); \$(LN) \$(SHARED_LIB) \$(SYMLINK)

END_OF_SYMLINKS
   }
   else { print $makefile "\n"; }

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
       $obj_suffix,
       $so_suffix,
       $static_lib_suffix,
       $ar_command,
       undef, # $use_ranlib
       $src_hash, $check_hash, $include_hash, $docs,
       $install_root, $header_dir, $lib_dir, $doc_dir,
       $lib_list) = @_;

   ##################################################
   # Some constants                                 #
   ##################################################
   my $__TAB__ = "\t";
   my $COMMENT_CHAR = '#';

   ##################################################
   # Convert the references to hashes               #
   ##################################################
   my %src = %{ $src_hash };
   my %includes = %{ $include_hash };

   my %check = %{ $check_hash };

   my %docs = %{ $docs };

   ##################################################
   # Make the library linking list                  #
   ##################################################
   my $link_to = '';
   foreach my $lib (@{ $lib_list })
   {
       my $lib_full = $lib . "." . $static_lib_suffix;
       if($link_to eq '') { $link_to .= $lib_full; }
       else               { $link_to .= ' ' . $lib_full; }
   }

   ##################################################
   # Generate a few variables                       #
   ##################################################
   my $lib_flags   = '$(LIB_OPT) $(MACH_OPT) $(LANG_FLAGS) $(WARN_FLAGS)';

   my $libs = '$(STATIC_LIB)';

##################### COMMON CODE (PARTIALLY) ######################

   my $includes = file_list(16, undef, undef, undef, %includes);

   my $lib_obj = file_list(16, $BUILD_LIB_DIR, '.cpp', '.'.$obj_suffix,
                           %src, %added_src);
   my $check_obj = file_list(16, $BUILD_CHECK_DIR, '.cpp', '.'.$obj_suffix,
                             %check);

   my $doc_list = file_list(16, undef, undef, undef, %docs);

##################### / COMMON CODE (PARTIALLY) ######################

   print_header($makefile, $COMMENT_CHAR, 'Compiler Options');
   print $makefile <<END_OF_MAKEFILE_HEADER;
CXX           = $cc
LIB_OPT       = $lib_opt
CHECK_OPT     = $check_opt
MACH_OPT      = $mach_opt
LANG_FLAGS    = $lang_flags
WARN_FLAGS    = $warn_flags
SO_OBJ_FLAGS  =
SO_LINK_FLAGS =
LINK_TO       = $link_to

END_OF_MAKEFILE_HEADER

   print_header($makefile, $COMMENT_CHAR, 'Version Numbers');
   print $makefile <<END_OF_VERSIONS;
MAJOR         = $MAJOR_VERSION
MINOR         = $MINOR_VERSION
PATCH         = $PATCH_VERSION

VERSION       = \$(MAJOR).\$(MINOR).\$(PATCH)

END_OF_VERSIONS

   print_header($makefile, $COMMENT_CHAR, 'Installation Settings');
   print $makefile <<END_OF_INSTALL_SETTINGS;
INSTALLROOT   = $install_root

LIBDIR        = \$(INSTALLROOT)\\$lib_dir
HEADERDIR     = \$(INSTALLROOT)\\$header_dir\\botan
DOCDIR        = \$(INSTALLROOT)\\$doc_dir

END_OF_INSTALL_SETTINGS

   print_header($makefile, $COMMENT_CHAR, 'Aliases for Common Programs');
   print $makefile <<END_OF_COMMAND_ALIASES;
AR            = $ar_command
CD            = \@cd
ECHO          = \@echo
INSTALL       = copy
INSTALL_CMD   = \$(INSTALL)
MKDIR         = \@md
MKDIR_INSTALL = \@md
RM            = \@del /Q
RMDIR         = \@rmdir

END_OF_COMMAND_ALIASES

   print_header($makefile, $COMMENT_CHAR, 'File Lists');
   print $makefile <<END_OF_FILE_LISTS;
LIB_FLAGS     = $lib_flags
CHECK_FLAGS   = \$(CHECK_OPT) \$(LANG_FLAGS) \$(WARN_FLAGS)

CHECK         = check

DOCS          = $doc_list

HEADERS       = $includes

LIBOBJS       = $lib_obj

CHECKOBJS     = $check_obj

LIBRARIES     = $libs

LIBNAME       = libbotan
STATIC_LIB    = \$(LIBNAME).$static_lib_suffix

END_OF_FILE_LISTS

   print $makefile "all: \$(LIBRARIES)\n\n";
   print_header($makefile, $COMMENT_CHAR, 'Build Commands');

   sub print_build_cmds_nmake {
      my ($fh, $dir, $flags, $obj_suffix, %files) = @_;
      foreach (sort keys %files) {
         my $src_file = File::Spec->catfile ($files{$_}, $_);
         my $obj_file = File::Spec->catfile ($dir, $_);
         $obj_file =~ s/.cpp/.$obj_suffix/;
         print $fh "$obj_file: $src_file\n",
            "\t\$(CXX) -I$BUILD_INCLUDE_DIR $flags /c \$? /Fo\$@\n\n";
      }
   }

   print_build_cmds_nmake($makefile, $BUILD_LIB_DIR,
                          '$(LIB_FLAGS)', $obj_suffix, %src, %added_src);

   print_build_cmds_nmake($makefile, $BUILD_CHECK_DIR,
                          '$(CHECK_FLAGS)', $obj_suffix, %check);

   print_header($makefile, $COMMENT_CHAR, 'Link Commands');

   print $makefile <<END_OF_LINK_COMMANDS;
\$(CHECK): \$(LIBRARIES) \$(CHECKOBJS)
${__TAB__}LINK /OUT:\$@.exe \$(CHECKOBJS) \$(STATIC_LIB) \$(LINK_TO)

\$(STATIC_LIB): \$(LIBOBJS)
$__TAB__\$(AR) /OUT:\$@ /NAME:BOTAN-\$(VERSION) \$(LIBOBJS)
END_OF_LINK_COMMANDS

   print $makefile "\n";

   print_header($makefile, $COMMENT_CHAR, 'Misc Targets');
   print $makefile "static: \$(STATIC_LIB)\n\n";

   print_header($makefile, $COMMENT_CHAR, 'Fake Targets');
   print $makefile <<END_OF_FAKE_TARGETS;
clean:
$__TAB__\$(RM) $BUILD_LIB_DIR\\* $BUILD_CHECK_DIR\\*
$__TAB__\$(RM) \$(LIBRARIES) \$(CHECK)

distclean: clean
$__TAB__\$(RM) $CPP_INCLUDE_DIR\\*
$__TAB__\$(RMDIR) $CPP_INCLUDE_DIR
$__TAB__\$(RMDIR) $BUILD_LIB_DIR $BUILD_CHECK_DIR $BUILD_INCLUDE_DIR $BUILD_DIR
$__TAB__\$(RM) $MAKE_FILE
END_OF_FAKE_TARGETS

   print_header($makefile, $COMMENT_CHAR, 'Install Commands');

   print $makefile <<END_OF_INSTALL_SCRIPTS;
install: \$(LIBRARIES)
$__TAB__\$(ECHO) "Install command not done"
END_OF_INSTALL_SCRIPTS

    print $makefile "\n";

}

sub print_pkg_config
{
    my ($os, $major,$minor,$patch,@libs) = @_;

    return if($os eq 'generic' or $os eq 'windows');

    my $install_root = os_install_info($os, 'root');
    my $header_dir   = os_install_info($os, 'headers');
    my $lib_dir      = os_install_info($os, 'libs');

   if($user_set_root ne '') { $install_root = $user_set_root; }

    my $link_to = "-lm";
    foreach my $lib (@libs)
    {
        $link_to .= " -l" . $lib;
    }

    my $VERSION = $major . "." . $minor . "." . $patch;

    open PKGCONFIG, ">botan-config" or
        die "Couldn't write to botan-config ($!)";

    print PKGCONFIG <<END_OF_FILE;
#!/bin/sh

guess_prefix=\`dirname \\\`dirname \$0\\\`\`
install_prefix=$install_root
prefix=
includedir=$header_dir
libdir=$lib_dir

usage()
{
    echo "botan-config [--prefix[=DIR]] [--version] [--libs] [--cflags]"
    exit 1
}

if test \$# -eq 0; then
    usage
fi

if test \`echo \$guess_prefix | cut -c 1\` = "/"; then
   prefix=\$guess_prefix
else
   prefix=\$install_prefix
fi

while test \$# -gt 0; do
    case "\$1" in
    -*=*) optarg=`echo "\$1" | sed 's/[-_a-zA-Z0-9]*=//'` ;;
    *) optarg= ;;
    esac
    case "\$1" in
    --prefix=*)
        prefix=\$optarg
        ;;
    --prefix)
        echo \$prefix
        ;;
    --version)
        echo $VERSION
        exit 0
        ;;
    --cflags)
        if [ \$prefix != "/usr" -a \$prefix != "/usr/local" ]
        then
           echo -I\$prefix/\$includedir
        fi
        ;;
    --libs)
        echo -L\$prefix/\$libdir $link_to -lbotan
        ;;
    *)
        usage
        ;;
    esac
    shift
done

exit 0
END_OF_FILE

    close PKGCONFIG;
    chmod 0755, 'botan-config';
}

sub set_arch_defines {
    my $dir = new DirHandle $_[0];
    if(!defined $dir) {
        die "Couldn't open directory $_[0] ($!)";
    }

    while(defined($_ = $dir->read)) {
        next if($_ eq '.' or $_ eq '..');
        my $arch = $_;
        my $filename = File::Spec->catfile($_[0], $arch);
        open ARCHFILE, "<$filename" or die "Couldn't open $filename, ($!)";

        $ARCH{$arch} = $arch;
        while(<ARCHFILE>) {
            $_ = process($_);
            next unless $_;

            $REALNAME{$arch} = $1 if(/^realname \"(.*)\"/);
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
}

sub set_os_defines {
    my $dir = new DirHandle $_[0];
    if(!defined $dir) {
        die "Couldn't open directory $_[0] ($!)";
    }

    while(defined($_ = $dir->read)) {
        next if($_ eq '.' or $_ eq '..');
        my $os = $_;

        my $filename = File::Spec->catfile($_[0], $os);
        open OSFILE, "<$filename" or die "Couldn't open $filename, ($!)";
        $OS_SHARED_SUFFIX{$os} = '';
        $OS_AR_COMMAND{$os} = '';

        # Default values
        while(<OSFILE>) {
            $_ = process($_);
            next unless $_;

            $REALNAME{$os} = $1 if(/^realname \"(.*)\"/);
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
                    push @{$OS_SUPPORTS_SHARED{$os}}, $_;
                }
            }

            # Read in a list of architectures and add them to OS_SUPPORTS_ARCH
            if(/^<arch>$/) {
                while(1) {
                    $_ = process($_ = <OSFILE>);
                    next unless $_;
                    last if(m@^</arch>$@);
                    push @{$OS_SUPPORTS_ARCH{$os}}, $_;
                }
            }
        }
    }
    undef $dir;
}

#############################################################################
sub set_cc_defines {
    my $dir = new DirHandle $_[0];
    if(!defined $dir) {
        die "Couldn't open directory $_[0] ($!)";
    }

    while(defined($_ = $dir->read)) {
        next if($_ eq '.' or $_ eq '..');
        my $cc = $_;
        my $filename = File::Spec->catfile($_[0], $cc);
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

            $REALNAME{$cc} = $1 if(/^realname \"(.*)\"/);
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
                    push @{$CC_SUPPORTS_ARCH{$cc}}, $_;
                }
            }

            # Read in a list of supported OSes
            if(/^<os>$/) {
                while(1) {
                    $_ = process($_ = <CCFILE>);
                    next unless $_;
                    last if(m@^</os>$@);
                    push @{$CC_SUPPORTS_OS{$cc}}, $_;
                }
            }

            # Read in a list of machine optimization flags
            if(/^<mach_opt>$/) {
                while(1) {
                    $_ = process($_ = <CCFILE>);
                    next unless $_;
                    last if(m@^</mach_opt>$@);
                    m/^(\S*) -> \"(.*)\" ?(.*)?$/;
                    $CC_MACHINE_OPT_FLAGS{$cc}{$1} = $2;
                    if($3 ne '') {
                        $CC_MACHINE_OPT_FLAGS_RE{$cc}{$1} = $3;
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
}
