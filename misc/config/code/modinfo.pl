sub get_module_info
   {
   my ($MODULE, $MOD_DIR) = @_;
   my %HASH;
   my $mod_dirname = catfile($MOD_DIR,$MODULE);
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

   my $desc_file = catfile($MOD_DIR,$MODULE,$mod_info_name);
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

