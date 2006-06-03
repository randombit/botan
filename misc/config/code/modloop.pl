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

