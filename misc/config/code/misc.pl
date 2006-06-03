
sub catfile {
      return File::Spec->catfile(@_);
}

sub catdir {
      return File::Spec->catdir(@_);
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
         my $path = catfile($dir, $file);
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
            die "(error): More than one MPI module was loaded\n"
                if($seen_mp_module);

            $seen_mp_module = 1;
            $mp_bits = $modinfo{'mp_bits'};
        }
    }
    return $mp_bits;
}
