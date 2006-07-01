sub print_config_h
   {
   my ($major, $minor, $patch, $os, $arch, $cpu,
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

   open CONFIG_H, ">$CONFIG_H_FILE" or
      die "Couldn't write $CONFIG_H_FILE ($!)\n";

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
   print CONFIG_H "\n#endif\n";

   close CONFIG_H;
   }
