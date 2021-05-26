#!/usr/bin/perl
use strict;

sub usage {
    my $program = "dt";
    warn "${program} adt-to-dtp <adt file> <dtp file>: convert ADT binary format to DT property format\n";
    warn "${program} dtb-to-dtp <adt file> <dtp file>: convert DTB binary format to DT property format\n";
    warn "${program} dtp-to-dtb <adt file> <dtp file>: convert DT property format to DTB binary format\n";
    warn "${program} tunable <adt file> <dtp file>: extract tunables from ADT binary format\n";
    warn "${program} dts-to-dtp <adt file> <dtp file>: convert DT source format to DT property format\n";
    warn "${program} dtp-to-dts <adt file> <dtp file>: convert DT property format to DT source format\n";
}

if ($ARGV[0] eq "--help") {
    usage();
    exit(1);
} elsif ($ARGV[0] eq "adt-to-dtp") {
} elsif ($ARGV[0] eq "dtb-to-dtp") {
} elsif ($ARGV[0] eq "dts-to-dtp") {
} elsif ($ARGV[0] eq "dtp-to-dts") {
} elsif ($ARGV[0] eq "dtp-to-dtb") {
} elsif ($ARGV[0] eq "tunable") {
} elsif ($ARGV[0] eq "dtb-to-adt") {
} else {
    usage();
    exit(1);
}
