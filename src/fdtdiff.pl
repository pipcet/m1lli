#!/usr/bin/perl
my %lines;
my %lines_a;
my %lines_b;

my $fh;
open $fh, $ARGV[1] or die;
while (<$fh>) {
    chomp;
    $lines{$_} = $_;
    $lines_a{$_} = $_;
}
close $fh;

my $fh;
open $fh, $ARGV[2] or die;
while (<$fh>) {
    chomp;
    $lines{$_} = $_;
    $lines_b{$_} = $_;
}
close $fh;

for my $line (sort keys %lines) {
    if (!exists $lines_a{$line}) {
	print "+$line\n";
    } elsif (!exists $lines_b{$line}) {
	print "-$line\n";
    }
}
