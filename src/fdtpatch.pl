#!/usr/bin/perl
my @lines;
while (<>) {
    chomp;
    next unless $_;
    if (/^-(.*)$/) {
	@lines = grep { $_ !~ /^$1/ } @lines;
    } elsif (/^\+(.*)$/) {
	push @lines, $1;
    } else {
	push @lines, $_;
    }
}

for my $line (@lines) {
    print "$line\n";
}
