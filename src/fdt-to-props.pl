#!/usr/bin/perl
while (<>) {
    next if /^\//;
    chomp;
    s/^[\t ]*//;
    if (/^};/) {
	pop @path;
    } elsif (/^(.*) {/) {
	push @path, $1;
    } elsif (/^(.*?) = (.*);$/) {
	print join(".", @path) . ".$1 = $2\n";
    }
}
