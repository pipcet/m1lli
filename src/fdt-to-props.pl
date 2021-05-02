#!/usr/bin/perl
my @path = ();
while (<>) {
    next if /^\//;
    chomp;
    s/^[\t ]*//;
    if (/^};/) {
	pop @path;
    } elsif (/^(.*) {/) {
	push @path, "$1.";
    } elsif (/^(.*?) = (.*);$/) {
	print join("", @path) . "$1 = $2\n";
    } elsif (/^(.*?);$/) {
	print join("", @path) . "$1\n";
    } elsif (/^[ \t]*$/) {
    } else {
	warn "bad line $_";
	sleep(1);
    }
}
