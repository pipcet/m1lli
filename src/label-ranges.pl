#!/usr/bin/perl
my @ranges = (
    [0x235100000, 0x235104000, "spi0"],
    [0x235108000, 0x23510c000, "spi2"],
    [0x23510c000, 0x235110000, "spi3"],
    [0x23d1f0000, 0x23d1f4000, "nub-gpio"],
    [0x200100000, 0x200200000, "error-handler"],
    [0x204d10000, 0x204d14000, "pmp"],
    [0x204d14000, 0x204d18000, "pmp???"],
    [0x228300000, 0x228304000, "dart-dispdfr"],
    [0x228304000, 0x228308000, "dart-dispdfr"],
    [0x235004000, 0x235008000, "dart-sio"],
    [0x235044000, 0x235048000, "fpwm"],
    [0x200014050, 0x200014060, "boring"],
    );

 line:
while (<>) {
    chomp;
    if (/^\[ *([0-9.]*)\] ([0-9a-f]*) (->|<-) ([0-9a-f]*) /) {
	my ($ts, $addr, $direction, $data) = ($1, $2, $3, $4);
	for my $range (@ranges) {
	    if (hex $addr >= $range->[0] and hex $addr < $range->[1]) {
		next line;
	    }
	}
	print "$_\n";
    }
}
