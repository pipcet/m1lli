0:
	stp	x0,x1,[sp,-16]!
	sub	x0,sp,#0x400
	and	x0,x0,#0xffffffffffffc000
	mrs	x1,ttbr1_el2
	str	x1,[x0]
	ldp	x0,x1,[sp]
	b	0b - . + 0xc03110 - 0xc02080
