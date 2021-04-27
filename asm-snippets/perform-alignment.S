1:	adr x0, .
	and x0, x0, #0xffffffffffffc000
	and x4, x0, #0x1fc000
	mov x1, 1
2:	lsl x1, x1, 1
	cbz x1, 3f
	and x2, x4, x1
	cbz x2, 2b
	ldr x3, [x0, #0x10]
	add x3, x3, #15
	and x3, x3, #0xfffffffffffffff0
	add x0, x0, x3
	add x2, x0, x4
5:	cbz x3, 4f
	ldp x10, x11, [x0], #-16
	stp x10, x11, [x2], #-16
	sub x3, x3, #16
	add x2, x2, #0x2000
	b 5b
4:	br x2
3:	nop
