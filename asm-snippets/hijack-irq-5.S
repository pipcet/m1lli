0:
	stp	x0,x1,[sp,-16]
	ldr	x0,1f
	msr	vbar_el1,x0
	ldp	x0,x1,[sp]
	add sp,sp,16
	b 0b - . + 0xc03110 - 0xc02080
	.align 4
1:
	.quad 0xabcdef
	nop
	nop

	nop	// not used
	nop
	nop
	nop

	nop	// not used
	nop
	nop
	nop

	nop	// not used
	nop
	nop
	nop

	nop	// not used
	nop
	nop
	nop

	nop	// not used
	ldp	x0,x1,[sp]
	add	sp,sp,16
	b 0b
